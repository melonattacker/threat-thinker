"""
Local Retrieval-Augmented Generation (RAG) helpers.

Implements a lightweight, file-based knowledge base for Threat Thinker.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

import numpy as np

try:
    import tiktoken
except ImportError as exc:  # pragma: no cover - enforced via requirements
    raise RuntimeError(
        "tiktoken is required for the local RAG feature. Please install dependencies."
    ) from exc

DEFAULT_EMBED_MODEL = "text-embedding-3-small"
DEFAULT_CHUNK_TOKENS = 800
DEFAULT_CHUNK_OVERLAP = 80
DEFAULT_TOPK = 8

DEFAULT_RAG_STRATEGY = "hybrid"
DEFAULT_RAG_RERANKER = "auto"
DEFAULT_RAG_CANDIDATES = 40
DEFAULT_RAG_MIN_SCORE = 0.25
DEFAULT_RAG_RRF_K = 60
DEFAULT_RAG_MMR_LAMBDA = 0.7
DEFAULT_RAG_MAX_PER_SOURCE = 2
DEFAULT_RAG_DENSE_RRF_WEIGHT = 0.30
DEFAULT_RAG_SPARSE_RRF_WEIGHT = 0.40
DEFAULT_RAG_DENSE_RAW_WEIGHT = 0.10
DEFAULT_RAG_SPARSE_RAW_WEIGHT = 0.20
DEFAULT_LOCAL_RERANK_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"

RAG_STRATEGIES = {"dense", "hybrid"}
RAG_RERANKERS = {"auto", "local", "llm", "off"}

TEXT_EXTENSIONS = {".md", ".markdown", ".txt", ".text"}
HTML_EXTENSIONS = {".html", ".htm"}
SUPPORTED_EXTENSIONS = {".pdf", *TEXT_EXTENSIONS, *HTML_EXTENSIONS}
_TOKEN_RE = re.compile(r"[A-Za-z0-9_:/.-]+")

_CROSS_ENCODER_CACHE: Dict[str, Any] = {}
_CROSS_ENCODER_IMPORT_FAILED = False


class KnowledgeBaseError(Exception):
    """Raised when KB operations fail."""


@dataclass
class RetrievalOptions:
    strategy: str = DEFAULT_RAG_STRATEGY
    reranker: str = DEFAULT_RAG_RERANKER
    candidates: int = DEFAULT_RAG_CANDIDATES
    min_score: float = DEFAULT_RAG_MIN_SCORE
    rrf_k: int = DEFAULT_RAG_RRF_K
    mmr_lambda: float = DEFAULT_RAG_MMR_LAMBDA
    max_per_source: int = DEFAULT_RAG_MAX_PER_SOURCE
    local_rerank_model: str = DEFAULT_LOCAL_RERANK_MODEL


@dataclass
class ChunkRecord:
    kb_name: str
    chunk_id: str
    source: str
    text: str
    token_count: int
    chunk_index: int
    term_freq: Dict[str, int] = field(default_factory=dict)
    doc_len: int = 0


@dataclass
class LoadedKB:
    name: str
    chunks: List[dict]
    embeddings: np.ndarray
    meta: dict
    bm25_df: Dict[str, int]
    bm25_avgdl: float


def get_kb_root() -> Path:
    """Return the base directory for all knowledge bases."""
    base = os.getenv("THREAT_THINKER_KB_ROOT", "~/.threat-thinker/kb")
    path = Path(base).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _get_encoding(model: str):
    try:
        return tiktoken.encoding_for_model(model)
    except KeyError:
        return tiktoken.get_encoding("cl100k_base")


def _read_text_from_file(file_path: Path) -> str:
    if not file_path.exists():
        raise KnowledgeBaseError(f"File not found: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise KnowledgeBaseError(
                "pypdf is required to read PDF documents. Install dependencies via pip."
            ) from exc

        reader = PdfReader(str(file_path))
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n".join(pages)

    if suffix in HTML_EXTENSIONS:
        try:
            from bs4 import BeautifulSoup
        except ImportError as exc:
            raise KnowledgeBaseError(
                "beautifulsoup4 is required to parse HTML documents."
            ) from exc

        text = file_path.read_text(encoding="utf-8", errors="ignore")
        soup = BeautifulSoup(text, "html.parser")
        return soup.get_text(separator=" ", strip=True)

    if suffix in TEXT_EXTENSIONS:
        return file_path.read_text(encoding="utf-8", errors="ignore")

    raise KnowledgeBaseError(
        f"Unsupported file type: {suffix}. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
    )


def _tokenize(text: str) -> List[str]:
    return [tok.lower() for tok in _TOKEN_RE.findall(text) if len(tok) > 1]


def _term_freq(tokens: List[str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for tok in tokens:
        counts[tok] = counts.get(tok, 0) + 1
    return counts


def _chunk_text(
    text: str,
    chunk_tokens: int,
    chunk_overlap: int,
    encoder,
) -> Iterator[tuple[str, int]]:
    tokens = encoder.encode(text)
    total = len(tokens)
    if not tokens:
        return

    if chunk_tokens <= 0:
        raise KnowledgeBaseError("chunk_tokens must be positive")

    if chunk_overlap >= chunk_tokens:
        chunk_overlap = max(0, chunk_tokens // 4)

    start = 0
    while start < total:
        end = min(total, start + chunk_tokens)
        piece = encoder.decode(tokens[start:end])
        yield piece, end - start
        if end >= total:
            break
        start = max(0, end - chunk_overlap)


def _batched(iterable: Iterable[str], batch_size: int) -> Iterator[List[str]]:
    batch: List[str] = []
    for item in iterable:
        batch.append(item)
        if len(batch) == batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _embed_with_openai(texts: List[str], model: str) -> np.ndarray:
    if not texts:
        return np.zeros((0, 0), dtype=np.float32)

    try:
        from openai import OpenAI
    except ImportError as exc:
        raise KnowledgeBaseError(
            "openai python package is required for embeddings."
        ) from exc

    client = OpenAI()
    vectors: List[List[float]] = []
    for batch in _batched(texts, 64):
        response = client.embeddings.create(model=model, input=batch)
        vectors.extend(item.embedding for item in response.data)
    return np.array(vectors, dtype=np.float32)


def _cosine_similarities(embeddings: np.ndarray, query_vec: np.ndarray) -> np.ndarray:
    if embeddings.ndim != 2:
        raise KnowledgeBaseError("Invalid embedding matrix format.")

    doc_norms = np.linalg.norm(embeddings, axis=1)
    query_norm = np.linalg.norm(query_vec)
    if query_norm == 0:
        raise KnowledgeBaseError("Query embedding has zero norm.")

    return embeddings.dot(query_vec) / (doc_norms * query_norm + 1e-10)


def _compute_bm25_stats(chunks: List[dict]) -> Tuple[Dict[str, int], float]:
    if not chunks:
        return {}, 0.0

    doc_freq: Dict[str, int] = {}
    total_len = 0
    for chunk in chunks:
        terms = chunk.get("term_freq") or {}
        if not isinstance(terms, dict):
            terms = {}
        doc_len = chunk.get("doc_len")
        if not isinstance(doc_len, int) or doc_len <= 0:
            doc_len = int(
                sum(int(v) for v in terms.values())
                or len(_tokenize(chunk.get("text", "")))
            )
            chunk["doc_len"] = doc_len
        if not terms:
            terms = _term_freq(_tokenize(chunk.get("text", "")))
            chunk["term_freq"] = terms
        total_len += max(1, doc_len)
        for term in terms.keys():
            doc_freq[term] = doc_freq.get(term, 0) + 1

    avgdl = float(total_len) / float(max(1, len(chunks)))
    return doc_freq, avgdl


def _bm25_scores(
    chunks: List[dict], query: str, doc_freq: Dict[str, int], avgdl: float
) -> np.ndarray:
    scores = np.zeros(len(chunks), dtype=np.float32)
    if not chunks:
        return scores

    query_terms = _tokenize(query)
    if not query_terms:
        return scores

    n_docs = max(1, len(chunks))
    k1 = 1.5
    b = 0.75

    unique_terms = list(dict.fromkeys(query_terms))
    for i, chunk in enumerate(chunks):
        terms = chunk.get("term_freq") or {}
        if not isinstance(terms, dict):
            continue
        dl = float(max(1, int(chunk.get("doc_len", 0) or 0)))
        denom_base = k1 * (1.0 - b + b * (dl / max(1e-6, avgdl or 1.0)))

        score = 0.0
        for term in unique_terms:
            tf_raw = terms.get(term, 0)
            try:
                tf = float(tf_raw)
            except (TypeError, ValueError):
                tf = 0.0
            if tf <= 0:
                continue
            df = float(doc_freq.get(term, 0))
            idf = math.log(1.0 + ((n_docs - df + 0.5) / (df + 0.5)))
            score += idf * ((tf * (k1 + 1.0)) / (tf + denom_base))

        scores[i] = float(score)
    return scores


def _normalize(values: List[float]) -> List[float]:
    if not values:
        return []
    lo = min(values)
    hi = max(values)
    if hi - lo < 1e-10:
        return [1.0 for _ in values]
    return [(v - lo) / (hi - lo) for v in values]


def _rrf_score(rank: int, k: int) -> float:
    return 1.0 / float(k + rank)


def _source_cap_reached(
    source_counts: Dict[str, int], source: Optional[str], cap: int
) -> bool:
    if cap <= 0:
        return False
    if not source:
        return False
    return source_counts.get(source, 0) >= cap


def _cosine_pair(vec_a: np.ndarray, vec_b: np.ndarray) -> float:
    denom = (np.linalg.norm(vec_a) * np.linalg.norm(vec_b)) + 1e-10
    if denom == 0:
        return 0.0
    return float(np.dot(vec_a, vec_b) / denom)


def _apply_mmr(
    candidates: List[dict],
    topk: int,
    mmr_lambda: float,
    max_per_source: int,
) -> List[dict]:
    if topk <= 0 or not candidates:
        return []

    selected: List[dict] = []
    selected_vecs: List[np.ndarray] = []
    source_counts: Dict[str, int] = {}

    remaining = list(candidates)
    while remaining and len(selected) < topk:
        best_idx = -1
        best_score = -1e9
        for idx, cand in enumerate(remaining):
            source = cand.get("source")
            if _source_cap_reached(source_counts, source, max_per_source):
                continue

            relevance = float(cand.get("final_score", 0.0))
            vec = cand.get("_vector")
            if selected_vecs and isinstance(vec, np.ndarray):
                diversity = max(_cosine_pair(vec, chosen) for chosen in selected_vecs)
            else:
                diversity = 0.0
            mmr_score = mmr_lambda * relevance - (1.0 - mmr_lambda) * diversity
            if mmr_score > best_score:
                best_score = mmr_score
                best_idx = idx

        if best_idx < 0:
            break

        chosen = remaining.pop(best_idx)
        selected.append(chosen)
        vec = chosen.get("_vector")
        if isinstance(vec, np.ndarray):
            selected_vecs.append(vec)
        source = chosen.get("source")
        if source:
            source_counts[source] = source_counts.get(source, 0) + 1

    return selected


def _load_cross_encoder(model_name: str):
    global _CROSS_ENCODER_IMPORT_FAILED

    if model_name in _CROSS_ENCODER_CACHE:
        return _CROSS_ENCODER_CACHE[model_name]
    if _CROSS_ENCODER_IMPORT_FAILED:
        return None

    try:
        from sentence_transformers import CrossEncoder
    except Exception:  # pragma: no cover - optional dependency
        _CROSS_ENCODER_IMPORT_FAILED = True
        return None

    try:
        model = CrossEncoder(model_name)
    except Exception:  # pragma: no cover - runtime env dependent
        return None

    _CROSS_ENCODER_CACHE[model_name] = model
    return model


def _run_local_rerank(
    query: str,
    candidates: List[dict],
    model_name: str,
) -> Optional[List[float]]:
    model = _load_cross_encoder(model_name)
    if model is None:
        return None

    pairs = [(query, (cand.get("text") or "")[:3500]) for cand in candidates]
    if not pairs:
        return []

    try:
        scores = model.predict(pairs)
    except Exception:  # pragma: no cover - runtime env dependent
        return None

    if isinstance(scores, np.ndarray):
        return [float(x) for x in scores.tolist()]
    return [float(x) for x in scores]


def _validate_retrieval_options(options: RetrievalOptions) -> None:
    if options.strategy not in RAG_STRATEGIES:
        raise KnowledgeBaseError(
            f"Unsupported rag strategy '{options.strategy}'. Choose from: {sorted(RAG_STRATEGIES)}"
        )
    if options.reranker not in RAG_RERANKERS:
        raise KnowledgeBaseError(
            f"Unsupported rag reranker '{options.reranker}'. Choose from: {sorted(RAG_RERANKERS)}"
        )
    if options.candidates <= 0:
        raise KnowledgeBaseError("rag candidates must be a positive integer")
    if not (0.0 <= options.min_score <= 1.0):
        raise KnowledgeBaseError("rag min score must be between 0 and 1")
    if options.rrf_k <= 0:
        raise KnowledgeBaseError("rrf_k must be positive")
    if not (0.0 <= options.mmr_lambda <= 1.0):
        raise KnowledgeBaseError("mmr_lambda must be between 0 and 1")


def _load_kb(kb_name: str) -> tuple[List[dict], np.ndarray, dict]:
    kb_path = get_kb_root() / kb_name
    if not kb_path.exists():
        raise KnowledgeBaseError(f"Knowledge base '{kb_name}' not found.")

    chunks_path = kb_path / "chunks.jsonl"
    if not chunks_path.exists():
        raise KnowledgeBaseError(f"chunks.jsonl is missing for KB '{kb_name}'.")

    embeddings_path = kb_path / "embeddings.npy"
    if not embeddings_path.exists():
        raise KnowledgeBaseError(f"embeddings.npy is missing for KB '{kb_name}'.")

    with open(chunks_path, "r", encoding="utf-8") as f:
        chunks = [json.loads(line) for line in f if line.strip()]

    embeddings = np.load(embeddings_path, allow_pickle=False)
    if len(chunks) != len(embeddings):
        raise KnowledgeBaseError(
            f"Chunk/embedding count mismatch for KB '{kb_name}'. Re-run `kb build`."
        )

    meta = {}
    meta_path = kb_path / "meta.json"
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

    # Backfill sparse metadata for legacy KBs.
    _, avgdl = _compute_bm25_stats(chunks)
    if "bm25_avgdl" not in meta:
        meta["bm25_avgdl"] = avgdl
    return chunks, embeddings, meta


def _load_kb_bundle(kb_name: str) -> LoadedKB:
    chunks, embeddings, meta = _load_kb(kb_name)
    bm25_df, bm25_avgdl = _compute_bm25_stats(chunks)
    return LoadedKB(
        name=kb_name,
        chunks=chunks,
        embeddings=embeddings,
        meta=meta,
        bm25_df=bm25_df,
        bm25_avgdl=bm25_avgdl,
    )


def _dense_rank(
    chunks: List[dict],
    embeddings: np.ndarray,
    query: str,
    topk: int,
    model: str,
    embedder: Callable[[List[str], str], np.ndarray],
) -> Tuple[List[int], Dict[int, float], np.ndarray]:
    if not chunks or topk <= 0:
        return [], {}, np.zeros((0,), dtype=np.float32)

    qvecs = embedder([query], model)
    if qvecs.size == 0:
        return [], {}, np.zeros((0,), dtype=np.float32)

    qvec = qvecs[0]
    sims = _cosine_similarities(embeddings, qvec)
    top_indices = np.argsort(sims)[::-1][:topk]
    scores = {int(idx): float(sims[idx]) for idx in top_indices}
    return [int(i) for i in top_indices], scores, qvec


def _sparse_rank(
    bundle: LoadedKB, query: str, topk: int
) -> Tuple[List[int], Dict[int, float]]:
    if not bundle.chunks or topk <= 0:
        return [], {}
    sparse_scores = _bm25_scores(
        bundle.chunks, query, bundle.bm25_df, bundle.bm25_avgdl
    )
    top_indices = np.argsort(sparse_scores)[::-1][:topk]
    scores = {int(idx): float(sparse_scores[idx]) for idx in top_indices}
    return [int(i) for i in top_indices], scores


def build_kb(
    kb_name: str,
    embed_model: str = DEFAULT_EMBED_MODEL,
    chunk_tokens: int = DEFAULT_CHUNK_TOKENS,
    chunk_overlap: int = DEFAULT_CHUNK_OVERLAP,
    embed_fn: Optional[Callable[[List[str], str], np.ndarray]] = None,
) -> dict:
    """Build or rebuild a KB from raw documents."""
    kb_path = get_kb_root() / kb_name
    raw_dir = kb_path / "raw"
    if not raw_dir.exists():
        raise KnowledgeBaseError(
            f"No documents found in {raw_dir}\nPlease place your documents and re-run `kb build`."
        )

    files = [
        f
        for f in raw_dir.iterdir()
        if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS
    ]
    if not files:
        raise KnowledgeBaseError(
            f"No supported documents found in {raw_dir}\nSupported extensions: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    encoder = _get_encoding(embed_model)
    chunks: List[ChunkRecord] = []
    chunk_texts: List[str] = []

    for fpath in sorted(files):
        text = _read_text_from_file(fpath)
        if not text.strip():
            continue
        chunk_iter = _chunk_text(text, chunk_tokens, chunk_overlap, encoder)
        for idx, (chunk_text, token_count) in enumerate(chunk_iter):
            tokens = _tokenize(chunk_text)
            terms = _term_freq(tokens)
            chunk_id = f"{fpath.stem}-{idx:05d}"
            chunks.append(
                ChunkRecord(
                    kb_name=kb_name,
                    chunk_id=chunk_id,
                    source=fpath.name,
                    text=chunk_text,
                    token_count=token_count,
                    chunk_index=idx,
                    term_freq=terms,
                    doc_len=max(1, len(tokens)),
                )
            )
            chunk_texts.append(chunk_text)

    if not chunks:
        raise KnowledgeBaseError("Unable to generate chunks from provided documents.")

    embedder = embed_fn or _embed_with_openai
    embeddings = embedder(chunk_texts, embed_model)
    if embeddings.shape[0] != len(chunks):
        raise KnowledgeBaseError(
            f"Embedding count mismatch (expected {len(chunks)}, got {embeddings.shape[0]})"
        )

    kb_path.mkdir(parents=True, exist_ok=True)
    with open(kb_path / "chunks.jsonl", "w", encoding="utf-8") as f:
        for rec in chunks:
            f.write(
                json.dumps(
                    {
                        "chunk_id": rec.chunk_id,
                        "source": rec.source,
                        "text": rec.text,
                        "token_count": rec.token_count,
                        "chunk_index": rec.chunk_index,
                        "term_freq": rec.term_freq,
                        "doc_len": rec.doc_len,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    np.save(kb_path / "embeddings.npy", embeddings, allow_pickle=False)

    bm25_df, bm25_avgdl = _compute_bm25_stats(
        [
            {
                "term_freq": rec.term_freq,
                "doc_len": rec.doc_len,
                "text": rec.text,
            }
            for rec in chunks
        ]
    )

    meta = {
        "kb_name": kb_name,
        "embedding_model": embed_model,
        "chunk_tokens": chunk_tokens,
        "chunk_overlap": chunk_overlap,
        "num_chunks": len(chunks),
        "num_documents": len(files),
        "bm25_avgdl": bm25_avgdl,
        "bm25_vocab_size": len(bm25_df),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(kb_path / "meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    return meta


def list_kbs() -> List[dict]:
    root = get_kb_root()
    entries = []
    for kb_dir in sorted(root.iterdir()):
        if not kb_dir.is_dir():
            continue
        meta_file = kb_dir / "meta.json"
        meta = {}
        if meta_file.exists():
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
        entries.append(
            {
                "name": kb_dir.name,
                "num_chunks": meta.get("num_chunks", 0),
                "num_documents": meta.get("num_documents", 0),
                "embedding_model": meta.get("embedding_model"),
                "updated_at": meta.get("updated_at"),
            }
        )
    return entries


def search_kb(
    kb_name: str,
    query: str,
    topk: int = DEFAULT_TOPK,
    embed_model: Optional[str] = None,
    embed_fn: Optional[Callable[[List[str], str], np.ndarray]] = None,
    strategy: str = "dense",
) -> List[dict]:
    bundle = _load_kb_bundle(kb_name)
    if not bundle.chunks:
        return []

    model = embed_model or bundle.meta.get("embedding_model") or DEFAULT_EMBED_MODEL
    embedder = embed_fn or _embed_with_openai

    strategy = (strategy or "dense").strip().lower()
    if strategy not in RAG_STRATEGIES:
        raise KnowledgeBaseError(
            f"Unsupported search strategy '{strategy}'. Choose from: {sorted(RAG_STRATEGIES)}"
        )

    dense_indices, dense_scores, _ = _dense_rank(
        bundle.chunks, bundle.embeddings, query, max(1, topk), model, embedder
    )

    if strategy == "dense":
        results = []
        for idx in dense_indices[:topk]:
            chunk = bundle.chunks[int(idx)]
            score = float(dense_scores.get(int(idx), 0.0))
            results.append(
                {
                    "kb": kb_name,
                    "chunk_id": chunk["chunk_id"],
                    "score": score,
                    "source": chunk.get("source"),
                    "text": chunk.get("text", ""),
                    "dense_score": score,
                    "sparse_score": 0.0,
                    "fused_score": score,
                    "rerank_score": None,
                    "final_score": score,
                }
            )
        return results

    sparse_indices, sparse_scores = _sparse_rank(bundle, query, max(1, topk))
    dense_ranks = {idx: rank + 1 for rank, idx in enumerate(dense_indices)}
    sparse_ranks = {idx: rank + 1 for rank, idx in enumerate(sparse_indices)}
    dense_norm_vals = _normalize([dense_scores[idx] for idx in dense_indices])
    sparse_norm_vals = _normalize([sparse_scores[idx] for idx in sparse_indices])
    dense_norm = {idx: dense_norm_vals[pos] for pos, idx in enumerate(dense_indices)}
    sparse_norm = {idx: sparse_norm_vals[pos] for pos, idx in enumerate(sparse_indices)}

    fused: Dict[int, float] = {}
    for idx in set(dense_ranks.keys()) | set(sparse_ranks.keys()):
        score = 0.0
        if idx in dense_ranks:
            score += DEFAULT_RAG_DENSE_RRF_WEIGHT * _rrf_score(
                dense_ranks[idx], DEFAULT_RAG_RRF_K
            )
            score += DEFAULT_RAG_DENSE_RAW_WEIGHT * dense_norm.get(idx, 0.0)
        if idx in sparse_ranks:
            score += DEFAULT_RAG_SPARSE_RRF_WEIGHT * _rrf_score(
                sparse_ranks[idx], DEFAULT_RAG_RRF_K
            )
            score += DEFAULT_RAG_SPARSE_RAW_WEIGHT * sparse_norm.get(idx, 0.0)
        fused[idx] = score

    top_indices = sorted(fused.keys(), key=lambda i: fused[i], reverse=True)[:topk]
    results = []
    for idx in top_indices:
        chunk = bundle.chunks[int(idx)]
        final = float(fused[idx])
        results.append(
            {
                "kb": kb_name,
                "chunk_id": chunk["chunk_id"],
                "score": final,
                "source": chunk.get("source"),
                "text": chunk.get("text", ""),
                "dense_score": float(dense_scores.get(int(idx), 0.0)),
                "sparse_score": float(sparse_scores.get(int(idx), 0.0)),
                "fused_score": final,
                "rerank_score": None,
                "final_score": final,
            }
        )
    return results


def remove_kb(kb_name: str):
    kb_path = get_kb_root() / kb_name
    if not kb_path.exists():
        raise KnowledgeBaseError(f"Knowledge base '{kb_name}' does not exist.")
    shutil.rmtree(kb_path)


def generate_graph_query(graph) -> str:
    from threat_thinker.models import Graph as ThreatGraph

    if isinstance(graph, ThreatGraph):
        nodes = [
            f"{node.id}:{node.label} zone={node.zone or 'n/a'} type={node.type or 'n/a'} data={','.join(node.data) or 'none'}"
            for node in graph.nodes.values()
        ]
        edges = [
            f"{edge.src}->{edge.dst} ({edge.label or 'flow'}) data={','.join(edge.data) or 'none'}"
            for edge in graph.edges
        ]
    else:
        nodes = []
        edges = []

    node_blob = "; ".join(nodes)[:2000]
    edge_blob = "; ".join(edges)[:2000]
    return (
        "Security knowledge needed for a system with components: "
        f"{node_blob} | data flows: {edge_blob}"
    )


def generate_graph_queries(graph) -> List[str]:
    from threat_thinker.models import Graph as ThreatGraph

    queries: List[str] = [generate_graph_query(graph)]
    if not isinstance(graph, ThreatGraph):
        return queries

    nodes_by_id = graph.nodes

    flow_candidates: List[Tuple[int, str]] = []
    for edge in graph.edges:
        src = nodes_by_id.get(edge.src)
        dst = nodes_by_id.get(edge.dst)
        if src is None or dst is None:
            continue

        src_zone = src.zone or (src.zones[-1] if src.zones else "n/a")
        dst_zone = dst.zone or (dst.zones[-1] if dst.zones else "n/a")
        crossing = src_zone != dst_zone
        data_items = ", ".join(edge.data or src.data or dst.data) or "none"
        proto = edge.protocol or edge.label or "unknown"

        risk = 0
        if crossing:
            risk += 2
        if data_items != "none":
            risk += 2
        if any(tag in proto.lower() for tag in ["http", "sql", "grpc", "tcp", "ssh"]):
            risk += 1

        query = (
            f"Security controls and abuse cases for flow {src.label} ({src_zone}) -> {dst.label} ({dst_zone}) "
            f"over {proto}; data={data_items}. Include authentication, authorization, encryption, and tampering risks."
        )
        flow_candidates.append((risk, query))

    for _, query in sorted(flow_candidates, key=lambda it: it[0], reverse=True)[:3]:
        queries.append(query)

    sensitive_nodes = [
        n
        for n in nodes_by_id.values()
        if n.data and any((d or "").strip() for d in n.data)
    ]
    for node in sensitive_nodes[:2]:
        data_items = ", ".join(node.data)
        queries.append(
            f"Threat modeling guidance for handling sensitive data ({data_items}) in component {node.label} "
            f"(type={node.type or 'n/a'}, zone={node.zone or 'n/a'})."
        )

    public_markers = {"internet", "public", "external", "untrusted", "dmz"}
    public_nodes = []
    for node in nodes_by_id.values():
        zone_text = " ".join([node.zone or "", *node.zones]).lower()
        node_type = (node.type or "").lower()
        if any(marker in zone_text for marker in public_markers) or node_type in {
            "actor",
            "client",
            "gateway",
            "browser",
        }:
            public_nodes.append(node)

    for node in public_nodes[:2]:
        queries.append(
            f"Common attack patterns and mitigations for internet-facing component {node.label} "
            f"(type={node.type or 'n/a'}, zone={node.zone or 'n/a'})."
        )

    # Preserve order while deduplicating.
    unique: List[str] = []
    seen = set()
    for query in queries:
        normalized = " ".join(query.split()).lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(query)
    return unique[:8]


def _select_reranker_backend(
    options: RetrievalOptions,
    rerank_fn: Optional[Callable[[str, List[dict]], List[float]]],
) -> str:
    mode = options.reranker

    if mode == "off":
        return "off"

    local_available = _load_cross_encoder(options.local_rerank_model) is not None

    if mode == "local":
        if not local_available:
            raise KnowledgeBaseError(
                "Local reranker requested but sentence-transformers/cross-encoder model is unavailable."
            )
        return "local"

    if mode == "llm":
        if rerank_fn is None:
            raise KnowledgeBaseError(
                "LLM reranker requested but no rerank function is provided."
            )
        return "llm"

    # auto
    if local_available:
        return "local"
    if rerank_fn is not None:
        return "llm"
    return "off"


def retrieve_context_for_graph(
    graph,
    kb_names: List[str],
    topk: int = DEFAULT_TOPK,
    embed_fn: Optional[Callable[[List[str], str], np.ndarray]] = None,
    options: Optional[RetrievalOptions] = None,
    rerank_fn: Optional[Callable[[str, List[dict]], List[float]]] = None,
) -> dict:
    if not kb_names:
        raise KnowledgeBaseError("At least one KB name is required for retrieval.")

    opts = options or RetrievalOptions()
    _validate_retrieval_options(opts)

    if topk <= 0:
        raise KnowledgeBaseError("topk must be a positive integer")

    query = generate_graph_query(graph)

    if opts.strategy == "dense":
        aggregated: List[dict] = []
        for kb in kb_names:
            aggregated.extend(
                search_kb(
                    kb,
                    query,
                    topk=topk,
                    embed_fn=embed_fn,
                    strategy="dense",
                )
            )
        aggregated.sort(key=lambda r: r.get("score", 0.0), reverse=True)
        trimmed = aggregated[:topk]
        context_blocks = []
        for item in trimmed:
            context_blocks.append(
                f"[KB:{item['kb']} | chunk:{item['chunk_id']} | score:{item['score']:.3f} | source:{item.get('source')}]"
                f"\n{(item.get('text') or '').strip()}\n"
            )
        return {
            "query": query,
            "queries": [query],
            "results": trimmed,
            "candidate_results": list(aggregated),
            "context_text": "\n".join(context_blocks).strip(),
            "reranker_backend": "off",
        }

    queries = generate_graph_queries(graph)
    embedder = embed_fn or _embed_with_openai

    bundles = [_load_kb_bundle(kb) for kb in kb_names]
    fused_candidates: Dict[Tuple[str, int], dict] = {}

    per_query_limit = max(topk, opts.candidates)

    for bundle in bundles:
        model = bundle.meta.get("embedding_model") or DEFAULT_EMBED_MODEL

        for q in queries:
            dense_indices, dense_scores, _ = _dense_rank(
                bundle.chunks,
                bundle.embeddings,
                q,
                per_query_limit,
                model,
                embedder,
            )
            sparse_indices, sparse_scores = _sparse_rank(bundle, q, per_query_limit)

            dense_ranks = {idx: rank + 1 for rank, idx in enumerate(dense_indices)}
            sparse_ranks = {idx: rank + 1 for rank, idx in enumerate(sparse_indices)}
            dense_norm_vals = _normalize([dense_scores[idx] for idx in dense_indices])
            sparse_norm_vals = _normalize(
                [sparse_scores[idx] for idx in sparse_indices]
            )
            dense_norm = {
                idx: dense_norm_vals[pos] for pos, idx in enumerate(dense_indices)
            }
            sparse_norm = {
                idx: sparse_norm_vals[pos] for pos, idx in enumerate(sparse_indices)
            }

            merged_indices = set(dense_ranks.keys()) | set(sparse_ranks.keys())
            for idx in merged_indices:
                key = (bundle.name, idx)
                chunk = bundle.chunks[idx]
                fused = 0.0
                if idx in dense_ranks:
                    fused += DEFAULT_RAG_DENSE_RRF_WEIGHT * _rrf_score(
                        dense_ranks[idx], opts.rrf_k
                    )
                    fused += DEFAULT_RAG_DENSE_RAW_WEIGHT * dense_norm.get(idx, 0.0)
                if idx in sparse_ranks:
                    fused += DEFAULT_RAG_SPARSE_RRF_WEIGHT * _rrf_score(
                        sparse_ranks[idx], opts.rrf_k
                    )
                    fused += DEFAULT_RAG_SPARSE_RAW_WEIGHT * sparse_norm.get(idx, 0.0)

                rec = fused_candidates.get(key)
                if rec is None:
                    rec = {
                        "kb": bundle.name,
                        "chunk_id": chunk.get("chunk_id"),
                        "source": chunk.get("source"),
                        "text": chunk.get("text", ""),
                        "dense_score": 0.0,
                        "sparse_score": 0.0,
                        "fused_score": 0.0,
                        "query_hits": [],
                        "_vector": bundle.embeddings[idx],
                    }
                    fused_candidates[key] = rec

                rec["dense_score"] = max(
                    float(rec.get("dense_score", 0.0)),
                    float(dense_scores.get(idx, 0.0)),
                )
                rec["sparse_score"] = max(
                    float(rec.get("sparse_score", 0.0)),
                    float(sparse_scores.get(idx, 0.0)),
                )
                rec["fused_score"] = float(rec.get("fused_score", 0.0)) + float(fused)
                rec["query_hits"].append(q)

    if not fused_candidates:
        return {
            "query": query,
            "queries": queries,
            "results": [],
            "candidate_results": [],
            "context_text": "",
            "reranker_backend": "off",
        }

    candidates = sorted(
        fused_candidates.values(),
        key=lambda rec: float(rec.get("fused_score", 0.0)),
        reverse=True,
    )[: opts.candidates]

    fused_norm = _normalize([float(c.get("fused_score", 0.0)) for c in candidates])
    for c, score in zip(candidates, fused_norm):
        c["fused_norm"] = score

    backend = _select_reranker_backend(opts, rerank_fn)
    rerank_scores_raw: List[float] = []
    if backend == "local":
        local_scores = _run_local_rerank(query, candidates, opts.local_rerank_model)
        if local_scores is None:
            if opts.reranker == "local":
                raise KnowledgeBaseError("Local reranking failed.")
            backend = "off"
        else:
            rerank_scores_raw = local_scores
    elif backend == "llm":
        try:
            rerank_scores_raw = rerank_fn(query, candidates) if rerank_fn else []
        except Exception as exc:
            if opts.reranker == "llm":
                raise KnowledgeBaseError(f"LLM reranking failed: {exc}") from exc
            backend = "off"

    if backend in {"local", "llm"} and rerank_scores_raw:
        rerank_scores = _normalize([float(x) for x in rerank_scores_raw])
    else:
        rerank_scores = []

    for idx, cand in enumerate(candidates):
        fused_component = float(cand.get("fused_norm", 0.0))
        if rerank_scores and idx < len(rerank_scores):
            rerank_component = float(rerank_scores[idx])
            final = 0.8 * rerank_component + 0.2 * fused_component
            cand["rerank_score"] = rerank_component
        else:
            final = fused_component
            cand["rerank_score"] = None
        cand["final_score"] = float(final)

    filtered = [
        c for c in candidates if float(c.get("final_score", 0.0)) >= opts.min_score
    ]
    if not filtered and candidates:
        filtered = candidates[:1]

    ranked_candidates = sorted(
        filtered, key=lambda rec: float(rec.get("final_score", 0.0)), reverse=True
    )

    selected = _apply_mmr(
        ranked_candidates,
        topk,
        opts.mmr_lambda,
        opts.max_per_source,
    )

    results: List[dict] = []
    for cand in selected:
        result = {
            "kb": cand.get("kb"),
            "chunk_id": cand.get("chunk_id"),
            "score": float(cand.get("final_score", 0.0)),
            "source": cand.get("source"),
            "text": cand.get("text", ""),
            "dense_score": float(cand.get("dense_score", 0.0)),
            "sparse_score": float(cand.get("sparse_score", 0.0)),
            "fused_score": float(cand.get("fused_score", 0.0)),
            "rerank_score": cand.get("rerank_score"),
            "final_score": float(cand.get("final_score", 0.0)),
            "query_hits": list(dict.fromkeys(cand.get("query_hits", []))),
        }
        results.append(result)

    context_blocks = []
    for item in results:
        context_blocks.append(
            f"[KB:{item['kb']} | chunk:{item['chunk_id']} | score:{item['score']:.3f} | source:{item.get('source')}]"
            f"\n{(item.get('text') or '').strip()}\n"
        )

    candidate_results: List[dict] = []
    for cand in ranked_candidates:
        candidate_results.append(
            {
                "kb": cand.get("kb"),
                "chunk_id": cand.get("chunk_id"),
                "score": float(cand.get("final_score", 0.0)),
                "source": cand.get("source"),
                "text": cand.get("text", ""),
                "dense_score": float(cand.get("dense_score", 0.0)),
                "sparse_score": float(cand.get("sparse_score", 0.0)),
                "fused_score": float(cand.get("fused_score", 0.0)),
                "rerank_score": cand.get("rerank_score"),
                "final_score": float(cand.get("final_score", 0.0)),
                "query_hits": list(dict.fromkeys(cand.get("query_hits", []))),
            }
        )

    return {
        "query": query,
        "queries": queries,
        "results": results,
        "candidate_results": candidate_results,
        "context_text": "\n".join(context_blocks).strip(),
        "reranker_backend": backend,
    }


def _normalize_rag_source(rec: dict, method: str) -> dict:
    score = rec.get("score")
    try:
        score_val = float(score)
    except (TypeError, ValueError):
        score_val = 0.0
    return {
        "kb": str(rec.get("kb") or ""),
        "source": str(rec.get("source") or ""),
        "chunk_id": str(rec.get("chunk_id") or ""),
        "score": max(0.0, min(1.0, score_val)),
        "method": method,
    }


def _threat_query_text(threat) -> str:
    stride = ", ".join([str(s) for s in (threat.stride or [])])
    affected = ", ".join([str(a) for a in (threat.affected or [])])
    return f"{threat.title}\n{threat.why}\nSTRIDE: {stride}\nAffected: {affected}"


def _token_overlap_score(query: str, text: str) -> float:
    q_terms = set(_tokenize(query))
    t_terms = set(_tokenize(text))
    if not q_terms or not t_terms:
        return 0.0
    inter = len(q_terms & t_terms)
    return float(inter) / float(max(1, len(q_terms)))


def attach_rag_sources_to_threats(
    threats: List[Any],
    retrieval: Optional[dict],
    reranker_backend: str = "off",
    rerank_fn: Optional[Callable[[str, List[dict]], List[float]]] = None,
    min_score: float = 0.0,
    max_sources_per_threat: int = 2,
) -> tuple[List[Any], int]:
    """
    Attach RAG document citations to each threat.
    Threats without citations are dropped (strict mode).
    """
    if not threats:
        return [], 0

    if not retrieval:
        return [], len(threats)

    candidates: List[dict] = list(retrieval.get("candidate_results") or []) or list(
        retrieval.get("results") or []
    )
    if not candidates:
        return [], len(threats)

    threshold = max(0.0, float(min_score))
    filtered_candidates = [
        c
        for c in candidates
        if float(c.get("final_score", c.get("score", 0.0))) >= threshold
    ]
    if not filtered_candidates:
        filtered_candidates = list(candidates)

    by_chunk: Dict[str, List[dict]] = {}
    for cand in filtered_candidates:
        chunk_id = str(cand.get("chunk_id") or "")
        if not chunk_id:
            continue
        by_chunk.setdefault(chunk_id, []).append(cand)

    kept: List[Any] = []
    dropped = 0

    for threat in threats:
        assigned: List[dict] = []
        seen_keys = set()

        # 1) Validate LLM self-reported sources against retrieved candidates.
        for raw in getattr(threat, "rag_sources", []) or []:
            if not isinstance(raw, dict):
                continue
            chunk_id = str(raw.get("chunk_id") or "")
            if not chunk_id:
                continue
            matched = by_chunk.get(chunk_id) or []
            if raw.get("kb"):
                kb = str(raw.get("kb"))
                matched = [
                    m for m in matched if str(m.get("kb") or "") == kb
                ] or matched
            if not matched:
                continue
            best = max(
                matched, key=lambda m: float(m.get("final_score", m.get("score", 0.0)))
            )
            key = (best.get("kb"), best.get("chunk_id"))
            if key in seen_keys:
                continue
            normalized = _normalize_rag_source(
                {
                    "kb": best.get("kb"),
                    "source": best.get("source"),
                    "chunk_id": best.get("chunk_id"),
                    "score": best.get("final_score", best.get("score", 0.0)),
                },
                method="llm",
            )
            assigned.append(normalized)
            seen_keys.add(key)
            if len(assigned) >= max_sources_per_threat:
                break

        # 2) Backfill with automatic matching.
        if len(assigned) < max_sources_per_threat:
            remaining = [
                c
                for c in filtered_candidates
                if (c.get("kb"), c.get("chunk_id")) not in seen_keys
            ]
            if remaining:
                query = _threat_query_text(threat)
                auto_scores: List[float] = []

                if rerank_fn is not None and reranker_backend in {
                    "local",
                    "llm",
                    "auto",
                }:
                    try:
                        raw_scores = rerank_fn(query, remaining)
                    except Exception:
                        raw_scores = []
                    if raw_scores:
                        auto_scores = _normalize([float(s) for s in raw_scores])

                if not auto_scores:
                    auto_scores = [
                        _token_overlap_score(query, str(c.get("text") or ""))
                        for c in remaining
                    ]

                combined: List[tuple[float, dict]] = []
                for idx, cand in enumerate(remaining):
                    base = float(cand.get("final_score", cand.get("score", 0.0)))
                    backfill = (
                        float(auto_scores[idx]) if idx < len(auto_scores) else 0.0
                    )
                    combined_score = 0.7 * backfill + 0.3 * base
                    combined.append((combined_score, cand))

                combined.sort(key=lambda it: it[0], reverse=True)
                needed = max_sources_per_threat - len(assigned)
                for score, cand in combined[:needed]:
                    key = (cand.get("kb"), cand.get("chunk_id"))
                    if key in seen_keys:
                        continue
                    normalized = _normalize_rag_source(
                        {
                            "kb": cand.get("kb"),
                            "source": cand.get("source"),
                            "chunk_id": cand.get("chunk_id"),
                            "score": score,
                        },
                        method="auto",
                    )
                    assigned.append(normalized)
                    seen_keys.add(key)

        if not assigned:
            dropped += 1
            continue

        threat.rag_sources = assigned[:max_sources_per_threat]
        kept.append(threat)

    return kept, dropped
