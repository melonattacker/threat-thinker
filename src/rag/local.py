"""
Local Retrieval-Augmented Generation (RAG) helpers.

Implements a lightweight, file-based knowledge base for Threat Thinker.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, List, Optional

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
SUPPORTED_EXTENSIONS = {".pdf", ".md", ".markdown", ".html", ".htm"}


class KnowledgeBaseError(Exception):
    """Raised when KB operations fail."""


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

    if suffix in {".html", ".htm"}:
        try:
            from bs4 import BeautifulSoup
        except ImportError as exc:
            raise KnowledgeBaseError(
                "beautifulsoup4 is required to parse HTML documents."
            ) from exc

        text = file_path.read_text(encoding="utf-8", errors="ignore")
        soup = BeautifulSoup(text, "html.parser")
        return soup.get_text(separator=" ", strip=True)

    if suffix in {".md", ".markdown"}:
        return file_path.read_text(encoding="utf-8", errors="ignore")

    raise KnowledgeBaseError(
        f"Unsupported file type: {suffix}. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
    )


@dataclass
class ChunkRecord:
    kb_name: str
    chunk_id: str
    source: str
    text: str
    token_count: int
    chunk_index: int


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
            chunk_id = f"{fpath.stem}-{idx:05d}"
            chunks.append(
                ChunkRecord(
                    kb_name=kb_name,
                    chunk_id=chunk_id,
                    source=fpath.name,
                    text=chunk_text,
                    token_count=token_count,
                    chunk_index=idx,
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
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    np.save(kb_path / "embeddings.npy", embeddings, allow_pickle=False)

    meta = {
        "kb_name": kb_name,
        "embedding_model": embed_model,
        "chunk_tokens": chunk_tokens,
        "chunk_overlap": chunk_overlap,
        "num_chunks": len(chunks),
        "num_documents": len(files),
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

    return chunks, embeddings, meta


def search_kb(
    kb_name: str,
    query: str,
    topk: int = DEFAULT_TOPK,
    embed_model: Optional[str] = None,
    embed_fn: Optional[Callable[[List[str], str], np.ndarray]] = None,
) -> List[dict]:
    chunks, embeddings, meta = _load_kb(kb_name)
    if not chunks:
        return []

    model = embed_model or meta.get("embedding_model") or DEFAULT_EMBED_MODEL
    embedder = embed_fn or _embed_with_openai
    query_vec = embedder([query], model)
    if query_vec.size == 0:
        return []

    query_vec = query_vec[0]
    if embeddings.ndim != 2:
        raise KnowledgeBaseError("Invalid embedding matrix format.")

    # Normalize for cosine similarity
    doc_norms = np.linalg.norm(embeddings, axis=1)
    query_norm = np.linalg.norm(query_vec)
    if query_norm == 0:
        raise KnowledgeBaseError("Query embedding has zero norm.")

    similarities = embeddings.dot(query_vec) / (doc_norms * query_norm + 1e-10)
    top_indices = np.argsort(similarities)[::-1][:topk]

    results = []
    for idx in top_indices:
        score = float(similarities[idx])
        chunk = chunks[int(idx)]
        results.append(
            {
                "kb": kb_name,
                "chunk_id": chunk["chunk_id"],
                "score": score,
                "source": chunk.get("source"),
                "text": chunk.get("text", ""),
            }
        )
    return results


def remove_kb(kb_name: str):
    kb_path = get_kb_root() / kb_name
    if not kb_path.exists():
        raise KnowledgeBaseError(f"Knowledge base '{kb_name}' does not exist.")
    shutil.rmtree(kb_path)


def generate_graph_query(graph) -> str:
    from models import Graph as ThreatGraph

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


def retrieve_context_for_graph(
    graph,
    kb_names: List[str],
    topk: int = DEFAULT_TOPK,
    embed_fn: Optional[Callable[[List[str], str], np.ndarray]] = None,
) -> dict:
    if not kb_names:
        raise KnowledgeBaseError("At least one KB name is required for retrieval.")

    query = generate_graph_query(graph)
    aggregated: List[dict] = []
    for kb in kb_names:
        aggregated.extend(search_kb(kb, query, topk=topk, embed_fn=embed_fn))

    aggregated.sort(key=lambda r: r["score"], reverse=True)
    trimmed = aggregated[:topk]
    context_blocks = []
    for item in trimmed:
        context_blocks.append(
            f"[KB:{item['kb']} | chunk:{item['chunk_id']} | score:{item['score']:.3f} | source:{item.get('source')}]"
            f"\n{item['text'].strip()}\n"
        )

    context_text = "\n".join(context_blocks).strip()
    return {
        "query": query,
        "results": trimmed,
        "context_text": context_text,
    }
