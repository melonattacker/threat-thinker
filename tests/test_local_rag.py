import numpy as np

from threat_thinker.models import Edge, Graph, Node, Threat
from threat_thinker.rag import (
    RetrievalOptions,
    attach_rag_sources_to_threats,
    build_kb,
    generate_graph_query,
    retrieve_context_for_graph,
    search_kb,
)
import threat_thinker.rag.local as rag_local


def _fake_embed(texts, model):
    """Deterministic embeddings for tests."""
    dim = 4
    if not texts:
        return np.zeros((0, dim), dtype=np.float32)
    base = np.arange(dim, dtype=np.float32)
    return np.vstack([base + idx for idx, _ in enumerate(texts)])


def _biased_embed(texts, model):
    """Bias query vectors to make dense retrieval prefer the wrong chunk."""
    vectors = []
    for text in texts:
        low = text.lower()
        if low.startswith("security knowledge needed for a system"):
            vectors.append([0.95, 0.05])
        elif "asvs-v4" in low:
            vectors.append([0.05, 0.95])
        else:
            vectors.append([0.95, 0.05])
    return np.array(vectors, dtype=np.float32)


def test_build_and_search_kb(tmp_path, monkeypatch):
    kb_root = tmp_path / "kb"
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(kb_root))

    raw_dir = kb_root / "demo" / "raw"
    raw_dir.mkdir(parents=True)
    (raw_dir / "doc.md").write_text("Sample security guidance " * 200, encoding="utf-8")

    meta = build_kb(
        "demo",
        embed_model="test-model",
        chunk_tokens=100,
        chunk_overlap=10,
        embed_fn=_fake_embed,
    )
    assert meta["num_chunks"] > 0

    results = search_kb("demo", "security guidance", topk=3, embed_fn=_fake_embed)
    assert results, "Expected at least one search hit"
    assert results[0]["kb"] == "demo"


def test_retrieve_context_limits_results_dense_strategy(monkeypatch):
    graph = Graph(
        nodes={
            "A": Node(id="A", label="Web Server"),
            "B": Node(id="B", label="Database"),
        },
        edges=[Edge(src="A", dst="B", label="SQL over TLS")],
    )

    def _fake_search(kb_name, query, topk, embed_fn=None, strategy="dense"):
        return [
            {
                "kb": kb_name,
                "chunk_id": f"{kb_name}-chunk",
                "score": 0.9 if kb_name == "kb1" else 0.4,
                "source": f"{kb_name}.md",
                "text": f"{kb_name} content referencing {query}",
            }
        ]

    monkeypatch.setattr(rag_local, "search_kb", _fake_search)
    options = RetrievalOptions(
        strategy="dense", reranker="off", candidates=5, min_score=0.0
    )
    ctx = retrieve_context_for_graph(graph, ["kb1", "kb2"], topk=1, options=options)
    assert len(ctx["results"]) == 1
    assert ctx["results"][0]["kb"] == "kb1"
    assert "Web Server" in ctx["query"]


def test_hybrid_prioritizes_sparse_relevance(tmp_path, monkeypatch):
    kb_root = tmp_path / "kb"
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(kb_root))

    raw_dir = kb_root / "controls" / "raw"
    raw_dir.mkdir(parents=True)
    (raw_dir / "controls.md").write_text(
        "ASVS-V4 session management requirements and security controls.",
        encoding="utf-8",
    )
    (raw_dir / "notes.md").write_text(
        "Generic platform architecture and deployment notes.",
        encoding="utf-8",
    )

    build_kb(
        "controls",
        embed_model="test-model",
        chunk_tokens=120,
        chunk_overlap=10,
        embed_fn=_biased_embed,
    )

    graph = Graph(nodes={"A": Node(id="A", label="ASVS-V4 Gateway")}, edges=[])

    dense_results = search_kb(
        "controls", "ASVS-V4 guidance", topk=1, embed_fn=_biased_embed, strategy="dense"
    )
    assert dense_results

    options = RetrievalOptions(
        strategy="hybrid", reranker="off", candidates=10, min_score=0.0
    )
    ctx = retrieve_context_for_graph(
        graph,
        ["controls"],
        topk=1,
        embed_fn=_biased_embed,
        options=options,
    )

    assert ctx["results"]
    assert ctx["results"][0]["source"] == "controls.md"
    assert ctx["results"][0]["sparse_score"] > 0


def test_hybrid_rrf_is_deterministic(tmp_path, monkeypatch):
    kb_root = tmp_path / "kb"
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(kb_root))

    raw_dir = kb_root / "deterministic" / "raw"
    raw_dir.mkdir(parents=True)
    (raw_dir / "a.md").write_text("alpha security control " * 80, encoding="utf-8")
    (raw_dir / "b.md").write_text("beta security control " * 80, encoding="utf-8")

    build_kb(
        "deterministic",
        embed_model="test-model",
        chunk_tokens=100,
        chunk_overlap=20,
        embed_fn=_fake_embed,
    )

    graph = Graph(nodes={"A": Node(id="A", label="alpha")}, edges=[])
    options = RetrievalOptions(
        strategy="hybrid", reranker="off", candidates=15, min_score=0.0
    )

    first = retrieve_context_for_graph(
        graph,
        ["deterministic"],
        topk=3,
        embed_fn=_fake_embed,
        options=options,
    )
    second = retrieve_context_for_graph(
        graph,
        ["deterministic"],
        topk=3,
        embed_fn=_fake_embed,
        options=options,
    )

    assert [r["chunk_id"] for r in first["results"]] == [
        r["chunk_id"] for r in second["results"]
    ]


def test_auto_reranker_prefers_local_then_falls_back_llm(tmp_path, monkeypatch):
    kb_root = tmp_path / "kb"
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(kb_root))

    raw_dir = kb_root / "rerank" / "raw"
    raw_dir.mkdir(parents=True)
    (raw_dir / "doc.md").write_text("threat model guidance " * 120, encoding="utf-8")

    build_kb(
        "rerank",
        embed_model="test-model",
        chunk_tokens=80,
        chunk_overlap=10,
        embed_fn=_fake_embed,
    )

    graph = Graph(nodes={"A": Node(id="A", label="Threat Model")}, edges=[])

    llm_calls = {"count": 0}

    def _llm_rerank(query, candidates):
        llm_calls["count"] += 1
        return [0.9 for _ in candidates]

    class _DummyCrossEncoder:
        def predict(self, pairs):
            return np.array(
                [0.2 + 0.01 * i for i, _ in enumerate(pairs)], dtype=np.float32
            )

    monkeypatch.setattr(
        rag_local, "_load_cross_encoder", lambda model_name: _DummyCrossEncoder()
    )
    options = RetrievalOptions(
        strategy="hybrid", reranker="auto", candidates=8, min_score=0.0
    )
    local_ctx = retrieve_context_for_graph(
        graph,
        ["rerank"],
        topk=2,
        embed_fn=_fake_embed,
        options=options,
        rerank_fn=_llm_rerank,
    )
    assert local_ctx["reranker_backend"] == "local"
    assert llm_calls["count"] == 0

    monkeypatch.setattr(rag_local, "_load_cross_encoder", lambda model_name: None)
    llm_ctx = retrieve_context_for_graph(
        graph,
        ["rerank"],
        topk=2,
        embed_fn=_fake_embed,
        options=options,
        rerank_fn=_llm_rerank,
    )
    assert llm_ctx["reranker_backend"] == "llm"
    assert llm_calls["count"] > 0


def test_mmr_respects_source_cap(tmp_path, monkeypatch):
    kb_root = tmp_path / "kb"
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(kb_root))

    raw_dir = kb_root / "source-cap" / "raw"
    raw_dir.mkdir(parents=True)
    (raw_dir / "a.md").write_text("token auth control " * 300, encoding="utf-8")
    (raw_dir / "b.md").write_text(
        "token auth fallback control " * 120, encoding="utf-8"
    )

    build_kb(
        "source-cap",
        embed_model="test-model",
        chunk_tokens=60,
        chunk_overlap=20,
        embed_fn=_fake_embed,
    )

    graph = Graph(nodes={"A": Node(id="A", label="token auth")}, edges=[])
    options = RetrievalOptions(
        strategy="hybrid",
        reranker="off",
        candidates=30,
        min_score=0.0,
        max_per_source=1,
    )
    ctx = retrieve_context_for_graph(
        graph,
        ["source-cap"],
        topk=2,
        embed_fn=_fake_embed,
        options=options,
    )

    sources = [item["source"] for item in ctx["results"]]
    assert len(sources) == len(set(sources))


def test_generate_graph_query_mentions_edges():
    graph = Graph(
        nodes={
            "A": Node(id="A", label="Client"),
            "B": Node(id="B", label="API"),
        },
        edges=[Edge(src="A", dst="B", label="https")],
    )
    query = generate_graph_query(graph)
    assert "Client" in query
    assert "A->B" in query


def test_build_kb_supports_plain_text(tmp_path, monkeypatch):
    kb_root = tmp_path / "kb"
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(kb_root))

    raw_dir = kb_root / "notes" / "raw"
    raw_dir.mkdir(parents=True)
    (raw_dir / "notes.txt").write_text(
        "Playbook entry for service hardening." * 50, encoding="utf-8"
    )

    meta = build_kb(
        "notes",
        embed_model="test-model",
        chunk_tokens=120,
        chunk_overlap=20,
        embed_fn=_fake_embed,
    )
    assert meta["num_documents"] == 1
    results = search_kb("notes", "service hardening", topk=1, embed_fn=_fake_embed)
    assert results and results[0]["source"].endswith(".txt")


def test_attach_rag_sources_prefers_llm_reported_and_backfills():
    threats = [
        Threat(
            id="",
            title="Session hijack",
            stride=["S"],
            severity="High",
            score=8.0,
            affected=["Web"],
            why="Session token can be reused",
            references=["ASVS V3.1.1"],
            recommended_action="Rotate session tokens",
            evidence_nodes=["WEB"],
            evidence_edges=[],
            rag_sources=[{"chunk_id": "c2"}],
        )
    ]
    retrieval = {
        "candidate_results": [
            {
                "kb": "owasp",
                "source": "sessions.md",
                "chunk_id": "c1",
                "final_score": 0.82,
                "text": "Session fixation mitigations and token binding.",
            },
            {
                "kb": "owasp",
                "source": "auth.md",
                "chunk_id": "c2",
                "final_score": 0.91,
                "text": "Session hijack prevention for auth cookies.",
            },
        ],
        "reranker_backend": "off",
    }

    enriched, dropped = attach_rag_sources_to_threats(
        threats, retrieval, min_score=0.1, max_sources_per_threat=2
    )

    assert dropped == 0
    assert len(enriched) == 1
    assert len(enriched[0].rag_sources) == 2
    assert enriched[0].rag_sources[0]["chunk_id"] == "c2"
    assert enriched[0].rag_sources[0]["method"] == "llm"
    assert enriched[0].rag_sources[1]["method"] == "auto"


def test_attach_rag_sources_drops_threat_without_attribution():
    threats = [
        Threat(
            id="",
            title="Unknown threat",
            stride=["T"],
            severity="Low",
            score=2.0,
            affected=["API"],
            why="Insufficient context",
            references=["ASVS V1.1.1"],
            recommended_action="Investigate",
            evidence_nodes=["API"],
            evidence_edges=[],
        )
    ]
    retrieval = {"candidate_results": [], "reranker_backend": "off"}

    enriched, dropped = attach_rag_sources_to_threats(threats, retrieval, min_score=0.1)
    assert enriched == []
    assert dropped == 1


def test_attach_rag_sources_uses_rerank_fn_for_backfill():
    threat = Threat(
        id="",
        title="CSRF",
        stride=["T"],
        severity="Medium",
        score=5.0,
        affected=["Web"],
        why="No anti-CSRF token",
        references=["ASVS V4.3.2"],
        recommended_action="Use CSRF tokens",
        evidence_nodes=["WEB"],
        evidence_edges=[],
    )
    retrieval = {
        "candidate_results": [
            {
                "kb": "kb",
                "source": "a.md",
                "chunk_id": "a1",
                "final_score": 0.3,
                "text": "Generic security notes",
            },
            {
                "kb": "kb",
                "source": "b.md",
                "chunk_id": "b1",
                "final_score": 0.3,
                "text": "Cross-site request forgery mitigation guidance",
            },
        ],
        "reranker_backend": "llm",
    }

    def _rerank(query, candidates):
        assert "CSRF" in query
        # Prefer second candidate.
        return [0.1, 0.95]

    enriched, dropped = attach_rag_sources_to_threats(
        [threat],
        retrieval,
        reranker_backend="llm",
        rerank_fn=_rerank,
        min_score=0.0,
        max_sources_per_threat=1,
    )

    assert dropped == 0
    assert len(enriched) == 1
    assert enriched[0].rag_sources[0]["chunk_id"] == "b1"
