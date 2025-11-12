import numpy as np

from models import Graph, Node, Edge
from rag import (
    build_kb,
    search_kb,
    retrieve_context_for_graph,
    generate_graph_query,
)
import rag.local as rag_local


def _fake_embed(texts, model):
    """Deterministic embeddings for tests."""
    dim = 4
    if not texts:
        return np.zeros((0, dim), dtype=np.float32)
    base = np.arange(dim, dtype=np.float32)
    return np.vstack([base + idx for idx, _ in enumerate(texts)])


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


def test_retrieve_context_limits_results(monkeypatch):
    graph = Graph(
        nodes={
            "A": Node(id="A", label="Web Server"),
            "B": Node(id="B", label="Database"),
        },
        edges=[Edge(src="A", dst="B", label="SQL over TLS")],
    )

    def _fake_search(kb_name, query, topk, embed_fn=None):
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
    ctx = retrieve_context_for_graph(graph, ["kb1", "kb2"], topk=1)
    assert len(ctx["results"]) == 1
    assert ctx["results"][0]["kb"] == "kb1"
    assert "Web Server" in ctx["query"]


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
