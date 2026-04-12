import json

from fastapi.testclient import TestClient

from threat_thinker.serve.api import create_app
from threat_thinker.serve.config import ServeConfig
from threat_thinker.serve.jobstore import AsyncJobStore


def _base_config() -> ServeConfig:
    cfg = ServeConfig()
    cfg.security.auth.mode = "none"
    cfg.security.rate_limit.enabled = False
    return cfg


def _capture_enqueue(monkeypatch):
    captured = {}

    async def _fake_enqueue(self, payload):
        captured["payload"] = payload
        return "job-1"

    monkeypatch.setattr(AsyncJobStore, "enqueue", _fake_enqueue)
    return captured


def test_analyze_json_defaults_apply_config_language_and_format(monkeypatch):
    cfg = _base_config()
    cfg.engine.report.default_language = "ja"
    cfg.engine.report.default_format = "html"

    captured = _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    response = client.post(
        "/v1/analyze",
        json={"input": {"type": "mermaid", "content": "graph LR;A-->B"}},
    )

    assert response.status_code == 202
    payload = captured["payload"]
    assert payload["language"] == "ja"
    assert payload["report_formats"] == ["html"]
    assert payload["use_rag"] is False
    assert payload["kb_names"] == []


def test_analyze_multipart_options_are_used(monkeypatch):
    cfg = _base_config()
    captured = _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    options = {
        "report_formats": ["json", "html"],
        "language": "en",
        "infer_hints": True,
        "require_asvs": True,
        "min_confidence": 0.6,
        "topn": 5,
        "autodetect": True,
        "use_rag": True,
        "kb_names": ["owasp"],
        "rag_topk": 6,
        "rag_strategy": "hybrid",
        "rag_reranker": "off",
        "rag_candidates": 25,
        "rag_min_score": 0.2,
        "drawio_page": "Page-1",
    }
    response = client.post(
        "/v1/analyze",
        files={"file": ("system.mmd", "graph LR;A-->B", "text/plain")},
        data={"options": json.dumps(options)},
    )

    assert response.status_code == 202
    payload = captured["payload"]
    assert payload["report_formats"] == ["json", "html"]
    assert payload["language"] == "en"
    assert payload["infer_hints"] is True
    assert payload["require_asvs"] is True
    assert payload["min_confidence"] == 0.6
    assert payload["topn"] == 5
    assert payload["use_rag"] is True
    assert payload["kb_names"] == ["owasp"]
    assert payload["rag_topk"] == 6
    assert payload["rag_strategy"] == "hybrid"
    assert payload["rag_reranker"] == "off"
    assert payload["rag_candidates"] == 25
    assert payload["rag_min_score"] == 0.2
    assert payload["drawio_page"] == "Page-1"


def test_analyze_autodetect_respects_server_config(monkeypatch):
    cfg = _base_config()
    cfg.engine.autodetect = False

    captured = _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    options = {"autodetect": True}
    response = client.post(
        "/v1/analyze",
        files={"file": ("system.mmd", "graph LR;A-->B", "text/plain")},
        data={"type": "mermaid", "options": json.dumps(options)},
    )

    assert response.status_code == 202
    payload = captured["payload"]
    assert payload["autodetect"] is False


def test_analyze_json_rejects_rag_without_kb_names(monkeypatch):
    cfg = _base_config()
    _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    response = client.post(
        "/v1/analyze",
        json={
            "input": {"type": "mermaid", "content": "graph LR;A-->B"},
            "use_rag": True,
            "kb_names": [],
        },
    )

    assert response.status_code == 400
    assert "kb_names is required" in response.json()["detail"]


def test_analyze_json_accepts_rag_options(monkeypatch):
    cfg = _base_config()
    captured = _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    response = client.post(
        "/v1/analyze",
        json={
            "input": {"type": "mermaid", "content": "graph LR;A-->B"},
            "use_rag": True,
            "kb_names": ["owasp"],
            "rag_topk": 4,
            "rag_strategy": "hybrid",
            "rag_reranker": "off",
            "rag_candidates": 12,
            "rag_min_score": 0.2,
            "drawio_page": "p2",
        },
    )

    assert response.status_code == 202
    payload = captured["payload"]
    assert payload["use_rag"] is True
    assert payload["kb_names"] == ["owasp"]
    assert payload["rag_topk"] == 4
    assert payload["rag_strategy"] == "hybrid"
    assert payload["rag_reranker"] == "off"
    assert payload["rag_candidates"] == 12
    assert payload["rag_min_score"] == 0.2
    assert payload["drawio_page"] == "p2"


def test_analyze_json_accepts_context_options(monkeypatch):
    cfg = _base_config()
    captured = _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    response = client.post(
        "/v1/analyze",
        json={
            "input": {"type": "mermaid", "content": "graph LR;A-->B"},
            "contexts": [
                {
                    "filename": "business.md",
                    "content": "Business context: payment refunds.",
                }
            ],
            "prompt_token_limit": 32000,
        },
    )

    assert response.status_code == 202
    payload = captured["payload"]
    assert payload["contexts"][0]["filename"] == "business.md"
    assert payload["contexts"][0]["content"] == "Business context: payment refunds."
    assert payload["prompt_token_limit"] == 32000


def test_analyze_json_accepts_ir_input(monkeypatch):
    cfg = _base_config()
    captured = _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    response = client.post(
        "/v1/analyze",
        json={"input": {"type": "ir", "content": '{"nodes": {}, "edges": []}'}},
    )

    assert response.status_code == 202
    assert captured["payload"]["input"]["type"] == "ir"


def test_analyze_multipart_accepts_explicit_ir_type(monkeypatch):
    cfg = _base_config()
    captured = _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    response = client.post(
        "/v1/analyze",
        files={
            "file": ("system.ir.json", '{"nodes": {}, "edges": []}', "application/json")
        },
        data={"type": "ir"},
    )

    assert response.status_code == 202
    assert captured["payload"]["input"]["type"] == "ir"


def test_analyze_multipart_accepts_context_files(monkeypatch):
    cfg = _base_config()
    captured = _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    response = client.post(
        "/v1/analyze",
        files=[
            ("file", ("system.mmd", "graph LR;A-->B", "text/plain")),
            ("context_files", ("business.txt", "Payment context", "text/plain")),
            ("context_files", ("scope.md", "# Scope", "text/markdown")),
        ],
    )

    assert response.status_code == 202
    payload = captured["payload"]
    assert [ctx["filename"] for ctx in payload["contexts"]] == [
        "business.txt",
        "scope.md",
    ]
    assert all(ctx["data_b64"] for ctx in payload["contexts"])


def test_analyze_ir_rejects_when_not_allowed(monkeypatch):
    cfg = _base_config()
    cfg.engine.allowed_inputs = ["mermaid"]
    _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    response = client.post(
        "/v1/analyze",
        json={"input": {"type": "ir", "content": '{"nodes": {}, "edges": []}'}},
    )

    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"]


def test_analyze_multipart_json_autodetect_stays_threat_dragon(monkeypatch):
    cfg = _base_config()
    captured = _capture_enqueue(monkeypatch)
    app = create_app(cfg)

    client = TestClient(app)
    response = client.post(
        "/v1/analyze",
        files={
            "file": ("system.json", '{"nodes": {}, "edges": []}', "application/json")
        },
    )

    assert response.status_code == 202
    assert captured["payload"]["input"]["type"] == "threat-dragon"
