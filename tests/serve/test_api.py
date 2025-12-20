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
