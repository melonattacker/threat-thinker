import json
from pathlib import Path

import pytest

from threat_thinker.models import Threat
from threat_thinker.service.analyzer import AnalysisError, analyze_job
from threat_thinker.serve.config import EngineConfig, TimeoutConfig


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_graph_ir.json"


def _dfd_payload():
    return {
        "summary": "Customer order system",
        "graph": {
            "nodes": {
                "customer": {
                    "id": "customer",
                    "label": "Customer",
                    "type": "actor",
                    "zones": ["internet"],
                    "confidence": "stated",
                },
                "api": {
                    "id": "api",
                    "label": "Order API",
                    "type": "service",
                    "zones": ["app"],
                    "data": ["PII"],
                    "confidence": "implied",
                },
            },
            "edges": [
                {
                    "id": "customer-api",
                    "src": "customer",
                    "dst": "api",
                    "label": "Places orders",
                    "protocol": "HTTPS",
                    "confidence": "stated",
                }
            ],
            "zones": {
                "internet": {
                    "id": "internet",
                    "name": "Internet",
                    "confidence": "stated",
                },
                "app": {
                    "id": "app",
                    "name": "Application",
                    "confidence": "implied",
                },
            },
        },
        "assumptions": ["The API stores order data."],
        "clarifying_questions": [],
    }


def _empty_dfd_payload():
    return {
        "summary": "Insufficient detail",
        "graph": {"nodes": {}, "edges": [], "zones": {}},
        "assumptions": [],
        "clarifying_questions": ["Which users access the system?"],
    }


def _engine():
    engine = EngineConfig()
    engine.model.provider = "ollama"
    engine.model.name = "llama3.1"
    return engine


def test_analyze_job_accepts_ir_input(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def _fake_llm_infer_threats(*args, **kwargs):
        return [
            Threat(
                id="T999",
                title="Test threat",
                stride=["T"],
                severity="High",
                score=8.0,
                affected=["API"],
                why="Edge lacks validation controls",
                references=["ASVS V5.1.1"],
                recommended_action="Validate requests",
                evidence_nodes=["api"],
                evidence_edges=["user->api"],
                confidence=0.9,
            )
        ]

    monkeypatch.setattr(
        "threat_thinker.service.analyzer.llm_infer_threats", _fake_llm_infer_threats
    )

    payload = {
        "input": {
            "type": "ir",
            "content": FIXTURE_PATH.read_text(encoding="utf-8"),
            "filename": "system.ir.json",
        },
        "report_formats": ["json", "markdown"],
        "language": "en",
        "infer_hints": False,
        "require_asvs": False,
        "min_confidence": 0.0,
        "topn": 10,
        "autodetect": True,
        "use_rag": False,
        "kb_names": [],
        "rag_topk": 5,
        "rag_strategy": "hybrid",
        "rag_reranker": "off",
        "rag_candidates": 10,
        "rag_min_score": 0.0,
        "drawio_page": None,
    }

    engine = EngineConfig()
    engine.model.provider = "ollama"
    engine.model.name = "llama3.1"

    result = analyze_job(payload, engine, TimeoutConfig())

    formats = {entry.report_format for entry in result.reports}
    assert formats == {"json", "markdown"}
    assert any('"count": 1' in entry.content for entry in result.reports)


def test_analyze_job_passes_business_context_to_threat_inference(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    captured = {}

    def _fake_llm_infer_threats(*args, **kwargs):
        captured["business_context"] = kwargs.get("business_context")
        captured["prompt_token_limit"] = kwargs.get("prompt_token_limit")
        return [
            Threat(
                id="T999",
                title="Context threat",
                stride=["T"],
                severity="High",
                score=8.0,
                affected=["API"],
                why="Business context identifies safety-critical data",
                references=["ASVS V5.1.1"],
                recommended_action="Protect context-specific data",
                evidence_nodes=["api"],
                evidence_edges=[],
                confidence=0.9,
            )
        ]

    monkeypatch.setattr(
        "threat_thinker.service.analyzer.llm_infer_threats", _fake_llm_infer_threats
    )

    payload = {
        "input": {
            "type": "ir",
            "content": FIXTURE_PATH.read_text(encoding="utf-8"),
            "filename": "system.ir.json",
        },
        "report_formats": ["json"],
        "language": "en",
        "infer_hints": False,
        "require_asvs": False,
        "min_confidence": 0.0,
        "topn": 10,
        "use_rag": False,
        "contexts": [
            {
                "filename": "business.txt",
                "content": "Allergy information is safety-critical.",
            }
        ],
        "prompt_token_limit": 32000,
    }

    engine = EngineConfig()
    engine.model.provider = "ollama"
    engine.model.name = "llama3.1"

    result = analyze_job(payload, engine, TimeoutConfig())

    assert result.reports
    assert "business.txt" in captured["business_context"]
    assert "Allergy information is safety-critical." in captured["business_context"]
    assert captured["prompt_token_limit"] == 32000


def test_analyze_job_generates_dfd_from_description(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    captured = {}

    def _fake_generate_dfd(*args, **kwargs):
        captured["description"] = args[0]
        captured["prompt_token_limit"] = kwargs.get("prompt_token_limit")
        return _dfd_payload()

    def _fake_llm_infer_threats(*args, **kwargs):
        graph = args[0]
        captured["graph_source_format"] = graph.source_format
        captured["business_context"] = kwargs.get("business_context")
        return [
            Threat(
                id="T1000",
                title="Order API accepts spoofed requests",
                stride=["S"],
                severity="High",
                score=8.0,
                affected=["Order API"],
                why="The generated DFD exposes an internet-facing order API.",
                references=["ASVS V2.1.1"],
                recommended_action="Require strong customer authentication.",
                evidence_nodes=["api"],
                evidence_edges=["customer-api"],
                confidence=0.9,
            )
        ]

    monkeypatch.setattr(
        "threat_thinker.service.analyzer.llm_generate_dfd_from_description",
        _fake_generate_dfd,
    )
    monkeypatch.setattr(
        "threat_thinker.service.analyzer.llm_infer_threats",
        _fake_llm_infer_threats,
    )

    payload = {
        "input": {
            "type": "description",
            "content": "Customers use a web app to manage orders.",
        },
        "report_formats": ["json", "dfd"],
        "language": "en",
        "min_confidence": 0.0,
        "contexts": [
            {
                "filename": "business.txt",
                "content": "Order history includes customer PII.",
            }
        ],
        "prompt_token_limit": 32000,
    }

    result = analyze_job(payload, _engine(), TimeoutConfig())

    reports = {entry.report_format: entry.content for entry in result.reports}
    assert set(reports) == {"json", "dfd"}
    assert captured["description"] == "Customers use a web app to manage orders."
    assert captured["graph_source_format"] == "description"
    assert "Customers use a web app to manage orders." in captured["business_context"]
    assert "Order history includes customer PII." in captured["business_context"]
    assert json.loads(reports["dfd"])["summary"] == "Customer order system"


def test_analyze_job_empty_dfd_returns_dfd_report_without_threats(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    called = {"threats": False}

    def _fake_generate_dfd(*args, **kwargs):
        return _empty_dfd_payload()

    def _fake_llm_infer_threats(*args, **kwargs):
        called["threats"] = True
        return []

    monkeypatch.setattr(
        "threat_thinker.service.analyzer.llm_generate_dfd_from_description",
        _fake_generate_dfd,
    )
    monkeypatch.setattr(
        "threat_thinker.service.analyzer.llm_infer_threats",
        _fake_llm_infer_threats,
    )

    payload = {
        "input": {"type": "description", "content": "A drone delivery app."},
        "report_formats": ["dfd"],
        "language": "en",
    }

    result = analyze_job(payload, _engine(), TimeoutConfig())

    assert called["threats"] is False
    assert len(result.reports) == 1
    assert result.reports[0].report_format == "dfd"
    sidecar = json.loads(result.reports[0].content)
    assert sidecar["clarifying_questions"] == ["Which users access the system?"]


def test_analyze_job_empty_dfd_without_dfd_report_fails(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    monkeypatch.setattr(
        "threat_thinker.service.analyzer.llm_generate_dfd_from_description",
        lambda *args, **kwargs: _empty_dfd_payload(),
    )

    payload = {
        "input": {"type": "description", "content": "A drone delivery app."},
        "report_formats": ["json"],
        "language": "en",
    }

    with pytest.raises(AnalysisError, match="Which users access the system"):
        analyze_job(payload, _engine(), TimeoutConfig())
