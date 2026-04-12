from pathlib import Path

from threat_thinker.models import Threat
from threat_thinker.service.analyzer import analyze_job
from threat_thinker.serve.config import EngineConfig, TimeoutConfig


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_graph_ir.json"


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
