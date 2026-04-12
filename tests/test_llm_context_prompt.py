import pytest

import threat_thinker.llm.inference as inference
from threat_thinker.models import Graph, Node


def test_llm_infer_threats_includes_business_context_and_rag(monkeypatch):
    captured = {}

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        def call_llm(self, *, system_prompt, user_prompt, **kwargs):
            captured["user_prompt"] = user_prompt
            return '{"threats": [{"title": "Context threat", "severity": "High"}]}'

    monkeypatch.setattr(inference, "LLMClient", _Client)

    graph = Graph(nodes={"api": Node(id="api", label="Menu API")}, edges=[])
    threats = inference.llm_infer_threats(
        graph,
        "openai",
        "gpt-4.1",
        business_context="Business context documents:\nAllergy data is safety-critical.",
        rag_context="Retrieved ASVS guidance.",
        rag_candidates=[
            {
                "chunk_id": "kb-0001",
                "kb": "secure",
                "source": "asvs.md",
            }
        ],
        prompt_token_limit=60000,
    )

    prompt = captured["user_prompt"]
    assert threats[0].title == "Context threat"
    assert prompt.index("System graph") < prompt.index("Business context documents")
    assert prompt.index("Business context documents") < prompt.index(
        "Retrieved knowledge snippets"
    )
    assert "Allergy data is safety-critical." in prompt
    assert "Retrieved ASVS guidance." in prompt
    assert "include `rag_sources`" in prompt
    assert "chunk_id=kb-0001" in prompt


def test_llm_infer_threats_rejects_prompt_over_limit(monkeypatch):
    class _Client:
        def __init__(self, *args, **kwargs):
            raise AssertionError("LLMClient should not be constructed")

    monkeypatch.setattr(inference, "LLMClient", _Client)
    graph = Graph(nodes={"api": Node(id="api", label="Menu API")}, edges=[])

    with pytest.raises(RuntimeError, match="Prompt token budget exceeded"):
        inference.llm_infer_threats(
            graph,
            "openai",
            "gpt-4.1",
            business_context="Business context documents:\n" + ("context " * 50),
            prompt_token_limit=5,
        )


def test_llm_infer_threats_does_not_request_rag_sources_for_context_only(
    monkeypatch,
):
    captured = {}

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        def call_llm(self, *, system_prompt, user_prompt, **kwargs):
            captured["user_prompt"] = user_prompt
            return '{"threats": [{"title": "Context threat", "severity": "Medium"}]}'

    monkeypatch.setattr(inference, "LLMClient", _Client)
    graph = Graph(nodes={"api": Node(id="api", label="Menu API")}, edges=[])

    inference.llm_infer_threats(
        graph,
        "openai",
        "gpt-4.1",
        business_context="Business context documents:\nAllergy data",
        prompt_token_limit=60000,
    )

    assert "include `rag_sources`" not in captured["user_prompt"]
