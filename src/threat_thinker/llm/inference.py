"""
LLM inference functions for threat analysis
"""

import json
from typing import Callable, Dict, List, Optional

from threat_thinker.models import Graph, Threat
from threat_thinker.constants import (
    HINT_SYSTEM,
    HINT_INSTRUCTIONS,
    LLM_SYSTEM,
    LLM_INSTRUCTIONS,
)
from .client import LLMClient
from .response_utils import safe_json_loads

# Token budgets tuned for the JSON-heavy responses we expect from each flow.
HINT_INFERENCE_MAX_TOKENS = 4096
THREAT_INFERENCE_MAX_TOKENS = (
    4096  # Enough headroom for 12 verbose threats plus metadata
)
HINT_JSON_SCHEMA: Dict = {
    "type": "object",
    "properties": {
        "nodes": {"type": "object"},
        "edges": {"type": "array", "items": {"type": "object"}},
        "policies": {"type": "object"},
    },
}
THREAT_JSON_SCHEMA: Dict = {
    "type": "object",
    "properties": {
        "threats": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "stride": {"type": "array"},
                    "severity": {"type": "string"},
                    "score": {"type": ["integer", "number"]},
                    "affected": {"type": "array"},
                    "why": {"type": "string"},
                    "recommended_action": {"type": "string"},
                    "references": {"type": "array"},
                    "evidence": {"type": "object"},
                    "confidence": {"type": ["integer", "number", "null"]},
                },
                "required": ["title", "severity"],
            },
        }
    },
    "required": ["threats"],
}


def _validate_hints_payload(payload: dict) -> None:
    if not isinstance(payload, dict):
        raise ValueError("Hints payload must be a JSON object")
    nodes = payload.get("nodes")
    if nodes is not None and not isinstance(nodes, dict):
        raise ValueError("Hints payload 'nodes' must be an object when present")
    edges = payload.get("edges")
    if edges is not None and not isinstance(edges, list):
        raise ValueError("'edges' must be a list when present")
    policies = payload.get("policies")
    if policies is not None and not isinstance(policies, dict):
        raise ValueError("'policies' must be an object when present")


def _validate_threats_payload(payload: dict) -> None:
    if not isinstance(payload, dict):
        raise ValueError("Threat payload must be a JSON object")
    threats = payload.get("threats")
    if not isinstance(threats, list):
        raise ValueError("Threat payload missing 'threats' list")
    for threat in threats:
        if not isinstance(threat, dict):
            raise ValueError("Each threat entry must be an object")
        if not threat.get("title"):
            raise ValueError("Each threat must include a title")


def _call_llm_json_with_retry(
    call_fn: Callable[[], str],
    validate_fn: Callable[[dict], None],
    attempts: int = 2,
) -> dict:
    errors: List[Exception] = []
    for idx in range(attempts):
        raw = call_fn()
        try:
            data = safe_json_loads(raw)
            validate_fn(data)
            return data
        except Exception as exc:  # json decode or validation
            errors.append(exc)
            if idx == attempts - 1:
                raise RuntimeError(
                    f"LLM returned invalid JSON after {attempts} attempt(s): {exc}"
                ) from exc
    raise RuntimeError(f"LLM returned invalid JSON: {errors!r}")


def _get_language_name(lang_code: str) -> str:
    """
    Get language name from language code.

    Args:
        lang_code: ISO language code (ja, fr, de, etc.)

    Returns:
        Language name in English
    """
    lang_names = {
        "ja": "Japanese",
        "fr": "French",
        "de": "German",
        "es": "Spanish",
        "ko": "Korean",
        "zh": "Chinese",
        "pt": "Portuguese",
        "it": "Italian",
        "ru": "Russian",
        "ar": "Arabic",
        "hi": "Hindi",
        "th": "Thai",
        "vi": "Vietnamese",
        "nl": "Dutch",
        "sv": "Swedish",
        "da": "Danish",
        "no": "Norwegian",
        "fi": "Finnish",
        "pl": "Polish",
        "cs": "Czech",
        "hu": "Hungarian",
        "tr": "Turkish",
        "he": "Hebrew",
        "id": "Indonesian",
        "ms": "Malay",
        "tl": "Filipino",
        "bn": "Bengali",
        "ta": "Tamil",
        "te": "Telugu",
        "ml": "Malayalam",
        "kn": "Kannada",
        "gu": "Gujarati",
        "ur": "Urdu",
        "fa": "Persian",
        "uk": "Ukrainian",
        "bg": "Bulgarian",
        "hr": "Croatian",
        "sr": "Serbian",
        "sk": "Slovak",
        "sl": "Slovenian",
        "et": "Estonian",
        "lv": "Latvian",
        "lt": "Lithuanian",
        "mt": "Maltese",
    }
    return lang_names.get(lang_code, lang_code.upper())


def llm_infer_hints(
    graph_skeleton_json: str,
    api: str,
    model: str,
    aws_profile: str = None,
    aws_region: str = None,
    ollama_host: str = None,
    lang: str = "en",
) -> dict:
    """
    Use LLM to infer hints from graph skeleton.

    Args:
        graph_skeleton_json: JSON representation of graph skeleton
        api: LLM API provider
        model: Model name
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)
        lang: Language code for output (en, ja, fr, de, es, etc.)

    Returns:
        Dictionary of inferred hints
    """
    # Language instruction - simple and universal approach
    if lang == "en":
        lang_instruction = ""
    else:
        lang_name = _get_language_name(lang)
        lang_instruction = f"Please respond in {lang_name}. "

    user_prompt = (
        "Graph skeleton (nodes with id/label; edges with from/to/label):\n"
        f"{graph_skeleton_json}\n\n"
        f"{lang_instruction}Infer attributes strictly following the output schema.\n"
        f"{HINT_INSTRUCTIONS}"
    )

    # Use LLMClient for better handling
    llm_client = LLMClient(
        api=api,
        model=model,
        aws_profile=aws_profile,
        aws_region=aws_region,
        ollama_host=ollama_host,
    )
    data = _call_llm_json_with_retry(
        lambda: llm_client.call_llm(
            system_prompt=HINT_SYSTEM,
            user_prompt=user_prompt,
            response_format={"type": "json_object"},
            json_schema=HINT_JSON_SCHEMA,
            temperature=0.15,
            max_tokens=HINT_INFERENCE_MAX_TOKENS,
        ),
        _validate_hints_payload,
    )
    return data


def llm_infer_threats(
    g: Graph,
    api: str,
    model: str,
    aws_profile: str = None,
    aws_region: str = None,
    ollama_host: str = None,
    lang: str = "en",
    rag_context: Optional[str] = None,
) -> List[Threat]:
    """
    Use LLM to infer threats from graph.

    Args:
        g: Graph object
        api: LLM API provider
        model: Model name
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)
        lang: Language code for output (en, ja, fr, de, es, etc.)
        rag_context: Optional retrieved knowledge to ground the analysis

    Returns:
        List of Threat objects

    Raises:
        RuntimeError: If no threats are returned
    """
    # Import here to avoid circular import
    from dataclasses import asdict

    # Convert graph to prompt format (inline to avoid circular import)
    nodes = [asdict(n) for n in g.nodes.values()]
    edges = [asdict(e) for e in g.edges]
    payload = json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False, indent=2)

    # Simple language instruction approach
    if lang == "en":
        lang_instruction = ""
    else:
        lang_name = _get_language_name(lang)
        lang_instruction = f"Please write threat titles, reasons, and descriptions in {lang_name}, but keep field names (id, title, why, etc.) in English. "

    context_block = ""
    if rag_context:
        context_block = (
            "\nRetrieved knowledge snippets (ground your reasoning in these when relevant):\n"
            f"{rag_context}\n"
        )

    user_prompt = (
        f"System graph (JSON):\n{payload}\n"
        f"{context_block}\n"
        f"{lang_instruction}Perform threat analysis following the instructions below.\n"
        f"{LLM_INSTRUCTIONS}"
    )

    # Use LLMClient for better handling
    llm_client = LLMClient(
        api=api,
        model=model,
        aws_profile=aws_profile,
        aws_region=aws_region,
        ollama_host=ollama_host,
    )
    data = _call_llm_json_with_retry(
        lambda: llm_client.call_llm(
            system_prompt=LLM_SYSTEM,
            user_prompt=user_prompt,
            response_format={"type": "json_object"},
            json_schema=THREAT_JSON_SCHEMA,
            temperature=0.15,
            max_tokens=THREAT_INFERENCE_MAX_TOKENS,
        ),
        _validate_threats_payload,
    )

    threats_out: List[Threat] = []
    threat_list = data.get("threats", [])

    # Limit to maximum 12 threats as instructed to LLM
    if len(threat_list) > 12:
        threat_list = threat_list[:12]

    for index, t in enumerate(threat_list):
        # Don't assign ID here - will be assigned after filtering/sorting

        severity = str(t.get("severity", "Medium"))
        score = float(t.get("score", 4))
        ev = t.get("evidence") or {}
        ev_nodes = [str(x) for x in (ev.get("nodes") or [])]
        ev_edges = [str(x) for x in (ev.get("edges") or [])]
        conf = t.get("confidence", None)
        if isinstance(conf, (int, float)):
            conf = float(conf)
        else:
            conf = None
        threats_out.append(
            Threat(
                id="",  # Empty ID - will be assigned later
                title=str(t.get("title") or "Untitled"),
                stride=[str(s) for s in (t.get("stride") or [])],
                severity=severity,
                score=score,
                affected=[str(a) for a in (t.get("affected") or [])],
                why=str(t.get("why") or ""),
                recommended_action=str(
                    t.get("recommended_action") or "No specific action provided"
                ),
                references=[str(r) for r in (t.get("references") or [])],
                evidence_nodes=ev_nodes,
                evidence_edges=ev_edges,
                confidence=conf,
            )
        )
    if not threats_out:
        raise RuntimeError("LLM returned no threats")
    return threats_out
