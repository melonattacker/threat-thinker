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
from threat_thinker.context_loader import count_tokens
from .client import LLMClient
from .response_utils import safe_json_loads

# Token budgets tuned for the JSON-heavy responses we expect from each flow.
HINT_INFERENCE_MAX_TOKENS = 4096
THREAT_INFERENCE_MAX_TOKENS = (
    10000  # Headroom for 10-12 verbose multilingual threats with evidence metadata
)
RERANK_MAX_TOKENS = 1500
DEFAULT_HOSTED_PROMPT_TOKEN_LIMIT = 60000
DEFAULT_OLLAMA_PROMPT_TOKEN_LIMIT = 12000
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
                    "rag_sources": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kb": {"type": "string"},
                                "source": {"type": "string"},
                                "chunk_id": {"type": "string"},
                                "score": {"type": ["integer", "number"]},
                            },
                            "required": ["chunk_id"],
                        },
                    },
                    "evidence": {"type": "object"},
                    "confidence": {"type": ["integer", "number", "null"]},
                },
                "required": ["title", "severity"],
            },
        }
    },
    "required": ["threats"],
}
RERANK_JSON_SCHEMA: Dict = {
    "type": "object",
    "properties": {
        "scores": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "idx": {"type": "integer"},
                    "score": {"type": ["integer", "number"]},
                },
                "required": ["idx", "score"],
            },
        }
    },
    "required": ["scores"],
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


def _validate_rerank_payload(payload: dict) -> None:
    if not isinstance(payload, dict):
        raise ValueError("Rerank payload must be a JSON object")
    scores = payload.get("scores")
    if not isinstance(scores, list):
        raise ValueError("Rerank payload missing 'scores' list")
    for item in scores:
        if not isinstance(item, dict):
            raise ValueError("Each rerank score entry must be an object")
        if "idx" not in item or "score" not in item:
            raise ValueError("Each rerank score entry requires idx and score")


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


def default_prompt_token_limit(api: str) -> int:
    if (api or "").strip().lower() == "ollama":
        return DEFAULT_OLLAMA_PROMPT_TOKEN_LIMIT
    return DEFAULT_HOSTED_PROMPT_TOKEN_LIMIT


def _validate_prompt_token_limit(
    *,
    system_prompt: str,
    user_prompt: str,
    api: str,
    model: str,
    prompt_token_limit: Optional[int],
) -> int:
    limit = (
        default_prompt_token_limit(api)
        if prompt_token_limit is None
        else prompt_token_limit
    )
    if limit <= 0:
        raise ValueError("prompt_token_limit must be a positive integer")
    total_tokens = count_tokens(f"{system_prompt}\n\n{user_prompt}", model)
    if total_tokens > limit:
        raise RuntimeError(
            "Prompt token budget exceeded: "
            f"{total_tokens} tokens estimated, limit is {limit}. "
            "Reduce --context input size or increase --prompt-token-limit."
        )
    return total_tokens


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


def llm_rerank_chunks(
    query: str,
    chunks: List[dict],
    api: str,
    model: str,
    aws_profile: str = None,
    aws_region: str = None,
    ollama_host: str = None,
    batch_size: int = 12,
) -> List[float]:
    """
    Re-rank retrieved chunks by semantic relevance to the query.
    Returns a score list aligned to the input chunk order.
    """
    if not chunks:
        return []

    llm_client = LLMClient(
        api=api,
        model=model,
        aws_profile=aws_profile,
        aws_region=aws_region,
        ollama_host=ollama_host,
    )

    out_scores = [0.0 for _ in chunks]
    for start in range(0, len(chunks), max(1, int(batch_size))):
        batch = chunks[start : start + max(1, int(batch_size))]
        lines = []
        for rel_idx, chunk in enumerate(batch):
            text = str(chunk.get("text") or "").strip().replace("\n", " ")
            if len(text) > 1200:
                text = text[:1200] + "..."
            lines.append(f"{rel_idx}: {text}")
        snippets = "\n".join(lines)
        user_prompt = (
            "Rank snippet relevance to the security analysis query.\n"
            "Return JSON with scores in range [0,1].\n"
            "Query:\n"
            f"{query}\n\n"
            "Snippets:\n"
            f"{snippets}\n\n"
            'Return format: {"scores":[{"idx":0,"score":0.0}]}'
        )

        payload = _call_llm_json_with_retry(
            lambda: llm_client.call_llm(
                system_prompt=(
                    "You are a strict relevance ranker for threat-modeling context retrieval."
                ),
                user_prompt=user_prompt,
                response_format={"type": "json_object"},
                json_schema=RERANK_JSON_SCHEMA,
                temperature=0.0,
                max_tokens=RERANK_MAX_TOKENS,
            ),
            _validate_rerank_payload,
        )

        for item in payload.get("scores", []):
            try:
                rel_idx = int(item.get("idx"))
                score = float(item.get("score"))
            except (TypeError, ValueError):
                continue
            if 0 <= rel_idx < len(batch):
                out_scores[start + rel_idx] = max(0.0, min(1.0, score))

    return out_scores


def llm_infer_threats(
    g: Graph,
    api: str,
    model: str,
    aws_profile: str = None,
    aws_region: str = None,
    ollama_host: str = None,
    lang: str = "en",
    rag_context: Optional[str] = None,
    rag_candidates: Optional[List[dict]] = None,
    business_context: Optional[str] = None,
    prompt_token_limit: Optional[int] = None,
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
        business_context: Optional full business context document text
        prompt_token_limit: Optional token limit for the assembled prompt

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

    business_context_block = ""
    if business_context:
        business_context_block = f"\n{business_context}\n"

    context_block = ""
    rag_source_instruction = ""
    if rag_context:
        candidate_lines = []
        for item in (rag_candidates or [])[:30]:
            candidate_lines.append(
                f"- chunk_id={item.get('chunk_id')} kb={item.get('kb')} source={item.get('source')}"
            )
        candidate_text = "\n".join(candidate_lines)
        context_block = (
            "\nRetrieved knowledge snippets (ground your reasoning in these when relevant):\n"
            f"{rag_context}\n"
        )
        rag_source_instruction = (
            "When retrieved snippets support a threat, include `rag_sources` using only listed chunk_id values.\n"
            'rag_sources item shape: {"kb":"...","source":"...","chunk_id":"...","score":0.0..1.0}\n'
            f"Available chunks:\n{candidate_text}\n"
        )

    user_prompt = (
        f"System graph (JSON):\n{payload}\n"
        f"{business_context_block}\n"
        f"{context_block}\n"
        f"{rag_source_instruction}\n"
        f"{lang_instruction}Perform threat analysis following the instructions below.\n"
        f"{LLM_INSTRUCTIONS}"
    )

    _validate_prompt_token_limit(
        system_prompt=LLM_SYSTEM,
        user_prompt=user_prompt,
        api=api,
        model=model,
        prompt_token_limit=prompt_token_limit,
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
        raw_sources = t.get("rag_sources") or []
        rag_sources = []
        if isinstance(raw_sources, list):
            for src in raw_sources:
                if not isinstance(src, dict):
                    continue
                chunk_id = str(src.get("chunk_id") or "").strip()
                if not chunk_id:
                    continue
                rag_sources.append(
                    {
                        "kb": str(src.get("kb") or ""),
                        "source": str(src.get("source") or ""),
                        "chunk_id": chunk_id,
                        "score": float(src.get("score") or 0.0),
                    }
                )
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
                rag_sources=rag_sources,
            )
        )
    if not threats_out:
        raise RuntimeError("LLM returned no threats")
    return threats_out
