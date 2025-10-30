"""
LLM inference functions for threat analysis
"""

import json
from typing import Dict, List

from models import Graph, Threat
from constants import HINT_SYSTEM, HINT_INSTRUCTIONS, LLM_SYSTEM, LLM_INSTRUCTIONS
from .client import LLMClient
from .response_utils import safe_json_loads


def _get_language_name(lang_code: str) -> str:
    """
    Get language name from language code.
    
    Args:
        lang_code: ISO language code (ja, fr, de, etc.)
        
    Returns:
        Language name in English
    """
    lang_names = {
        "ja": "Japanese", "fr": "French", "de": "German", "es": "Spanish",
        "ko": "Korean", "zh": "Chinese", "pt": "Portuguese", "it": "Italian",
        "ru": "Russian", "ar": "Arabic", "hi": "Hindi", "th": "Thai",
        "vi": "Vietnamese", "nl": "Dutch", "sv": "Swedish", "da": "Danish",
        "no": "Norwegian", "fi": "Finnish", "pl": "Polish", "cs": "Czech",
        "hu": "Hungarian", "tr": "Turkish", "he": "Hebrew", "id": "Indonesian",
        "ms": "Malay", "tl": "Filipino", "bn": "Bengali", "ta": "Tamil",
        "te": "Telugu", "ml": "Malayalam", "kn": "Kannada", "gu": "Gujarati",
        "ur": "Urdu", "fa": "Persian", "uk": "Ukrainian", "bg": "Bulgarian",
        "hr": "Croatian", "sr": "Serbian", "sk": "Slovak", "sl": "Slovenian",
        "et": "Estonian", "lv": "Latvian", "lt": "Lithuanian", "mt": "Maltese"
    }
    return lang_names.get(lang_code, lang_code.upper())


def llm_infer_hints(graph_skeleton_json: str, api: str, model: str, aws_profile: str = None, aws_region: str = None, lang: str = "en") -> dict:
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
    llm_client = LLMClient(api=api, model=model, aws_profile=aws_profile, aws_region=aws_region)
    content = llm_client.call_llm(
        system_prompt=HINT_SYSTEM,
        user_prompt=user_prompt,
        response_format={"type": "json_object"},
        temperature=0.2,
        max_tokens=1400
    )
    return safe_json_loads(content)


def llm_infer_threats(g: Graph, api: str, model: str, aws_profile: str = None, aws_region: str = None, lang: str = "en") -> List[Threat]:
    """
    Use LLM to infer threats from graph.
    
    Args:
        g: Graph object
        api: LLM API provider
        model: Model name
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)
        lang: Language code for output (en, ja, fr, de, es, etc.)
        
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
    
    user_prompt = (
        f"System graph (JSON):\n{payload}\n\n"
        f"{lang_instruction}Perform threat analysis following the instructions below.\n"
        f"{LLM_INSTRUCTIONS}"
    )
    
    # Use LLMClient for better handling
    llm_client = LLMClient(api=api, model=model, aws_profile=aws_profile, aws_region=aws_region)
    content = llm_client.call_llm(
        system_prompt=LLM_SYSTEM,
        user_prompt=user_prompt,
        response_format={"type": "json_object"},
        temperature=0.2,
        max_tokens=2500,  # Increased from 1600 to reduce truncation
    )
    data = safe_json_loads(content)

    threats_out: List[Threat] = []
    threat_list = data.get("threats", [])
    
    # Limit to maximum 12 threats as instructed to LLM
    if len(threat_list) > 12:
        threat_list = threat_list[:12]
    
    for index, t in enumerate(threat_list):
        # Don't assign ID here - will be assigned after filtering/sorting
        
        severity = str(t.get("severity","Medium"))
        score = float(t.get("score", 4))
        ev = t.get("evidence") or {}
        ev_nodes = [str(x) for x in (ev.get("nodes") or [])]
        ev_edges = [str(x) for x in (ev.get("edges") or [])]
        conf = t.get("confidence", None)
        if isinstance(conf, (int, float)):
            conf = float(conf)
        else:
            conf = None
        threats_out.append(Threat(
            id="",  # Empty ID - will be assigned later
            title=str(t.get("title") or "Untitled"),
            stride=[str(s) for s in (t.get("stride") or [])],
            severity=severity,
            score=score,
            affected=[str(a) for a in (t.get("affected") or [])],
            why=str(t.get("why") or ""),
            references=[str(r) for r in (t.get("references") or [])],
            evidence_nodes=ev_nodes,
            evidence_edges=ev_edges,
            confidence=conf
        ))
    if not threats_out:
        raise RuntimeError("LLM returned no threats")
    return threats_out