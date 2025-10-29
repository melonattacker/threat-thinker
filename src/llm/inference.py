"""
LLM inference functions for threat analysis
"""

import json
from typing import Dict, List

from models import Graph, Threat
from constants import HINT_SYSTEM, HINT_INSTRUCTIONS, LLM_SYSTEM, LLM_INSTRUCTIONS
from .client import call_llm


def llm_infer_hints(graph_skeleton_json: str, api: str, model: str, aws_profile: str = None, aws_region: str = None) -> dict:
    """
    Use LLM to infer hints from graph skeleton.
    
    Args:
        graph_skeleton_json: JSON representation of graph skeleton
        api: LLM API provider
        model: Model name
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)
        
    Returns:
        Dictionary of inferred hints
    """
    user_prompt = (
        "Graph skeleton (nodes with id/label; edges with from/to/label):\n"
        f"{graph_skeleton_json}\n\n"
        "Infer attributes strictly following the output schema.\n"
        f"{HINT_INSTRUCTIONS}"
    )
    content = call_llm(
        api=api,
        model=model,
        system_prompt=HINT_SYSTEM,
        user_prompt=user_prompt,
        response_format={"type": "json_object"},
        temperature=0.2,
        max_tokens=1400,
        aws_profile=aws_profile,
        aws_region=aws_region,
    )
    return json.loads(content)


def llm_infer_threats(g: Graph, api: str, model: str, aws_profile: str = None, aws_region: str = None) -> List[Threat]:
    """
    Use LLM to infer threats from graph.
    
    Args:
        g: Graph object
        api: LLM API provider
        model: Model name
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)
        
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
    
    user_prompt = (
        "System graph (JSON):\n"
        f"{payload}\n\n"
        f"{LLM_INSTRUCTIONS}"
    )
    content = call_llm(
        api=api,
        model=model,
        system_prompt=LLM_SYSTEM,
        user_prompt=user_prompt,
        response_format={"type": "json_object"},
        temperature=0.2,
        max_tokens=1600,
        aws_profile=aws_profile,
        aws_region=aws_region,
    )
    data = json.loads(content)

    threats_out: List[Threat] = []
    for t in data.get("threats", []):
        tid = (str(t.get("id") or "").strip())[:64]
        if not tid:
            import hashlib
            tid = hashlib.sha1(str(t.get("title","")).encode("utf-8")).hexdigest()[:8]
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
            id=tid,
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
    # de-dup by stable id first
    uniq = {t.id: t for t in threats_out}
    return list(uniq.values())