"""
LLM client functionality
"""

import json
import os
from typing import Dict, List, Optional
from openai import OpenAI

from models import Graph, Threat
from constants import HINT_SYSTEM, HINT_INSTRUCTIONS, LLM_SYSTEM, LLM_INSTRUCTIONS


def call_llm(api: str,
             model: str,
             system_prompt: str,
             user_prompt: str,
             *,
             response_format: Optional[Dict[str, str]] = None,
             temperature: float = 0.2,
             max_tokens: int = 1600) -> str:
    """
    Call LLM API with given parameters.
    
    Args:
        api: LLM API provider (currently only "openai")
        model: Model name
        system_prompt: System prompt
        user_prompt: User prompt
        response_format: Optional response format specification
        temperature: Sampling temperature
        max_tokens: Maximum tokens in response
        
    Returns:
        String response from LLM
        
    Raises:
        NotImplementedError: If API provider is not supported
        RuntimeError: If API key is not set or response is empty
    """
    api_normalized = api.lower()
    if api_normalized != "openai":
        raise NotImplementedError(f"LLM api '{api}' is not supported yet.")

    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")

    client = OpenAI()
    kwargs = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if response_format is not None:
        kwargs["response_format"] = response_format

    resp = client.chat.completions.create(**kwargs)
    content = resp.choices[0].message.content
    if not content:
        raise RuntimeError("LLM returned empty content")
    return content


def llm_infer_hints(graph_skeleton_json: str, api: str, model: str) -> dict:
    """
    Use LLM to infer hints from graph skeleton.
    
    Args:
        graph_skeleton_json: JSON representation of graph skeleton
        api: LLM API provider
        model: Model name
        
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
    )
    return json.loads(content)


def llm_infer_threats(g: Graph, api: str, model: str) -> List[Threat]:
    """
    Use LLM to infer threats from graph.
    
    Args:
        g: Graph object
        api: LLM API provider
        model: Model name
        
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