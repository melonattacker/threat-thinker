"""
Threat analysis functionality
"""

import json
from dataclasses import asdict
from typing import List, Optional

from models import Graph, Threat


def graph_to_prompt(g: Graph) -> str:
    """
    Convert graph to JSON string for LLM prompts.

    Args:
        g: Graph object

    Returns:
        JSON string representation of the graph
    """
    nodes = [asdict(n) for n in g.nodes.values()]
    edges = [asdict(e) for e in g.edges]
    # help LLM with available IDs for evidence
    return json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False, indent=2)


def denoise_threats(
    threats: List[Threat],
    require_asvs: bool = True,
    min_confidence: float = 0.0,
    topn: Optional[int] = None,
) -> List[Threat]:
    """
    Filter and denoise threats based on various criteria.

    Args:
        threats: List of Threat objects
        require_asvs: Whether to require ASVS references
        min_confidence: Minimum confidence threshold
        topn: Maximum number of threats to return

    Returns:
        Filtered and sorted list of threats
    """
    filtered: List[Threat] = []
    for t in threats:
        if require_asvs and not any("ASVS" in r.upper() for r in t.references):
            continue
        if (t.confidence is not None) and (t.confidence < min_confidence):
            continue
        # require evidence for explainability
        if not t.evidence_nodes and not t.evidence_edges:
            continue
        # drop too generic "why"
        if len(t.why.strip()) < 6:
            continue
        filtered.append(t)

    # stable sort: score desc, then severity, then title
    filtered.sort(key=lambda x: (-x.score, x.severity, x.title))
    if topn:
        filtered = filtered[:topn]

    # merge near-duplicates by (title, evidence) signature
    sig_seen = set()
    uniq: List[Threat] = []
    for t in filtered:
        sig = (
            t.title.lower(),
            tuple(sorted(t.evidence_nodes)),
            tuple(sorted(t.evidence_edges)),
        )
        if sig in sig_seen:
            continue
        sig_seen.add(sig)
        uniq.append(t)

    # Assign sequential IDs to final threats
    for i, threat in enumerate(uniq, 1):
        threat.id = f"T{i:03d}"

    return uniq
