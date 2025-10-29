"""
Export functionality for reports
"""

import json
from typing import Dict, List, Optional

from models import Threat, ImportMetrics


def export_json(threats: List[Threat], out_path: Optional[str], metrics: Optional[ImportMetrics] = None) -> str:
    """
    Export threats to JSON format.
    
    Args:
        threats: List of Threat objects
        out_path: Optional output file path
        metrics: Optional import metrics
        
    Returns:
        JSON string representation
    """
    data = []
    for t in threats:
        data.append({
            "id": t.id,
            "title": t.title,
            "stride": t.stride,
            "severity": t.severity,
            "score": t.score,
            "affected": t.affected,
            "why": t.why,
            "references": t.references,
            "evidence": {"nodes": t.evidence_nodes, "edges": t.evidence_edges},
            "confidence": t.confidence
        })
    obj = {
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat() + "Z",
        "count": len(data),
        "threats": data
    }
    if metrics:
        obj["import_metrics"] = {
            "total_lines": metrics.total_lines,
            "edge_candidates": metrics.edge_candidates,
            "edges_parsed": metrics.edges_parsed,
            "node_label_candidates": metrics.node_label_candidates,
            "node_labels_parsed": metrics.node_labels_parsed,
            "import_success_rate": metrics.import_success_rate
        }
    s = json.dumps(obj, ensure_ascii=False, indent=2)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(s)
    return s


def export_md(threats: List[Threat], out_path: Optional[str], metrics: Optional[ImportMetrics] = None) -> str:
    """
    Export threats to Markdown format.
    
    Args:
        threats: List of Threat objects
        out_path: Optional output file path
        metrics: Optional import metrics
        
    Returns:
        Markdown string representation
    """
    lines = []
    lines.append("# Threat Thinker Report")
    lines.append("")
    lines.append(f"Generated: {__import__('datetime').datetime.utcnow().isoformat()}Z")
    if metrics:
        lines.append("")
        lines.append(f"Import Success: {metrics.import_success_rate*100:.1f}% "
                     f"(edges {metrics.edges_parsed}/{metrics.edge_candidates}, "
                     f"labels {metrics.node_labels_parsed}/{metrics.node_label_candidates})")
    lines.append("")
    lines.append("| Severity | Title | Why | Affected | STRIDE | References | Evidence | Score |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for t in threats:
        ev = ", ".join([*t.evidence_nodes, *t.evidence_edges]).replace("|","/")
        lines.append("| {sev} | {title} | {why} | {aff} | {stride} | {refs} | {ev} | {score} |".format(
            sev=t.severity,
            title=t.title.replace("|","/"),
            why=t.why.replace("|","/"),
            aff=", ".join(t.affected).replace("|","/"),
            stride=", ".join(t.stride),
            refs=", ".join(t.references).replace("|","/"),
            ev=ev,
            score=int(t.score),
        ))
    s = "\n".join(lines)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(s)
    return s


def diff_reports(current_path: str, baseline_path: str) -> Dict:
    """
    Compare two threat reports and return differences.
    
    Args:
        current_path: Path to current report JSON
        baseline_path: Path to baseline report JSON
        
    Returns:
        Dictionary containing added and removed threats
    """
    with open(current_path, "r", encoding="utf-8") as f:
        cur = json.load(f)
    with open(baseline_path, "r", encoding="utf-8") as f:
        base = json.load(f)
    cur_ids = {t["id"] for t in cur.get("threats", [])}
    base_ids = {t["id"] for t in base.get("threats", [])}
    added = cur_ids - base_ids
    removed = base_ids - cur_ids
    return {
        "added": [t for t in cur.get("threats", []) if t["id"] in added],
        "removed": [t for t in base.get("threats", []) if t["id"] in removed],
        "count_added": len(added),
        "count_removed": len(removed)
    }