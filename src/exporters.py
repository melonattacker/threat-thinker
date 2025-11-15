"""
Export functionality for reports
"""

import json
from typing import Dict, List, Optional

from models import Threat, ImportMetrics, Graph

# Token budget sized for multi-section narrative diff explanations.
DIFF_EXPLANATION_MAX_TOKENS = 1800

def export_json(
    threats: List[Threat],
    out_path: Optional[str],
    metrics: Optional[ImportMetrics] = None,
    graph: Optional[Graph] = None,
) -> str:
    """
    Export threats to JSON format.

    Args:
        threats: List of Threat objects
        out_path: Optional output file path
        metrics: Optional import metrics
        graph: Optional graph object containing nodes and edges

    Returns:
        JSON string representation
    """
    data = []
    for t in threats:
        data.append(
            {
                "id": t.id,
                "title": t.title,
                "stride": t.stride,
                "severity": t.severity,
                "score": t.score,
                "affected": t.affected,
                "why": t.why,
                "recommended_action": t.recommended_action,
                "references": t.references,
                "evidence": {"nodes": t.evidence_nodes, "edges": t.evidence_edges},
                "confidence": t.confidence,
            }
        )
    obj = {
        "generated_at": __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat()
        + "Z",
        "count": len(data),
        "threats": data,
    }
    if metrics:
        obj["import_metrics"] = {
            "total_lines": metrics.total_lines,
            "edge_candidates": metrics.edge_candidates,
            "edges_parsed": metrics.edges_parsed,
            "node_label_candidates": metrics.node_label_candidates,
            "node_labels_parsed": metrics.node_labels_parsed,
            "import_success_rate": metrics.import_success_rate,
        }
    if graph:
        obj["graph"] = {
            "nodes": [
                {
                    "id": node.id,
                    "label": node.label,
                    "zone": node.zone,
                    "type": node.type,
                    "data": node.data,
                    "auth": node.auth,
                    "notes": node.notes,
                }
                for node in graph.nodes.values()
            ],
            "edges": [
                {
                    "src": edge.src,
                    "dst": edge.dst,
                    "label": edge.label,
                    "protocol": edge.protocol,
                    "data": edge.data,
                }
                for edge in graph.edges
            ],
        }
    s = json.dumps(obj, ensure_ascii=False, indent=2)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(s)
    return s


def export_md(threats: List[Threat], output_file: str = None) -> str:
    """
    Export threats to Markdown format
    """
    md_content = "# Threat Analysis Report\n\n"

    if not threats:
        md_content += "No threats identified.\n"
        return md_content

    # Threat Summary Table
    md_content += "## Threat Summary\n\n"
    md_content += "| ID | Threat | Severity | Score |\n"
    md_content += "|----|---------|---------|-------|\n"

    for threat in threats:
        md_content += f"| {threat.id} | {threat.title} | {threat.severity} | {threat.score:.1f} |\n"

    # Threat Details
    md_content += "\n## Threat Details\n\n"

    for threat in threats:
        md_content += f"### {threat.id}: {threat.title}\n\n"
        md_content += f"**Severity:** {threat.severity}\n\n"
        md_content += f"**Score:** {threat.score:.1f}\n\n"
        md_content += f"**STRIDE:** {', '.join(threat.stride)}\n\n"
        md_content += f"**Affected Components:** {', '.join(threat.affected)}\n\n"
        md_content += f"**Why:** {threat.why}\n\n"

        if threat.references:
            md_content += f"**References:** {', '.join(threat.references)}\n\n"

        recommended_action = getattr(threat, "recommended_action", "Not specified")
        md_content += f"**Recommended Actions:**\n\n{recommended_action}\n\n"
        md_content += "---\n\n"

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Markdown report saved to {output_file}")

    return md_content


def diff_reports(
    after_path: str,
    before_path: str,
    api: str = "openai",
    model: str = "gpt-4o-mini",
    aws_profile: str = None,
    aws_region: str = None,
    lang: str = "en",
) -> Dict:
    """
    Compare two threat reports and return differences with LLM-generated explanation.

    Args:
        after_path: Path to after report JSON
        before_path: Path to before report JSON
        api: LLM API provider
        model: Model name
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)
        lang: Language code for output

    Returns:
        Dictionary containing graph differences, threat differences, and LLM explanation
    """
    with open(after_path, "r", encoding="utf-8") as f:
        after_data = json.load(f)
    with open(before_path, "r", encoding="utf-8") as f:
        before_data = json.load(f)

    # Extract threats
    after_threats = after_data.get("threats", [])
    before_threats = before_data.get("threats", [])

    # Calculate threat differences
    after_ids = {t["id"] for t in after_threats}
    before_ids = {t["id"] for t in before_threats}
    added_threat_ids = after_ids - before_ids
    removed_threat_ids = before_ids - after_ids

    added_threats = [t for t in after_threats if t["id"] in added_threat_ids]
    removed_threats = [t for t in before_threats if t["id"] in removed_threat_ids]

    # Extract graph data
    after_graph = after_data.get("graph", {"nodes": [], "edges": []})
    before_graph = before_data.get("graph", {"nodes": [], "edges": []})

    # Calculate graph differences
    after_node_ids = {n["id"] for n in after_graph.get("nodes", [])}
    before_node_ids = {n["id"] for n in before_graph.get("nodes", [])}
    added_node_ids = after_node_ids - before_node_ids
    removed_node_ids = before_node_ids - after_node_ids

    added_nodes = [n for n in after_graph.get("nodes", []) if n["id"] in added_node_ids]
    removed_nodes = [
        n for n in before_graph.get("nodes", []) if n["id"] in removed_node_ids
    ]

    # For edges, create a unique identifier from src->dst->label
    def edge_key(edge):
        return f"{edge['src']}->{edge['dst']}:{edge.get('label', '')}"

    after_edge_keys = {edge_key(e) for e in after_graph.get("edges", [])}
    before_edge_keys = {edge_key(e) for e in before_graph.get("edges", [])}
    added_edge_keys = after_edge_keys - before_edge_keys
    removed_edge_keys = before_edge_keys - after_edge_keys

    added_edges = [
        e for e in after_graph.get("edges", []) if edge_key(e) in added_edge_keys
    ]
    removed_edges = [
        e for e in before_graph.get("edges", []) if edge_key(e) in removed_edge_keys
    ]

    # Generate LLM explanation
    from llm.inference import _get_language_name
    from llm.client import LLMClient

    # Create summary for LLM
    diff_summary = {
        "graph_changes": {
            "nodes_added": len(added_nodes),
            "nodes_removed": len(removed_nodes),
            "edges_added": len(added_edges),
            "edges_removed": len(removed_edges),
            "added_nodes": [
                {"id": n["id"], "label": n["label"], "type": n.get("type", "")}
                for n in added_nodes
            ],
            "removed_nodes": [
                {"id": n["id"], "label": n["label"], "type": n.get("type", "")}
                for n in removed_nodes
            ],
            "added_edges": [
                {"src": e["src"], "dst": e["dst"], "label": e.get("label", "")}
                for e in added_edges
            ],
            "removed_edges": [
                {"src": e["src"], "dst": e["dst"], "label": e.get("label", "")}
                for e in removed_edges
            ],
        },
        "threat_changes": {
            "threats_added": len(added_threats),
            "threats_removed": len(removed_threats),
            "added_threats": [
                {"id": t["id"], "title": t["title"], "severity": t["severity"]}
                for t in added_threats
            ],
            "removed_threats": [
                {"id": t["id"], "title": t["title"], "severity": t["severity"]}
                for t in removed_threats
            ],
        },
    }

    # Language instruction
    if lang == "en":
        lang_instruction = ""
    else:
        lang_name = _get_language_name(lang)
        lang_instruction = f"Please respond in {lang_name}. "

    system_prompt = """You are a cybersecurity expert analyzing changes between two system architecture diagrams and their threat models. Your task is to provide a clear, comprehensive explanation of the differences and their security implications."""

    user_prompt = f"""Analyze the following changes between two system architecture diagrams and their threat models:

CHANGES SUMMARY:
{json.dumps(diff_summary, ensure_ascii=False, indent=2)}

{lang_instruction}Please provide a structured analysis including:

1. **Graph Changes Summary**: Summarize what nodes and edges were added/removed
2. **Threat Changes Summary**: Summarize what threats were added/removed  
3. **Security Impact Analysis**: Analyze the security implications of these changes
4. **Risk Assessment**: Assess whether the changes increase or decrease overall security risk
5. **Recommendations**: Provide recommendations based on the changes

Format your response as a clear, professional analysis. Focus on the security implications and practical impact of the changes."""

    try:
        llm_client = LLMClient(
            api=api, model=model, aws_profile=aws_profile, aws_region=aws_region
        )
        explanation = llm_client.call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.3,
            max_tokens=DIFF_EXPLANATION_MAX_TOKENS,
        )
    except Exception as e:
        explanation = f"Error generating LLM explanation: {str(e)}"

    return {
        "graph_changes": {
            "nodes_added": added_nodes,
            "nodes_removed": removed_nodes,
            "edges_added": added_edges,
            "edges_removed": removed_edges,
            "count_nodes_added": len(added_nodes),
            "count_nodes_removed": len(removed_nodes),
            "count_edges_added": len(added_edges),
            "count_edges_removed": len(removed_edges),
        },
        "threat_changes": {
            "added": added_threats,
            "removed": removed_threats,
            "count_added": len(added_threats),
            "count_removed": len(removed_threats),
        },
        "explanation": explanation,
        "before_file": before_path,
        "after_file": after_path,
        "generated_at": __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat()
        + "Z",
    }


def export_diff_md(diff_data: Dict, out_path: Optional[str] = None) -> str:
    """
    Export diff data to Markdown format.

    Args:
        diff_data: Diff data dictionary from diff_reports
        out_path: Optional output file path

    Returns:
        Markdown string representation
    """
    lines = []
    lines.append("# System Architecture and Threat Model Diff Report")
    lines.append("")
    lines.append(f"**Generated:** {diff_data.get('generated_at', '')}")
    lines.append("")
    lines.append(f"**Before:** {diff_data.get('before_file', '')}")
    lines.append("")
    lines.append(f"**After:** {diff_data.get('after_file', '')}")
    lines.append("")

    # Graph changes summary
    graph_changes = diff_data.get("graph_changes", {})
    lines.append("## Graph Changes Summary")
    lines.append("")
    lines.append(f"- **Nodes Added:** {graph_changes.get('count_nodes_added', 0)}")
    lines.append(f"- **Nodes Removed:** {graph_changes.get('count_nodes_removed', 0)}")
    lines.append(f"- **Edges Added:** {graph_changes.get('count_edges_added', 0)}")
    lines.append(f"- **Edges Removed:** {graph_changes.get('count_edges_removed', 0)}")
    lines.append("")

    # Threat changes summary
    threat_changes = diff_data.get("threat_changes", {})
    lines.append("## Threat Changes Summary")
    lines.append("")
    lines.append(f"- **Threats Added:** {threat_changes.get('count_added', 0)}")
    lines.append(f"- **Threats Removed:** {threat_changes.get('count_removed', 0)}")
    lines.append("")

    # LLM explanation
    explanation = diff_data.get("explanation", "")
    if explanation:
        lines.append("## Analysis")
        lines.append("")
        lines.append(explanation)
        lines.append("")

    # Detailed changes
    if graph_changes.get("nodes_added"):
        lines.append("## Added Nodes")
        lines.append("")
        for node in graph_changes["nodes_added"]:
            lines.append(
                f"- **{node['id']}** ({node.get('type', '')}) - {node['label']}"
            )
        lines.append("")

    if graph_changes.get("nodes_removed"):
        lines.append("## Removed Nodes")
        lines.append("")
        for node in graph_changes["nodes_removed"]:
            lines.append(
                f"- **{node['id']}** ({node.get('type', '')}) - {node['label']}"
            )
        lines.append("")

    if graph_changes.get("edges_added"):
        lines.append("## Added Edges")
        lines.append("")
        for edge in graph_changes["edges_added"]:
            label = f" ({edge['label']})" if edge.get("label") else ""
            lines.append(f"- **{edge['src']}** → **{edge['dst']}**{label}")
        lines.append("")

    if graph_changes.get("edges_removed"):
        lines.append("## Removed Edges")
        lines.append("")
        for edge in graph_changes["edges_removed"]:
            label = f" ({edge['label']})" if edge.get("label") else ""
            lines.append(f"- **{edge['src']}** → **{edge['dst']}**{label}")
        lines.append("")

    if threat_changes.get("added"):
        lines.append("## Added Threats Summary")
        lines.append("")
        lines.append("| ID | Severity | Title |")
        lines.append("|---|---|---|")
        for threat in threat_changes["added"]:
            lines.append(
                f"| {threat['id']} | {threat['severity']} | {threat['title'].replace('|', '/')} |"
            )
        lines.append("")

        lines.append("### Added Threat Details")
        lines.append("")
        for threat in threat_changes["added"]:
            lines.append(f"#### {threat['id']}: {threat['title']}")
            lines.append("")
            lines.append(f"**Severity:** {threat['severity']}")
            lines.append("")
            if threat.get("why"):
                lines.append(f"**Why:** {threat['why']}")
                lines.append("")
            recommended_action = threat.get("recommended_action", "Not specified")
            lines.append("**Recommended Actions:**")
            lines.append("")
            lines.append(recommended_action)
            lines.append("")
            lines.append("---")
            lines.append("")

    if threat_changes.get("removed"):
        lines.append("## Removed Threats Summary")
        lines.append("")
        lines.append("| ID | Severity | Title |")
        lines.append("|---|---|---|")
        for threat in threat_changes["removed"]:
            lines.append(
                f"| {threat['id']} | {threat['severity']} | {threat['title'].replace('|', '/')} |"
            )
        lines.append("")

        lines.append("### Removed Threat Details")
        lines.append("")
        for threat in threat_changes["removed"]:
            lines.append(f"#### {threat['id']}: {threat['title']}")
            lines.append("")
            lines.append(f"**Severity:** {threat['severity']}")
            lines.append("")
            if threat.get("why"):
                lines.append(f"**Why:** {threat['why']}")
                lines.append("")
            recommended_action = threat.get("recommended_action", "Not specified")
            lines.append("**Recommended Actions:**")
            lines.append("")
            lines.append(recommended_action)
            lines.append("")
            lines.append("---")
            lines.append("")

    s = "\n".join(lines)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(s)
    return s
