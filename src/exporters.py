"""
Export functionality for reports
"""

import copy
import json
from html import escape
from typing import Any, Dict, List, Optional, Tuple

from models import Threat, ImportMetrics, Graph, Node, Edge

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

    return md_content


def _safe(text: Optional[str]) -> str:
    return escape(text or "")


def _edge_lookup(
    edges: List[Edge],
) -> Tuple[Dict[Tuple[str, str, Optional[str]], Edge], Dict[str, Edge]]:
    lookup: Dict[Tuple[str, str, Optional[str]], Edge] = {}
    id_lookup: Dict[str, Edge] = {}
    for edge in edges:
        key = (edge.src, edge.dst, edge.label or None)
        lookup[key] = edge
        # Fallback to match edges without label even if one exists
        lookup.setdefault((edge.src, edge.dst, None), edge)
        if edge.id:
            id_lookup[edge.id] = edge
    return lookup, id_lookup


def export_html(
    threats: List[Threat],
    output_file: Optional[str] = None,
    graph: Optional[Graph] = None,
) -> str:
    """
    Export threats to HTML format with diagram mapping details.
    Mirrors Markdown content and adds mapping between threats and architecture nodes/edges.
    """

    if not threats:
        content = """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <title>Threat Analysis Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; color: #0f172a; }
    .empty { font-style: italic; color: #475569; }
  </style>
</head>
<body>
  <h1>Threat Analysis Report</h1>
  <p class=\"empty\">No threats identified.</p>
</body>
</html>"""
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
        return content

    nodes = graph.nodes if graph else {}
    edges = graph.edges if graph else []
    edge_lookup, edge_id_lookup = _edge_lookup(edges)

    def format_text(text: str) -> str:
        return _safe(text).replace("\n", "<br>")

    def resolve_node(node_id: str) -> str:
        node: Optional[Node] = nodes.get(node_id)
        if node:
            extra = []
            if node.zone:
                extra.append(f"zone={_safe(node.zone)}")
            if node.type:
                extra.append(f"type={_safe(node.type)}")
            suffix = f" ({', '.join(extra)})" if extra else ""
            return f"{_safe(node.label)} [{_safe(node_id)}]{suffix}"
        return _safe(node_id)

    def resolve_edge(edge_id: str) -> str:
        if "->" not in edge_id:
            edge = edge_id_lookup.get(edge_id)
            if edge:
                src_label = nodes.get(edge.src).label if nodes.get(edge.src) else edge.src
                dst_label = nodes.get(edge.dst).label if nodes.get(edge.dst) else edge.dst
                label_suffix = f" : {edge.label}" if edge.label else ""
                protocol = f" ({edge.protocol})" if edge.protocol else ""
                return _safe(
                    f"{src_label} [{edge.src}] -> {dst_label} [{edge.dst}]{label_suffix}{protocol}"
                )
            return _safe(edge_id)
        src_part, rest = edge_id.split("->", 1)
        if ":" in rest:
            dst_part, label_part = rest.split(":", 1)
            label_part = label_part.strip()
        else:
            dst_part, label_part = rest, None
        src = src_part.strip()
        dst = dst_part.strip()
        edge = edge_lookup.get((src, dst, label_part or None))
        if edge:
            src_label = nodes.get(edge.src).label if nodes.get(edge.src) else edge.src
            dst_label = nodes.get(edge.dst).label if nodes.get(edge.dst) else edge.dst
            label = edge.label or label_part
            protocol = f" ({edge.protocol})" if edge.protocol else ""
            label_suffix = f" : {label}" if label else ""
            return _safe(
                f"{src_label} [{edge.src}] -> {dst_label} [{edge.dst}]{label_suffix}{protocol}"
            )
        return _safe(edge_id)

    # Build architecture mapping: nodes/edges to threat IDs
    node_threats: Dict[str, List[str]] = {nid: [] for nid in nodes}
    edge_threats: Dict[Tuple[str, str, Optional[str]], List[str]] = {
        k: [] for k in edge_lookup
    }
    # include id-based entries so evidence by id can still be mapped
    for edge in edges:
        key = (edge.src, edge.dst, edge.label or None)
        edge_threats.setdefault(key, [])
    for t in threats:
        for nid in t.evidence_nodes:
            if nid in node_threats:
                node_threats[nid].append(t.id)
        for e_ref in t.evidence_edges:
            if "->" in e_ref:
                src_part, rest = e_ref.split("->", 1)
                if ":" in rest:
                    dst_part, label_part = rest.split(":", 1)
                    key = (src_part.strip(), dst_part.strip(), label_part.strip())
                else:
                    key = (src_part.strip(), rest.strip(), None)
                edge = edge_lookup.get(key) or edge_lookup.get((key[0], key[1], None))
            else:
                edge = edge_id_lookup.get(e_ref)

            if edge:
                canonical_key = (edge.src, edge.dst, edge.label)
                edge_threats.setdefault(canonical_key, []).append(t.id)

    html_parts: List[str] = []
    html_parts.append("<!DOCTYPE html>")
    html_parts.append('<html lang="en">')
    html_parts.append("<head>")
    html_parts.append('  <meta charset="UTF-8" />')
    html_parts.append("  <title>Threat Analysis Report</title>")
    html_parts.append("  <style>")
    html_parts.append(
        "    body { font-family: Arial, sans-serif; margin: 32px; color: #0f172a; }"
    )
    html_parts.append("    h1 { font-size: 28px; margin-bottom: 8px; }")
    html_parts.append(
        "    h2 { margin-top: 32px; border-bottom: 2px solid #e2e8f0; padding-bottom: 4px; }"
    )
    html_parts.append("    h3 { margin-top: 24px; color: #0f172a; }")
    html_parts.append(
        "    table { border-collapse: collapse; width: 100%; margin-top: 12px; }"
    )
    html_parts.append(
        "    th, td { border: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; }"
    )
    html_parts.append("    th { background: #f8fafc; }")
    html_parts.append(
        "    .severity { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }"
    )
    html_parts.append("    .sev-High { background: #fee2e2; color: #b91c1c; }")
    html_parts.append("    .sev-Medium { background: #fef9c3; color: #b45309; }")
    html_parts.append("    .sev-Low { background: #dcfce7; color: #166534; }")
    html_parts.append("    .meta { color: #475569; font-size: 14px; }")
    html_parts.append("    .section { margin-top: 24px; }")
    html_parts.append("    .mapping-list { list-style: disc; margin-left: 20px; }")
    html_parts.append(
        "    .chip { background: #e2e8f0; padding: 2px 6px; border-radius: 8px; margin-right: 4px; display: inline-block; cursor: pointer; }"
    )
    html_parts.append("    #graph-container { margin-top: 24px; }")
    html_parts.append(
        "    #graph { width: 100%; height: 520px; border: 1px solid #e2e8f0; border-radius: 8px; }"
    )
    html_parts.append("    .dom-highlight { box-shadow: 0 0 0 2px #f97316; }")
    html_parts.append("    .cy-highlight { }")
    html_parts.append("    .cy-dim { }")
    html_parts.append(
        "    .zone { background-color: #f8fafc; border: 1px dashed #cbd5e1; padding: 8px; }"
    )
    html_parts.append("  </style>")
    html_parts.append("</head>")
    html_parts.append("<body>")
    html_parts.append("  <h1>Threat Analysis Report</h1>")

    # Summary table
    html_parts.append("  <h2>Threat Summary</h2>")
    html_parts.append("  <table>")
    html_parts.append(
        "    <tr><th>ID</th><th>Threat</th><th>Severity</th><th>Score</th></tr>"
    )
    for threat in threats:
        severity_class = f"sev-{_safe(threat.severity)}"
        html_parts.append(
            '    <tr class="threat-row" data-threat-id="'
            f'{_safe(threat.id)}">'
            f"<td>{_safe(threat.id)}</td>"
            f"<td>{_safe(threat.title)}</td>"
            f'<td><span class="severity {severity_class}">{_safe(threat.severity)}</span></td>'
            f"<td>{threat.score:.1f}</td>"
            "</tr>"
        )
    html_parts.append("  </table>")

    # Graph visualization
    html_parts.append('  <div id="graph-container">')
    html_parts.append("    <h2>Architecture Graph</h2>")
    html_parts.append('    <div id="graph"></div>')
    html_parts.append("  </div>")

    # Architecture mapping tables
    if nodes:
        html_parts.append("  <h2>Architecture Mapping</h2>")
        html_parts.append("  <h3>Nodes to Threats</h3>")
        html_parts.append("  <table>")
        html_parts.append(
            "    <tr><th>Node</th><th>Zone</th><th>Type</th><th>Threats</th></tr>"
        )
        for node_id, node in nodes.items():
            threats_for_node = node_threats.get(node_id) or []
            threat_badges = (
                " ".join(
                    f'<span class="chip" data-threat-id="{_safe(tid)}">{_safe(tid)}</span>'
                    for tid in threats_for_node
                )
                or "&mdash;"
            )
            html_parts.append(
                "    <tr>"
                f"<td>{_safe(node.label)} [{_safe(node.id)}]</td>"
                f"<td>{_safe(node.zone)}</td>"
                f"<td>{_safe(node.type)}</td>"
                f"<td>{threat_badges}</td>"
                "</tr>"
            )
        html_parts.append("  </table>")

    if edges:
        html_parts.append("  <h3>Edges to Threats</h3>")
        html_parts.append("  <table>")
        html_parts.append("    <tr><th>Edge</th><th>Protocol</th><th>Threats</th></tr>")
        for key, edge in edge_lookup.items():
            # Deduplicate rows by using only canonical (with label if present)
            if key[2] is None and edge.label:
                continue
            threats_for_edge = edge_threats.get(key) or []
            threat_badges = (
                " ".join(
                    f'<span class="chip" data-threat-id="{_safe(tid)}">{_safe(tid)}</span>'
                    for tid in threats_for_edge
                )
                or "&mdash;"
            )
            src_label = nodes.get(edge.src).label if nodes.get(edge.src) else edge.src
            dst_label = nodes.get(edge.dst).label if nodes.get(edge.dst) else edge.dst
            label_suffix = f" : {edge.label}" if edge.label else ""
            html_parts.append(
                "    <tr>"
                f"<td>{_safe(src_label)} [{_safe(edge.src)}] -> {_safe(dst_label)} [{_safe(edge.dst)}]{_safe(label_suffix)}</td>"
                f"<td>{_safe(edge.protocol)}</td>"
                f"<td>{threat_badges}</td>"
                "</tr>"
            )
        html_parts.append("  </table>")

    # Threat details with evidence mapping
    html_parts.append("  <h2>Threat Details</h2>")
    for threat in threats:
        html_parts.append(
            f'  <div class="section" id="{_safe(threat.id)}" data-threat-id="{_safe(threat.id)}">'
        )
        html_parts.append(f"    <h3>{_safe(threat.id)}: {_safe(threat.title)}</h3>")
        html_parts.append('    <div class="meta">')
        html_parts.append(
            f'      Severity: <span class="severity sev-{_safe(threat.severity)}">{_safe(threat.severity)}</span> | '
            f"Score: {threat.score:.1f} | STRIDE: {', '.join(_safe(s) for s in threat.stride)}"
        )
        html_parts.append("    </div>")
        html_parts.append(
            f"    <p><strong>Affected Components:</strong> {_safe(', '.join(threat.affected))}</p>"
        )
        html_parts.append(f"    <p><strong>Why:</strong> {format_text(threat.why)}</p>")

        if threat.references:
            html_parts.append(
                f"    <p><strong>References:</strong> {_safe(', '.join(threat.references))}</p>"
            )

        recommended_action = getattr(threat, "recommended_action", "Not specified")
        html_parts.append(
            "    <p><strong>Recommended Actions:</strong><br>"
            + format_text(recommended_action)
            + "</p>"
        )

        # Evidence mapping
        html_parts.append('    <div class="section">')
        html_parts.append("      <h4>Evidence Mapping</h4>")
        if threat.evidence_nodes:
            html_parts.append("      <p><em>Nodes:</em></p>")
            html_parts.append('      <ul class="mapping-list">')
            for nid in threat.evidence_nodes:
                html_parts.append(f"        <li>{resolve_node(nid)}</li>")
            html_parts.append("      </ul>")
        if threat.evidence_edges:
            html_parts.append("      <p><em>Edges:</em></p>")
            html_parts.append('      <ul class="mapping-list">')
            for edge_id in threat.evidence_edges:
                html_parts.append(f"        <li>{resolve_edge(edge_id)}</li>")
            html_parts.append("      </ul>")
        if not threat.evidence_nodes and not threat.evidence_edges:
            html_parts.append('      <p class="meta">No evidence mapping provided.</p>')
        html_parts.append("    </div>")

        html_parts.append("  </div>")

    # Embed report JSON for client-side rendering
    report_payload = {
        "graph": {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "zone": n.zone,
                    "type": n.type,
                    "data": n.data,
                    "auth": n.auth,
                    "notes": n.notes,
                }
                for n in nodes.values()
            ],
            "edges": [
                {
                    "id": e.id or f"{e.src}->{e.dst}",
                    "src": e.src,
                    "dst": e.dst,
                    "label": e.label,
                    "protocol": e.protocol,
                    "data": e.data,
                }
                for e in edges
            ],
        },
        "threats": [
            {
                "id": t.id,
                "title": t.title,
                "severity": t.severity,
                "score": t.score,
                "stride": t.stride,
                "affected": t.affected,
                "why": t.why,
                "references": t.references,
                "recommended_action": t.recommended_action,
                "evidence": {
                    "nodes": t.evidence_nodes,
                    "edges": t.evidence_edges,
                },
            }
            for t in threats
        ],
    }

    json_payload = json.dumps(report_payload, ensure_ascii=False)
    # Prevent accidental script termination
    safe_json_payload = json_payload.replace("</", "<\\/")

    html_parts.append(
        "  <script>\n    window.THREAT_REPORT = " + safe_json_payload + ";\n  </script>"
    )
    html_parts.append(
        '  <script src="https://unpkg.com/cytoscape@3.33.1/dist/cytoscape.min.js"></script>'
    )
    html_parts.append(
        '  <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>'
    )
    html_parts.append(
        '  <script src="https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>'
    )
    html_parts.append(
        "  <script>\n"
        "    (function() {\n"
        "      const report = window.THREAT_REPORT || {};\n"
        "      const nodes = (report.graph && report.graph.nodes) || [];\n"
        "      const edges = (report.graph && report.graph.edges) || [];\n"
        "      const container = document.getElementById('graph');\n"
        "      if (!container) return;\n"
        "      let initialZoom = 1;\n"
        "      const cssEscape = (value) => (window.CSS && CSS.escape ? CSS.escape(value) : value);\n"
        "      const edgeIdMap = new Map();\n"
        "      edges.forEach((e) => {\n"
        "        const primary = e.id || `${e.src}->${e.dst}`;\n"
        "        const aliases = new Set([primary, `${e.src}->${e.dst}`]);\n"
        "        if (e.label) aliases.add(`${e.src}->${e.dst}:${e.label}`);\n"
        "        aliases.forEach((alias) => edgeIdMap.set(alias, primary));\n"
        "      });\n"
        "\n"
        "      function clearCyHighlight(cy) {\n"
        "        cy.elements().removeClass('cy-highlight cy-dim');\n"
        "      }\n"
        "\n"
        "      function highlightThreat(cy, reportObj, threatId) {\n"
        "        if (!threatId) return;\n"
        "        const threat = (reportObj.threats || []).find((t) => t.id === threatId);\n"
        "        clearCyHighlight(cy);\n"
        "        if (!threat) return;\n"
        "        const nodeIds = (threat.evidence && threat.evidence.nodes) || [];\n"
        "        const edgeIds = ((threat.evidence && threat.evidence.edges) || []).map((id) => edgeIdMap.get(id) || id);\n"
        "        const threatNodes = cy.nodes().filter((n) => nodeIds.includes(n.id()));\n"
        "        const threatEdges = cy.edges().filter((e) => edgeIds.includes(e.id()));\n"
        "        const targets = threatNodes.union(threatEdges);\n"
        "        if (targets.length) {\n"
        "          targets.addClass('cy-highlight');\n"
        "          cy.elements().difference(targets).addClass('cy-dim');\n"
        "          try {\n"
        "            cy.fit(targets, 60);\n"
        "            const bbox = targets.boundingBox();\n"
        "            const center = { x: (bbox.x1 + bbox.x2) / 2, y: (bbox.y1 + bbox.y2) / 2 };\n"
        "            const clampedZoom = Math.min(cy.zoom(), initialZoom * 1.2);\n"
        "            if (cy.zoom() > clampedZoom) {\n"
        "              cy.zoom({ level: clampedZoom, position: center });\n"
        "            }\n"
        "          } catch (err) {}\n"
        "        }\n"
        "      }\n"
        "\n"
        "      function clearDomHighlights() {\n"
        "        document.querySelectorAll('.dom-highlight').forEach((el) => el.classList.remove('dom-highlight'));\n"
        "      }\n"
        "\n"
        "      function scrollToThreat(threatId) {\n"
        "        const detail = document.getElementById(threatId);\n"
        "        if (detail && typeof detail.scrollIntoView === 'function') {\n"
        "          detail.scrollIntoView({ behavior: 'smooth', block: 'start' });\n"
        "        }\n"
        "      }\n"
        "\n"
        "      function highlightRows(threatIds) {\n"
        "        clearDomHighlights();\n"
        "        threatIds.forEach((tid) => {\n"
        '          const row = document.querySelector(`.threat-row[data-threat-id="${cssEscape(tid)}"]`);\n'
        "          if (row) row.classList.add('dom-highlight');\n"
        "        });\n"
        "      }\n"
        "\n"
        "      function bindInteractions(cy) {\n"
        "        const rows = Array.from(document.querySelectorAll('.threat-row[data-threat-id]'));\n"
        "        rows.forEach((row) => {\n"
        "          row.addEventListener('click', () => {\n"
        "            const tid = row.getAttribute('data-threat-id');\n"
        "            highlightRows([tid]);\n"
        "            highlightThreat(cy, report, tid);\n"
        "          });\n"
        "        });\n"
        "\n"
        "        const chips = Array.from(document.querySelectorAll('.chip[data-threat-id]'));\n"
        "        chips.forEach((chip) => {\n"
        "          chip.addEventListener('click', () => {\n"
        "            const tid = chip.getAttribute('data-threat-id');\n"
        "            highlightRows([tid]);\n"
        "            highlightThreat(cy, report, tid);\n"
        "          });\n"
        "        });\n"
        "\n"
        "        cy.on('tap', 'node, edge', (evt) => {\n"
        "          const elementId = evt.target.id();\n"
        "          const matchingThreats = (report.threats || []).filter((t) => {\n"
        "            const ev = t.evidence || {};\n"
        "            const nids = ev.nodes || [];\n"
        "            const eids = ev.edges || [];\n"
        "            return nids.includes(elementId) || eids.includes(elementId);\n"
        "          });\n"
        "          const ids = matchingThreats.map((t) => t.id);\n"
        "          highlightRows(ids);\n"
        "          clearCyHighlight(cy);\n"
        "          evt.target.addClass('cy-highlight');\n"
        "          cy.elements().difference(evt.target).addClass('cy-dim');\n"
        "        });\n"
        "      }\n"
        "\n"
        "      function createCy() {\n"
        "        const palette = ['#0ea5e9','#22c55e','#f97316','#a78bfa','#f43f5e','#14b8a6','#eab308','#3b82f6'];\n"
        "        const zoneColor = {};\n"
        "        const zones = Array.from(new Set(nodes.map((n) => n.zone).filter(Boolean)));\n"
        "        const zoneElements = zones.map((z) => {\n"
        "          if (!zoneColor[z]) {\n"
        "            zoneColor[z] = palette[Object.keys(zoneColor).length % palette.length];\n"
        "          }\n"
        "          const zoneId = `zone::${String(z).replace(/\\s+/g, '_')}`;\n"
        "          return { data: { id: zoneId, label: z, type: 'zone' } };\n"
        "        });\n"
        "        const elements = {\n"
        "          nodes: [\n"
        "            ...zoneElements,\n"
        "            ...nodes.map((n) => {\n"
        "              const zone = n.zone || 'default';\n"
        "              if (zone && !zoneColor[zone]) {\n"
        "                zoneColor[zone] = palette[Object.keys(zoneColor).length % palette.length];\n"
        "              }\n"
        "              const color = zoneColor[zone] || '#0ea5e9';\n"
        "              const parent = n.zone ? `zone::${String(n.zone).replace(/\\s+/g, '_')}` : undefined;\n"
        "              return { data: { id: n.id, label: n.label, zone: n.zone, type: n.type, color, parent } };\n"
        "            })\n"
        "          ],\n"
        "          edges: edges.map((e) => {\n"
        "            const edgeId = e.id || `${e.src}->${e.dst}`;\n"
        "            return { data: { id: edgeId, source: e.src, target: e.dst, label: e.label || '', protocol: e.protocol || '' } };\n"
        "          })\n"
        "        };\n"
        "        const cy = cytoscape({\n"
        "          container,\n"
        "          elements,\n"
        "          style: [\n"
        "            { selector: 'node[type = \\\"zone\\\"]', style: { 'background-color': '#f8fafc', 'background-opacity': 0.25, 'shape': 'round-rectangle', 'label': 'data(label)', 'color': '#0f172a', 'text-valign': 'top', 'text-halign': 'center', 'text-wrap': 'wrap', 'font-weight': 700, 'font-size': 12, 'text-background-color': '#f8fafc', 'text-background-opacity': 0.9, 'text-background-padding': 4, 'text-margin-y': -12, 'border-style': 'dashed', 'border-color': '#94a3b8', 'border-width': 2, 'padding': 18, 'z-compound-depth': 'bottom' } },\n"
        "            { selector: 'node', style: { 'background-color': 'data(color)', 'label': 'data(label)', 'color': '#0f172a', 'text-valign': 'center', 'text-halign': 'center', 'text-wrap': 'wrap', 'font-size': 10, 'border-width': 1, 'border-color': '#0f172a10', 'z-compound-depth': 'top' } },\n"
        "            { selector: 'edge', style: { 'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'width': 2, 'line-color': '#94a3b8', 'target-arrow-color': '#94a3b8', 'label': 'data(label)', 'font-size': 8, 'text-background-color': '#fff', 'text-background-opacity': 0.7, 'text-background-padding': 2 } },\n"
        "            { selector: 'node.cy-highlight', style: { 'background-color': '#f97316', 'border-color': '#f97316', 'border-width': 3 } },\n"
        "            { selector: 'edge.cy-highlight', style: { 'line-color': '#f97316', 'target-arrow-color': '#f97316', 'width': 3 } },\n"
        "            { selector: '.cy-dim', style: { 'opacity': 0.25 } }\n"
        "          ],\n"
        "        });\n"
        "        try {\n"
        "          cy.layout({ name: 'dagre', rankDir: 'LR', padding: 30, nodeSep: 40, edgeSep: 20 }).run();\n"
        "        } catch (e) {\n"
        "          cy.layout({ name: 'cose', padding: 30, animate: false }).run();\n"
        "        }\n"
        "        cy.nodes().forEach((n) => n.grabbable(true));\n"
        "        initialZoom = cy.zoom();\n"
        "        return cy;\n"
        "      }\n"
        "\n"
        "      const cy = createCy();\n"
        "      bindInteractions(cy);\n"
        "    })();\n"
        "  </script>"
    )

    html_parts.append("</body>")
    html_parts.append("</html>")

    content = "\n".join(html_parts)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
    return content


def _resolve_node_id(ref: str, graph: Graph) -> Optional[str]:
    """Resolve a node reference to a graph node ID, matching by ID first then label."""
    if not ref:
        return None
    candidate = ref.strip()
    if candidate in graph.nodes:
        return candidate
    for nid, node in graph.nodes.items():
        if node.label == candidate:
            return nid
    return None


def _parse_edge_reference(
    ref: str, graph: Graph
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse an evidence edge reference like 'A->B:label' or an edge id into node IDs and optional label."""
    if "->" not in ref:
        for edge in graph.edges:
            if edge.id == ref:
                return edge.src, edge.dst, edge.label
        return None, None, None
    src_part, rest = ref.split("->", 1)
    label_part = None
    if ":" in rest:
        dst_part, label_part = rest.split(":", 1)
    else:
        dst_part = rest
    src_id = _resolve_node_id(src_part, graph)
    dst_id = _resolve_node_id(dst_part, graph)
    label = label_part.strip() if label_part and label_part.strip() else None
    return src_id, dst_id, label


def _extract_td_flow_label_for_export(cell: Dict[str, Any]) -> Optional[str]:
    """Extract a flow label using the same precedence as the Threat Dragon parser."""
    data_block: Dict[str, Any] = cell.get("data") or {}
    if data_block.get("name"):
        return str(data_block["name"]).strip() or None

    labels = cell.get("labels") or []
    if labels:
        first = labels[0]
        if isinstance(first, str):
            text = first
        elif isinstance(first, dict):
            text = first.get("text", "")
        else:
            text = ""
        if text and str(text).strip():
            return str(text).strip()
    return None


def _build_flow_lookup_for_export(
    cells: List[Dict[str, Any]],
) -> Dict[Tuple[str, str, Optional[str]], List[Dict[str, Any]]]:
    """Create a lookup map for flow cells keyed by (src, dst, label)."""
    lookup: Dict[Tuple[str, str, Optional[str]], List[Dict[str, Any]]] = {}
    for cell in cells:
        data_block: Dict[str, Any] = cell.get("data") or {}
        if data_block.get("type") != "tm.Flow" or cell.get("shape") != "flow":
            continue
        src = (cell.get("source") or {}).get("cell")
        dst = (cell.get("target") or {}).get("cell")
        if not src or not dst:
            continue
        label = _extract_td_flow_label_for_export(cell)
        key = (src, dst, label)
        lookup.setdefault(key, []).append(cell)
        # Allow matching flows that omit labels in evidence
        lookup.setdefault((src, dst, None), []).append(cell)
    return lookup


def _threat_to_threat_dragon(threat: Threat) -> Dict[str, Any]:
    """Map internal Threat to a Threat Dragon-friendly threat block."""
    stride_type = threat.stride[0] if threat.stride else ""
    return {
        "id": threat.id,
        "title": threat.title,
        "type": stride_type,
        "status": "Open",
        "severity": threat.severity,
        "description": threat.why,
        "mitigation": threat.recommended_action,
        "references": threat.references,
        "score": threat.score,
        "affected": threat.affected,
        "confidence": threat.confidence,
    }


def export_threat_dragon(
    threats: List[Threat], graph: Graph, output_file: Optional[str] = None
) -> str:
    """
    Export threats into a Threat Dragon-compatible JSON using preserved layout.

    This requires a graph that originated from a Threat Dragon import so the
    original model (including cells/positions) can be reused without regenerating
    layout data.
    """
    if not graph or not graph.threat_dragon or not graph.threat_dragon.original_model:
        raise ValueError("Threat Dragon metadata is missing; cannot export Threat Dragon JSON.")

    model = copy.deepcopy(graph.threat_dragon.original_model)
    detail = model.get("detail") or {}
    diagrams = detail.get("diagrams") or []
    if not diagrams:
        raise ValueError("Threat Dragon model is missing diagrams; cannot export.")

    diagram = diagrams[0] or {}
    cells = diagram.get("cells") or []
    cell_lookup = {
        cell.get("id"): cell for cell in cells if isinstance(cell, dict) and cell.get("id")
    }
    flow_lookup = _build_flow_lookup_for_export(cells)

    cell_threats: Dict[str, List[Dict[str, Any]]] = {}
    diagram_level_threats: List[Dict[str, Any]] = []

    for threat in threats:
        td_block = _threat_to_threat_dragon(threat)
        assigned = False

        for node_ref in threat.evidence_nodes:
            node_id = _resolve_node_id(node_ref, graph)
            if node_id and node_id in cell_lookup:
                cell_threats.setdefault(node_id, []).append(td_block)
                assigned = True

        for edge_ref in threat.evidence_edges:
            src_id, dst_id, label = _parse_edge_reference(edge_ref, graph)
            if not src_id or not dst_id:
                continue
            flow_cells = flow_lookup.get((src_id, dst_id, label)) or flow_lookup.get(
                (src_id, dst_id, None)
            )
            if not flow_cells:
                continue
            cell_id = flow_cells[0].get("id")
            if cell_id:
                cell_threats.setdefault(cell_id, []).append(td_block)
                assigned = True

        if not assigned:
            diagram_level_threats.append(td_block)

    for cell_id, cell in cell_lookup.items():
        data_block = cell.get("data")
        if not isinstance(data_block, dict):
            continue
        threats_for_cell = cell_threats.get(cell_id) or []
        data_block["threats"] = threats_for_cell
        if threats_for_cell:
            data_block["hasOpenThreats"] = True
        elif "hasOpenThreats" in data_block:
            data_block["hasOpenThreats"] = False

    if diagram_level_threats:
        diagram["threats"] = diagram_level_threats

    output = json.dumps(model, ensure_ascii=False, indent=2)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output)
    return output


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
