"""
Mermaid diagram parser
"""

import re
from typing import Dict, List, Tuple

from threat_thinker.models import Edge, Graph, ImportMetrics, Node, Zone
from threat_thinker.zone_utils import (
    representative_zone_name,
    sort_zone_ids_by_hierarchy,
)


# tolerate variations:
#   - Plain: A -> B, A --> B, A ---> B
#   - Pipe label: A --> B |label|
#   - Inline label: A -- label --> B
#   - Source with inline node label: A[User] --> B
# IDs allow letters, numbers, underscore, dash, dot
# Optional inline node label after source is captured and ignored
SOURCE_WITH_LABEL = r"([A-Za-z0-9_.-]+)(?:\s*[\[\(\{]{1,2}[^\]\)\}]+?[\]\)\}]{1,2})?"
MERMAID_EDGE_INLINE_RE = re.compile(
    rf"^\s*{SOURCE_WITH_LABEL}\s*--+\s*([^->\n]+?)\s*-+>\s*([A-Za-z0-9_.-]+)"
)
MERMAID_EDGE_PIPE_RE = re.compile(
    rf"^\s*{SOURCE_WITH_LABEL}\s*-\s*-*\s*>+\s*([A-Za-z0-9_.-]+)\s*\|\s*([^|]+?)\s*\|"
)
MERMAID_EDGE_PLAIN_RE = re.compile(
    rf"^\s*{SOURCE_WITH_LABEL}\s*-\s*-*\s*>+\s*([A-Za-z0-9_.-]+)"
)

NODE_LABEL_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*[\[\(\{]{1,2}\s*([^]\)\}]+?)\s*[\]\)\}]{1,2}"
)
SUBGRAPH_START_RE = re.compile(r"^\s*subgraph\s+(.+)", re.IGNORECASE)
SUBGRAPH_END_RE = re.compile(r"^\s*end\s*$", re.IGNORECASE)


def parse_mermaid(path: str) -> Tuple[Graph, ImportMetrics]:
    """
    Parse a Mermaid diagram file and return a Graph object and import metrics.

    Args:
        path: Path to the Mermaid file

    Returns:
        Tuple of (Graph, ImportMetrics)
    """
    g = Graph(source_format="mermaid")
    metrics = ImportMetrics()
    zone_stack: List[str] = []
    zone_defs: Dict[str, Zone] = {}
    node_zone_membership: Dict[str, List[str]] = {}

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    metrics.total_lines = len(lines)

    def _ensure_node(node_id: str) -> Node:
        if node_id not in g.nodes:
            g.nodes[node_id] = Node(id=node_id, label=node_id)
        return g.nodes[node_id]

    for line in lines:
        # manage subgraph nesting first
        start = SUBGRAPH_START_RE.match(line)
        if start:
            raw_label = start.group(1).strip()
            label = raw_label
            if "[" in raw_label and raw_label.endswith("]"):
                label = raw_label.split("[", 1)[1].rstrip("]")
            zone_id = f"zone_{len(zone_defs)}"
            parent_id = zone_stack[-1] if zone_stack else None
            zone_defs[zone_id] = Zone(
                id=zone_id, name=label.strip(), parent_id=parent_id
            )
            zone_stack.append(zone_id)
            continue
        if SUBGRAPH_END_RE.match(line):
            if zone_stack:
                zone_stack.pop()
            continue

        # normalize common arrow typos
        norm = line.replace("—", "-").replace("→", ">")  # emdash/arrow variants
        match = None
        label = None
        m_inline = MERMAID_EDGE_INLINE_RE.search(norm)
        if m_inline:
            match = m_inline
            src, label, dst = m_inline.group(1), m_inline.group(2), m_inline.group(3)
        else:
            m_pipe = MERMAID_EDGE_PIPE_RE.search(norm)
            if m_pipe:
                match = m_pipe
                src, dst, label = m_pipe.group(1), m_pipe.group(2), m_pipe.group(3)
            else:
                m_plain = MERMAID_EDGE_PLAIN_RE.search(norm)
                if m_plain:
                    match = m_plain
                    src, dst = m_plain.group(1), m_plain.group(2)
        if match:
            metrics.edge_candidates += 1
            g.edges.append(
                Edge(src=src, dst=dst, label=label.strip() if label else None)
            )
            metrics.edges_parsed += 1
            for nid in (src, dst):
                _ensure_node(nid)
                if zone_stack:
                    node_zone_membership.setdefault(nid, []).extend(zone_stack)

        # node labels like A[User], B((API))
        m = NODE_LABEL_RE.search(line)
        if m:
            metrics.node_label_candidates += 1
            nid, nlabel = m.group(1), m.group(2)
            n = _ensure_node(nid)
            n.label = nlabel.strip()
            if zone_stack:
                node_zone_membership.setdefault(nid, []).extend(zone_stack)
            metrics.node_labels_parsed += 1

    # finalize zone membership/order
    g.zones = zone_defs
    for nid, node in g.nodes.items():
        zone_ids = sort_zone_ids_by_hierarchy(
            node_zone_membership.get(nid, []), g.zones
        )
        node.zones = zone_ids
        if not node.zone:
            node.zone = representative_zone_name(zone_ids, g.zones)

    return g, metrics
