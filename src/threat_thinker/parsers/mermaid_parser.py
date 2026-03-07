"""
Mermaid diagram parser
"""

import re
from typing import Dict, List, Optional, Tuple

from threat_thinker.models import Edge, Graph, ImportMetrics, Node, Zone
from threat_thinker.zone_utils import (
    representative_zone_name,
    sort_zone_ids_by_hierarchy,
)


ARROW_CANDIDATE_RE = re.compile(r"(?:<-->|==>|-\.->|--->|-->|->)")
EDGE_OP_PATTERN = r"(?:==>|-\.->|--->|-->|->)"

MERMAID_EDGE_BIDIRECTIONAL_RE = re.compile(
    r"^\s*(?P<src>.+?)\s*<-->\s*(?:\|\s*(?P<label>[^|]+?)\s*\|\s*)?(?P<dst>.+?)\s*$"
)
MERMAID_EDGE_PIPE_RE = re.compile(
    rf"^\s*(?P<src>.+?)\s*(?P<op>{EDGE_OP_PATTERN})\s*\|\s*(?P<label>[^|]+?)\s*\|\s*(?P<dst>.+?)\s*$"
)
MERMAID_EDGE_TRAILING_PIPE_RE = re.compile(
    rf"^\s*(?P<src>.+?)\s*(?P<op>{EDGE_OP_PATTERN})\s*(?P<dst>.+?)\s*\|\s*(?P<label>[^|]+?)\s*\|\s*$"
)
MERMAID_EDGE_INLINE_RE = re.compile(
    rf"^\s*(?P<src>.+?)\s*--+\s*(?P<label>[^|<>]+?)\s*(?P<op>{EDGE_OP_PATTERN})\s*(?P<dst>.+?)\s*$"
)
MERMAID_EDGE_PLAIN_RE = re.compile(
    rf"^\s*(?P<src>.+?)\s*(?P<op>{EDGE_OP_PATTERN})\s*(?P<dst>.+?)\s*$"
)

NODE_ID_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)(.*)$")
SUBGRAPH_START_RE = re.compile(r"^\s*subgraph\s+(.+)", re.IGNORECASE)
SUBGRAPH_END_RE = re.compile(r"^\s*end\s*$", re.IGNORECASE)
PAIR_DELIMITERS = [
    ("[(", ")]"),
    ("((", "))"),
    ("{{", "}}"),
    ("[[", "]]"),
    ("[", "]"),
    ("(", ")"),
    ("{", "}"),
]


def _normalize_label(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    cleaned = text.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1].strip()
    return cleaned or None


def _parse_node_token(token: str) -> Tuple[Optional[str], Optional[str]]:
    cleaned = token.strip().rstrip(";")
    if not cleaned:
        return None, None

    # Mermaid class assignment suffix (e.g., "api[API]:::trusted")
    if ":::" in cleaned:
        cleaned = cleaned.split(":::", 1)[0].strip()

    match = NODE_ID_RE.match(cleaned)
    if not match:
        return None, None

    node_id = match.group(1)
    remainder = match.group(2).strip()
    if not remainder:
        return node_id, None

    for opener, closer in PAIR_DELIMITERS:
        if remainder.startswith(opener) and remainder.endswith(closer):
            inner = remainder[len(opener) : len(remainder) - len(closer)]
            return node_id, _normalize_label(inner)

    return None, None


def _parse_edge_entries(
    line: str,
) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    bidir = MERMAID_EDGE_BIDIRECTIONAL_RE.match(line)
    if bidir:
        src_id, src_label = _parse_node_token(bidir.group("src"))
        dst_id, dst_label = _parse_node_token(bidir.group("dst"))
        if not src_id or not dst_id:
            return []
        label = _normalize_label(bidir.group("label"))
        return [
            (src_id, dst_id, label, src_label, dst_label),
            (dst_id, src_id, label, dst_label, src_label),
        ]

    for pattern in (
        MERMAID_EDGE_PIPE_RE,
        MERMAID_EDGE_TRAILING_PIPE_RE,
        MERMAID_EDGE_INLINE_RE,
        MERMAID_EDGE_PLAIN_RE,
    ):
        match = pattern.match(line)
        if not match:
            continue
        src_id, src_label = _parse_node_token(match.group("src"))
        dst_id, dst_label = _parse_node_token(match.group("dst"))
        if not src_id or not dst_id:
            return []
        label = _normalize_label(match.groupdict().get("label"))
        return [(src_id, dst_id, label, src_label, dst_label)]

    return []


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

        # normalize common arrow typos and strip Mermaid comments
        norm = (
            line.split("%%", 1)[0].replace("—", "-").replace("→", ">").strip()
        )  # emdash/arrow variants
        if not norm:
            continue

        edge_entries: List[
            Tuple[str, str, Optional[str], Optional[str], Optional[str]]
        ] = []
        if ARROW_CANDIDATE_RE.search(norm):
            metrics.edge_candidates += 1
            edge_entries = _parse_edge_entries(norm)

        if edge_entries:
            for src, dst, label, src_label, dst_label in edge_entries:
                g.edges.append(Edge(src=src, dst=dst, label=label))
                metrics.edges_parsed += 1

                src_node = _ensure_node(src)
                dst_node = _ensure_node(dst)
                if src_label:
                    src_node.label = src_label
                if dst_label:
                    dst_node.label = dst_label
                if zone_stack:
                    node_zone_membership.setdefault(src, []).extend(zone_stack)
                    node_zone_membership.setdefault(dst, []).extend(zone_stack)

            continue

        # standalone node labels like A[User], B((API))
        node_id, node_label = _parse_node_token(norm)
        if node_id and node_label:
            metrics.node_label_candidates += 1
            n = _ensure_node(node_id)
            n.label = node_label
            if zone_stack:
                node_zone_membership.setdefault(node_id, []).extend(zone_stack)
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
