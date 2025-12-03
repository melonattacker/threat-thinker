"""
Hint processing functionality
"""

import yaml
from typing import Optional

from models import Graph, Node, Edge
from zone_utils import representative_zone_name


def apply_hints(g: Graph, hints_path: Optional[str]) -> Graph:
    """
    Apply hints from a YAML file to the graph.

    Args:
        g: Graph object to modify
        hints_path: Path to YAML hints file (optional)

    Returns:
        Modified Graph object
    """
    if not hints_path:
        return g

    with open(hints_path, "r", encoding="utf-8") as f:
        hints = yaml.safe_load(f) or {}

    # nodes
    for nid, attrs in (hints.get("nodes") or {}).items():
        if nid not in g.nodes:
            g.nodes[nid] = Node(id=nid, label=attrs.get("label", nid))
        node = g.nodes[nid]
        _apply_zone_attrs(node, attrs, g)
        node.type = attrs.get("type", node.type)
        node.auth = attrs.get("auth", node.auth)
        node.notes = attrs.get("notes", node.notes)
        if isinstance(attrs.get("data"), list):
            node.data = list({*node.data, *[str(x) for x in attrs["data"]]})
        if "label" in attrs:
            node.label = attrs["label"]

    # edges
    for e in hints.get("edges") or []:
        src, dst = e.get("from"), e.get("to")
        if not src or not dst:
            continue
        found = False
        for edge in g.edges:
            if edge.src == src and edge.dst == dst:
                found = True
                edge.protocol = e.get("protocol", edge.protocol)
                if isinstance(e.get("data"), list):
                    edge.data = list({*edge.data, *[str(x) for x in e["data"]]})
                if e.get("label"):
                    edge.label = e["label"]
        if not found:
            new_edge = Edge(src=src, dst=dst, label=e.get("label"))
            new_edge.protocol = e.get("protocol")
            if isinstance(e.get("data"), list):
                new_edge.data = [str(x) for x in e["data"]]
            g.edges.append(new_edge)
            if src not in g.nodes:
                g.nodes[src] = Node(id=src, label=src)
            if dst not in g.nodes:
                g.nodes[dst] = Node(id=dst, label=dst)

    return g


def merge_llm_hints(g: Graph, hints: dict) -> Graph:
    """
    Merge LLM-inferred hints into the graph.

    Args:
        g: Graph object to modify
        hints: Dictionary of hints from LLM

    Returns:
        Modified Graph object
    """
    # nodes
    for nid, attrs in (hints.get("nodes") or {}).items():
        if nid not in g.nodes:
            g.nodes[nid] = Node(id=nid, label=attrs.get("label", nid))
        n = g.nodes[nid]
        n.label = attrs.get("label", n.label)
        n.type = attrs.get("type", n.type)
        _apply_zone_attrs(n, attrs, g)
        if isinstance(attrs.get("data"), list):
            n.data = list({*n.data, *[str(x) for x in attrs["data"]]})
        if "auth" in attrs:
            n.auth = attrs["auth"]
        if "notes" in attrs:
            n.notes = attrs["notes"]

    # edges
    for e in hints.get("edges") or []:
        src, dst = e.get("from"), e.get("to")
        if not src or not dst:
            continue
        matched = None
        for edge in g.edges:
            if edge.src == src and edge.dst == dst:
                matched = edge
                break
        if matched:
            if e.get("protocol"):
                matched.protocol = e["protocol"]
            if isinstance(e.get("data"), list):
                matched.data = list({*matched.data, *[str(x) for x in e["data"]]})
        else:
            ne = Edge(src=src, dst=dst, protocol=e.get("protocol"))
            if isinstance(e.get("data"), list):
                ne.data = [str(x) for x in e["data"]]
            g.edges.append(ne)

    return g


def _apply_zone_attrs(node: Node, attrs: dict, graph: Graph) -> None:
    """
    Apply zone/zones hints to a node, keeping legacy zone in sync with the innermost zone name.
    """
    zones_hint = attrs.get("zones")
    zone_hint = attrs.get("zone")

    if isinstance(zones_hint, list):
        node.zones = [str(z) for z in zones_hint if z]
    if zone_hint is not None:
        node.zone = zone_hint
        if not node.zones and zone_hint:
            node.zones = [str(zone_hint)]
    if node.zones and not node.zone:
        node.zone = representative_zone_name(node.zones, graph.zones or {})
