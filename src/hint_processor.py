"""
Hint processing functionality
"""

import yaml
from typing import List, Optional

from models import Graph, Node, Edge
from zone_utils import representative_zone_name, sort_zone_ids_by_hierarchy


def _zone_name_lookup(graph: Graph) -> dict:
    """Return case-insensitive zone name -> id mapping."""
    lookup = {}
    for zid, zone in (graph.zones or {}).items():
        if zone.name:
            lookup[zone.name.lower()] = zid
    return lookup


def _normalize_zone_ids(zones_hint: List[str], node: Node, graph: Graph) -> List[str]:
    """
    Map hinted zone values to known zone ids when possible and preserve existing ids when hints don't match.
    """
    mapped: List[str] = []
    zones_map = graph.zones or {}
    name_lookup = _zone_name_lookup(graph) if zones_map else {}
    seen = set()
    for raw in zones_hint:
        if not raw:
            continue
        val = str(raw)
        candidate = None
        if val in zones_map:
            candidate = val
        else:
            lookup = name_lookup.get(val.lower())
            if lookup:
                candidate = lookup
        if candidate and candidate not in seen:
            seen.add(candidate)
            mapped.append(candidate)

    def _is_ancestor(anc_id: str, desc_id: str) -> bool:
        if anc_id == desc_id:
            return True
        current = zones_map.get(desc_id)
        visited = set()
        while current and current.parent_id and current.parent_id not in visited:
            if current.parent_id == anc_id:
                return True
            visited.add(current.parent_id)
            current = zones_map.get(current.parent_id)
        return False

    existing_ids = list(node.zones) if node.zones else []
    if mapped and existing_ids and zones_map:
        compatible = []
        for zid in mapped:
            if any(
                _is_ancestor(zid, ex) or _is_ancestor(ex, zid) for ex in existing_ids
            ):
                compatible.append(zid)
        if compatible:
            return sort_zone_ids_by_hierarchy(existing_ids + compatible, zones_map)
        return existing_ids
    if mapped:
        combined: List[str] = []
        for zid in mapped + existing_ids:
            if zid and zid not in combined:
                combined.append(zid)
        return combined
    if existing_ids:
        return existing_ids
    return [str(z) for z in zones_hint if z]


def _normalize_zone_hint(zone_hint: Optional[str], graph: Graph) -> Optional[str]:
    """Map a single zone hint to a known id if possible."""
    if not zone_hint:
        return None
    val = str(zone_hint)
    zones_map = graph.zones or {}
    if val in zones_map:
        return val
    name_lookup = _zone_name_lookup(graph)
    if val.lower() in name_lookup:
        return name_lookup[val.lower()]
    return val


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
        node.zones = _normalize_zone_ids(zones_hint, node, graph)
    if zone_hint is not None:
        normalized_zone = _normalize_zone_hint(zone_hint, graph)
        node.zone = normalized_zone
        if not node.zones and normalized_zone:
            node.zones = [str(normalized_zone)]
    if node.zones and not node.zone:
        node.zone = representative_zone_name(node.zones, graph.zones or {})
    elif node.zones:
        # Keep legacy single zone aligned with the deepest known zone name.
        node.zone = representative_zone_name(node.zones, graph.zones or {}) or node.zone
