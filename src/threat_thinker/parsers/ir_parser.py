"""
IR parser for Threat Thinker's native Graph representation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

from threat_thinker.models import Edge, Graph, ImportMetrics, Node, Zone
from threat_thinker.zone_utils import (
    representative_zone_name,
    sort_zone_ids_by_hierarchy,
)


class IRValidationError(ValueError):
    """Raised when a provided IR payload is structurally invalid."""


def parse_ir(path: str) -> Tuple[Graph, ImportMetrics]:
    """
    Parse a JSON file containing the native Graph IR.
    """
    metrics = ImportMetrics()
    raw_text = Path(path).read_text(encoding="utf-8")
    metrics.total_lines = len(raw_text.splitlines())

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise IRValidationError(f"Invalid IR JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise IRValidationError("IR payload must be a JSON object.")

    threat_dragon_meta = payload.get("threat_dragon")
    if threat_dragon_meta not in (None, {}):
        raise IRValidationError(
            "IR input does not support threat_dragon metadata; use Threat Dragon input instead."
        )

    nodes_payload = payload.get("nodes", {})
    edges_payload = payload.get("edges", [])
    zones_payload = payload.get("zones", {})

    if not isinstance(nodes_payload, dict):
        raise IRValidationError("IR field 'nodes' must be an object keyed by node id.")
    if not isinstance(edges_payload, list):
        raise IRValidationError("IR field 'edges' must be an array.")
    if not isinstance(zones_payload, dict):
        raise IRValidationError("IR field 'zones' must be an object keyed by zone id.")

    graph = Graph(source_format="ir")
    graph.zones = _parse_zones(zones_payload)
    graph.nodes = _parse_nodes(nodes_payload, graph.zones)
    graph.edges = _parse_edges(edges_payload, graph.nodes)

    metrics.node_label_candidates = len(nodes_payload)
    metrics.node_labels_parsed = len(graph.nodes)
    metrics.edge_candidates = len(edges_payload)
    metrics.edges_parsed = len(graph.edges)
    return graph, metrics


def _parse_zones(payload: Dict[str, Any]) -> Dict[str, Zone]:
    zones: Dict[str, Zone] = {}
    for zone_key, zone_value in payload.items():
        if not isinstance(zone_value, dict):
            raise IRValidationError(f"Zone '{zone_key}' must be a JSON object.")
        zone_id = str(zone_value.get("id") or zone_key).strip()
        if not zone_id:
            raise IRValidationError("Zone id cannot be empty.")
        if zone_key != zone_id:
            raise IRValidationError(
                f"Zone key '{zone_key}' does not match embedded id '{zone_id}'."
            )
        zone_name = str(zone_value.get("name") or "").strip()
        if not zone_name:
            raise IRValidationError(f"Zone '{zone_id}' must define a non-empty name.")
        parent_id = zone_value.get("parent_id")
        if parent_id is not None:
            parent_id = str(parent_id).strip() or None
        zones[zone_id] = Zone(id=zone_id, name=zone_name, parent_id=parent_id)

    for zone_id, zone in zones.items():
        if zone.parent_id and zone.parent_id not in zones:
            raise IRValidationError(
                f"Zone '{zone_id}' references unknown parent zone '{zone.parent_id}'."
            )

    _assert_zone_tree_acyclic(zones)
    return zones


def _assert_zone_tree_acyclic(zones: Dict[str, Zone]) -> None:
    visiting = set()
    visited = set()

    def _visit(zone_id: str) -> None:
        if zone_id in visited:
            return
        if zone_id in visiting:
            raise IRValidationError(f"Zone hierarchy contains a cycle at '{zone_id}'.")
        visiting.add(zone_id)
        parent_id = zones[zone_id].parent_id
        if parent_id:
            _visit(parent_id)
        visiting.remove(zone_id)
        visited.add(zone_id)

    for zone_id in zones:
        _visit(zone_id)


def _parse_nodes(payload: Dict[str, Any], zones: Dict[str, Zone]) -> Dict[str, Node]:
    nodes: Dict[str, Node] = {}
    for node_key, node_value in payload.items():
        if not isinstance(node_value, dict):
            raise IRValidationError(f"Node '{node_key}' must be a JSON object.")
        node_id = str(node_value.get("id") or node_key).strip()
        if not node_id:
            raise IRValidationError("Node id cannot be empty.")
        if node_key != node_id:
            raise IRValidationError(
                f"Node key '{node_key}' does not match embedded id '{node_id}'."
            )
        label = str(node_value.get("label") or "").strip()
        if not label:
            raise IRValidationError(f"Node '{node_id}' must define a non-empty label.")

        zones_list = _normalize_zone_refs(node_value.get("zones"), node_id, zones)
        zone_value = node_value.get("zone")
        zone = str(zone_value).strip() if zone_value is not None else None
        if zones_list and zones:
            zones_list = sort_zone_ids_by_hierarchy(zones_list, zones)
            zone = representative_zone_name(zones_list, zones) or zone

        node = Node(
            id=node_id,
            label=label,
            zone=zone,
            zones=zones_list,
            type=_strip_optional_str(node_value.get("type")),
            data=_normalize_string_list(node_value.get("data"), "node.data", node_id),
            auth=_normalize_optional_bool(node_value.get("auth"), "auth", node_id),
            notes=_strip_optional_str(node_value.get("notes")),
        )
        nodes[node_id] = node
    return nodes


def _parse_edges(payload: Iterable[Any], nodes: Dict[str, Node]) -> list[Edge]:
    edges: list[Edge] = []
    for index, edge_value in enumerate(payload):
        if not isinstance(edge_value, dict):
            raise IRValidationError(f"Edge at index {index} must be a JSON object.")
        src = str(edge_value.get("src") or "").strip()
        dst = str(edge_value.get("dst") or "").strip()
        if not src or not dst:
            raise IRValidationError(f"Edge at index {index} must define src and dst.")
        if src not in nodes or dst not in nodes:
            raise IRValidationError(
                f"Edge at index {index} references unknown nodes '{src}' -> '{dst}'."
            )
        edge = Edge(
            src=src,
            dst=dst,
            label=_strip_optional_str(edge_value.get("label")),
            protocol=_strip_optional_str(edge_value.get("protocol")),
            data=_normalize_string_list(
                edge_value.get("data"), "edge.data", str(index)
            ),
            id=_strip_optional_str(edge_value.get("id")),
        )
        edges.append(edge)
    return edges


def _normalize_zone_refs(value: Any, node_id: str, zones: Dict[str, Zone]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise IRValidationError(f"Node '{node_id}' field 'zones' must be an array.")
    zone_ids: list[str] = []
    for raw in value:
        zone_id = str(raw or "").strip()
        if not zone_id:
            raise IRValidationError(
                f"Node '{node_id}' field 'zones' cannot contain empty values."
            )
        if zones and zone_id not in zones:
            raise IRValidationError(
                f"Node '{node_id}' references unknown zone '{zone_id}'."
            )
        if zone_id not in zone_ids:
            zone_ids.append(zone_id)
    return zone_ids


def _normalize_string_list(value: Any, field_name: str, owner: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise IRValidationError(f"{field_name} for '{owner}' must be an array.")
    return [str(item) for item in value if str(item)]


def _normalize_optional_bool(value: Any, field_name: str, owner: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise IRValidationError(f"Field '{field_name}' for '{owner}' must be a boolean.")


def _strip_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
