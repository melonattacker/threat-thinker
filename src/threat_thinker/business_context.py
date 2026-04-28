"""Utilities for turning system descriptions into Threat Thinker Graph IR."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from threat_thinker.models import Edge, Graph, ImportMetrics, Node, Zone
from threat_thinker.zone_utils import (
    representative_zone_name,
    sort_zone_ids_by_hierarchy,
)


CONFIDENCE_VALUES = {"stated", "implied", "assumed"}


@dataclass
class BusinessContextDfdResult:
    summary: str
    graph: Graph
    metrics: ImportMetrics
    assumptions: List[str] = field(default_factory=list)
    clarifying_questions: List[str] = field(default_factory=list)
    element_confidence: Dict[str, Dict[str, str]] = field(default_factory=dict)


def dfd_result_from_payload(payload: Dict[str, Any]) -> BusinessContextDfdResult:
    """Convert a validated LLM DFD payload into Graph IR plus sidecar metadata."""
    graph_payload = payload.get("graph") or {}
    graph = Graph(source_format="description")
    metrics = ImportMetrics()
    element_confidence: Dict[str, Dict[str, str]] = {
        "nodes": {},
        "edges": {},
        "zones": {},
    }

    zones_payload = _dict_payload(graph_payload.get("zones"))
    graph.zones = _parse_zones(zones_payload, element_confidence["zones"])

    nodes_payload = _dict_payload(graph_payload.get("nodes"))
    metrics.node_label_candidates = len(nodes_payload)
    graph.nodes = _parse_nodes(nodes_payload, graph.zones, element_confidence["nodes"])
    metrics.node_labels_parsed = len(graph.nodes)

    edges_payload = graph_payload.get("edges") or []
    metrics.edge_candidates = (
        len(edges_payload) if isinstance(edges_payload, list) else 0
    )
    graph.edges = _parse_edges(edges_payload, graph.nodes, element_confidence["edges"])
    metrics.edges_parsed = len(graph.edges)

    return BusinessContextDfdResult(
        summary=str(payload.get("summary") or "").strip(),
        graph=graph,
        metrics=metrics,
        assumptions=_string_list(payload.get("assumptions")),
        clarifying_questions=_string_list(payload.get("clarifying_questions")),
        element_confidence=element_confidence,
    )


def graph_to_native_ir_dict(graph: Graph) -> Dict[str, Any]:
    """Serialize Graph to the native IR shape accepted by the IR parser."""
    return {
        "nodes": {
            node_id: {
                "id": node.id,
                "label": node.label,
                "zone": node.zone,
                "zones": node.zones,
                "type": node.type,
                "data": node.data,
                "auth": node.auth,
                "notes": node.notes,
            }
            for node_id, node in graph.nodes.items()
        },
        "edges": [
            {
                "src": edge.src,
                "dst": edge.dst,
                "label": edge.label,
                "protocol": edge.protocol,
                "data": edge.data,
                "id": edge.id,
            }
            for edge in graph.edges
        ],
        "zones": {
            zone_id: {
                "id": zone.id,
                "name": zone.name,
                "parent_id": zone.parent_id,
            }
            for zone_id, zone in graph.zones.items()
        },
    }


def dfd_result_to_sidecar_dict(result: BusinessContextDfdResult) -> Dict[str, Any]:
    """Return the JSON-serializable sidecar payload for generated DFDs."""
    return {
        "summary": result.summary,
        "graph": graph_to_native_ir_dict(result.graph),
        "assumptions": result.assumptions,
        "clarifying_questions": result.clarifying_questions,
        "element_confidence": result.element_confidence,
        "import_metrics": {
            "total_lines": result.metrics.total_lines,
            "edge_candidates": result.metrics.edge_candidates,
            "edges_parsed": result.metrics.edges_parsed,
            "node_label_candidates": result.metrics.node_label_candidates,
            "node_labels_parsed": result.metrics.node_labels_parsed,
            "import_success_rate": result.metrics.import_success_rate,
        },
    }


def dfd_result_to_sidecar_json(result: BusinessContextDfdResult) -> str:
    return json.dumps(dfd_result_to_sidecar_dict(result), ensure_ascii=False, indent=2)


def _parse_zones(
    zones_payload: Dict[str, Any], confidence_out: Dict[str, str]
) -> Dict[str, Zone]:
    zones: Dict[str, Zone] = {}
    for zone_key, zone_value in zones_payload.items():
        if not isinstance(zone_value, dict):
            continue
        zone_id = str(zone_value.get("id") or zone_key).strip()
        zone_name = str(zone_value.get("name") or zone_id).strip()
        if not zone_id or not zone_name:
            continue
        parent_id = _strip_optional_str(zone_value.get("parent_id"))
        confidence = _confidence(zone_value.get("confidence"))
        confidence_out[zone_id] = confidence
        zones[zone_id] = Zone(id=zone_id, name=zone_name, parent_id=parent_id)

    for zone in zones.values():
        if zone.parent_id not in zones:
            zone.parent_id = None
    return zones


def _parse_nodes(
    nodes_payload: Dict[str, Any],
    zones: Dict[str, Zone],
    confidence_out: Dict[str, str],
) -> Dict[str, Node]:
    nodes: Dict[str, Node] = {}
    for node_key, node_value in nodes_payload.items():
        if not isinstance(node_value, dict):
            continue
        node_id = str(node_value.get("id") or node_key).strip()
        label = str(node_value.get("label") or node_id).strip()
        if not node_id or not label:
            continue

        zone_ids = _string_list(node_value.get("zones"))
        if zones:
            zone_ids = [zone_id for zone_id in zone_ids if zone_id in zones]
            zone_ids = sort_zone_ids_by_hierarchy(zone_ids, zones)
        zone = _strip_optional_str(node_value.get("zone"))
        if zones and zone_ids:
            zone = representative_zone_name(zone_ids, zones) or zone

        confidence_out[node_id] = _confidence(node_value.get("confidence"))
        nodes[node_id] = Node(
            id=node_id,
            label=label,
            zone=zone,
            zones=zone_ids,
            type=_strip_optional_str(node_value.get("type")),
            data=_string_list(node_value.get("data")),
            auth=_optional_bool(node_value.get("auth")),
            notes=_strip_optional_str(node_value.get("notes")),
        )
    return nodes


def _parse_edges(
    edges_payload: Any,
    nodes: Dict[str, Node],
    confidence_out: Dict[str, str],
) -> List[Edge]:
    if not isinstance(edges_payload, list):
        return []
    edges: List[Edge] = []
    for edge_value in edges_payload:
        if not isinstance(edge_value, dict):
            continue
        src = str(edge_value.get("src") or "").strip()
        dst = str(edge_value.get("dst") or "").strip()
        if not src or not dst or src not in nodes or dst not in nodes:
            continue
        edge = Edge(
            src=src,
            dst=dst,
            label=_strip_optional_str(edge_value.get("label")),
            protocol=_strip_optional_str(edge_value.get("protocol")),
            data=_string_list(edge_value.get("data")),
            id=_strip_optional_str(edge_value.get("id")),
        )
        edges.append(edge)
        confidence_out[_edge_key(edge)] = _confidence(edge_value.get("confidence"))
    return edges


def _dict_payload(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        result: Dict[str, Any] = {}
        for item in value:
            if isinstance(item, dict):
                item_id = str(item.get("id") or item.get("name") or "").strip()
                if item_id:
                    result[item_id] = item
        return result
    return {}


def _string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _strip_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _confidence(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in CONFIDENCE_VALUES:
        return text
    return "assumed"


def _edge_key(edge: Edge) -> str:
    if edge.id:
        return edge.id
    label = f":{edge.label}" if edge.label else ""
    return f"{edge.src}->{edge.dst}{label}"
