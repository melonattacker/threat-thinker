import json
import os
import sys
import tempfile
from pathlib import Path

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_thinker.parsers.threat_dragon_parser import (
    is_threat_dragon_json,
    parse_threat_dragon,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "threat_dragon_simple.json"
BOUNDARY_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "threat_dragon_boundaries_nested.json"
)


def test_is_threat_dragon_json_detects_valid_file():
    assert is_threat_dragon_json(str(FIXTURE_PATH)) is True


def test_is_threat_dragon_json_rejects_non_td_json():
    payload = {"version": "1.0.0", "detail": {}}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(payload, tmp)
        tmp_path = tmp.name
    try:
        assert is_threat_dragon_json(tmp_path) is False
    finally:
        os.unlink(tmp_path)


def test_parse_threat_dragon_basic_graph():
    graph, metrics = parse_threat_dragon(str(FIXTURE_PATH))

    expected_nodes = {
        "9e76689c-634c-4824-9081-322a67f286d3",  # actor
        "36d4beb4-5c74-47ab-943e-4d0920e7be74",  # web server
        "d1566b36-6b0a-41c7-b9e0-95fb5a94fdce",  # database
        "e009a87e-6da5-489b-a0f5-a48ecf8a6465",  # api service
    }
    assert set(graph.nodes.keys()) == expected_nodes
    assert graph.nodes["9e76689c-634c-4824-9081-322a67f286d3"].label == "User"
    assert graph.nodes["9e76689c-634c-4824-9081-322a67f286d3"].type == "actor"
    assert graph.nodes["36d4beb4-5c74-47ab-943e-4d0920e7be74"].type == "process"
    assert graph.nodes["d1566b36-6b0a-41c7-b9e0-95fb5a94fdce"].type == "store"

    assert len(graph.edges) == 2
    flow_labels = {(edge.src, edge.dst): edge for edge in graph.edges}
    assert (
        "9e76689c-634c-4824-9081-322a67f286d3",
        "36d4beb4-5c74-47ab-943e-4d0920e7be74",
    ) in flow_labels
    assert (
        "36d4beb4-5c74-47ab-943e-4d0920e7be74",
        "e009a87e-6da5-489b-a0f5-a48ecf8a6465",
    ) in flow_labels

    user_http = flow_labels[
        ("9e76689c-634c-4824-9081-322a67f286d3", "36d4beb4-5c74-47ab-943e-4d0920e7be74")
    ]
    assert user_http.label == "HTTP Request"
    assert user_http.protocol is None
    assert user_http.data == []

    api_http = flow_labels[
        ("36d4beb4-5c74-47ab-943e-4d0920e7be74", "e009a87e-6da5-489b-a0f5-a48ecf8a6465")
    ]
    assert api_http.label == "HTTP Request"
    assert api_http.protocol is None
    assert api_http.data == []

    assert metrics.node_labels_parsed == 4
    assert metrics.node_label_candidates == 4
    assert metrics.edge_candidates == 3
    assert metrics.edges_parsed == 2

    # trust boundary detection
    assert graph.nodes["9e76689c-634c-4824-9081-322a67f286d3"].zone == "Internet"
    assert graph.nodes["36d4beb4-5c74-47ab-943e-4d0920e7be74"].zone == "DMZ"
    assert graph.nodes["d1566b36-6b0a-41c7-b9e0-95fb5a94fdce"].zone == "Internal"
    assert graph.nodes["e009a87e-6da5-489b-a0f5-a48ecf8a6465"].zone == "Internal"
    # Zone paths should be ordered outer->inner when applicable
    internal_zone_ids = {zid for zid, z in graph.zones.items() if z.name == "Internal"}
    assert graph.nodes["d1566b36-6b0a-41c7-b9e0-95fb5a94fdce"].zones
    assert graph.nodes["e009a87e-6da5-489b-a0f5-a48ecf8a6465"].zones
    assert (
        set(graph.nodes["e009a87e-6da5-489b-a0f5-a48ecf8a6465"].zones)
        & internal_zone_ids
    )

    assert graph.source_format == "threat-dragon"
    assert graph.threat_dragon is not None
    assert "36d4beb4-5c74-47ab-943e-4d0920e7be74" in graph.threat_dragon.cells_by_id


def test_parse_threat_dragon_nested_boundaries():
    graph, metrics = parse_threat_dragon(str(BOUNDARY_FIXTURE_PATH))

    assert set(graph.nodes.keys()) == {
        "service-inside-both",
        "edge-gateway",
        "external-caller",
    }
    assert metrics.node_labels_parsed == 3

    inside = graph.nodes["service-inside-both"]
    assert inside.zone == "Inner"
    assert inside.zones == ["outer-boundary", "inner-boundary"]

    outer_only = graph.nodes["edge-gateway"]
    assert outer_only.zone == "Outer"
    assert outer_only.zones == ["outer-boundary"]

    outside = graph.nodes["external-caller"]
    assert outside.zone is None
    assert outside.zones == []
