import json
from pathlib import Path

import pytest

from threat_thinker.parsers.ir_parser import IRValidationError, parse_ir


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_graph_ir.json"


def test_parse_ir_valid_fixture():
    graph, metrics = parse_ir(str(FIXTURE_PATH))

    assert graph.source_format == "ir"
    assert list(graph.nodes["db"].zones) == ["internet", "dmz", "private"]
    assert graph.nodes["db"].zone == "Private"
    assert graph.edges[0].id == "edge-1"
    assert metrics.node_labels_parsed == 3
    assert metrics.edges_parsed == 2


def test_parse_ir_rejects_unknown_zone(tmp_path: Path):
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    payload["nodes"]["api"]["zones"] = ["internet", "unknown-zone"]
    bad_path = tmp_path / "bad-ir.json"
    bad_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(IRValidationError, match="unknown zone"):
        parse_ir(str(bad_path))


def test_parse_ir_rejects_dangling_edge(tmp_path: Path):
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    payload["edges"][0]["dst"] = "missing"
    bad_path = tmp_path / "bad-edge-ir.json"
    bad_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(IRValidationError, match="unknown nodes"):
        parse_ir(str(bad_path))


def test_parse_ir_rejects_zone_cycles(tmp_path: Path):
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    payload["zones"]["internet"]["parent_id"] = "private"
    bad_path = tmp_path / "bad-zone-ir.json"
    bad_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(IRValidationError, match="cycle"):
        parse_ir(str(bad_path))


def test_parse_ir_rejects_malformed_json(tmp_path: Path):
    bad_path = tmp_path / "malformed-ir.json"
    bad_path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(IRValidationError, match="Invalid IR JSON"):
        parse_ir(str(bad_path))
