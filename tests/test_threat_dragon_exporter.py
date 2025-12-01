import json
import os
import sys
from pathlib import Path

import pytest

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from exporters import export_threat_dragon
from models import Graph, Threat
from parsers.threat_dragon_parser import parse_threat_dragon


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "threat_dragon_simple.json"


def test_export_threat_dragon_maps_threats_and_preserves_layout():
    graph, _ = parse_threat_dragon(str(FIXTURE_PATH))
    fixture_data = json.loads(FIXTURE_PATH.read_text())
    original_cells = {
        cell["id"]: cell
        for cell in fixture_data["detail"]["diagrams"][0]["cells"]
        if isinstance(cell, dict) and cell.get("id")
    }

    user_id = "9e76689c-634c-4824-9081-322a67f286d3"
    web_id = "36d4beb4-5c74-47ab-943e-4d0920e7be74"
    api_id = "e009a87e-6da5-489b-a0f5-a48ecf8a6465"

    threats = [
        Threat(
            id="T001",
            title="Harden web tier",
            stride=["T"],
            severity="High",
            score=8.0,
            affected=["Web"],
            why="Web server exposed to internet",
            references=["ASVS 1.1"],
            recommended_action="Apply strict input validation",
            evidence_nodes=[web_id],
            evidence_edges=[],
            confidence=0.9,
        ),
        Threat(
            id="T002",
            title="Encrypt edge flow",
            stride=["I"],
            severity="Medium",
            score=5.0,
            affected=["User->Web"],
            why="Flow crosses trust boundary without TLS",
            references=[],
            recommended_action="Enforce TLS",
            evidence_nodes=[],
            evidence_edges=[f"{user_id}->{web_id}"],
        ),
        Threat(
            id="T003",
            title="Orphan threat",
            stride=["R"],
            severity="Low",
            score=2.0,
            affected=["API"],
            why="No evidence provided",
            references=[],
            recommended_action="Document mitigation",
            evidence_nodes=[],
            evidence_edges=[],
        ),
    ]

    output = export_threat_dragon(threats, graph, None)
    data = json.loads(output)
    diagram = (data.get("detail") or {}).get("diagrams", [])[0]
    cells = {
        cell["id"]: cell for cell in diagram.get("cells", []) if isinstance(cell, dict)
    }

    web_cell = cells[web_id]
    assert web_cell["data"]["threats"][0]["id"] == "T001"
    assert web_cell["data"]["threats"][0]["mitigation"] == "Apply strict input validation"
    assert web_cell["data"]["hasOpenThreats"] is True
    assert web_cell.get("position") == original_cells[web_id].get("position")

    flow_cells = [
        cell
        for cell in cells.values()
        if (cell.get("data") or {}).get("type") == "tm.Flow"
        and (cell.get("source") or {}).get("cell") == user_id
        and (cell.get("target") or {}).get("cell") == web_id
    ]
    assert flow_cells
    assert flow_cells[0]["data"]["threats"][0]["id"] == "T002"
    assert flow_cells[0]["data"]["hasOpenThreats"] is True

    diagram_threats = diagram.get("threats") or []
    assert any(t.get("id") == "T003" for t in diagram_threats)

    # Position for a downstream component should remain identical to the source layout
    assert cells[api_id]["position"] == original_cells[api_id]["position"]


def test_export_threat_dragon_requires_metadata():
    graph = Graph(source_format="mermaid")
    threat = Threat(
        id="T100",
        title="Test threat",
        stride=["T"],
        severity="Low",
        score=1.0,
        affected=[],
        why="",
        references=[],
        recommended_action="",
        evidence_nodes=[],
        evidence_edges=[],
    )
    with pytest.raises(ValueError):
        export_threat_dragon([threat], graph, None)
