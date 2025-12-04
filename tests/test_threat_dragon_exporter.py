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
    assert web_cell["data"]["threats"][0]["title"].startswith("[Threat Thinker] ")
    assert (
        web_cell["data"]["threats"][0]["mitigation"] == "Apply strict input validation"
    )
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
    assert flow_cells[0]["data"]["threats"][0]["title"].startswith("[Threat Thinker] ")
    assert flow_cells[0]["data"]["hasOpenThreats"] is True

    diagram_threats = diagram.get("threats") or []
    assert any(
        t.get("id") == "T003" and t.get("title", "").startswith("[Threat Thinker] ")
        for t in diagram_threats
    )

    # Position for a downstream component should remain identical to the source layout
    assert cells[api_id]["position"] == original_cells[api_id]["position"]


def test_export_threat_dragon_merges_existing_threats(tmp_path):
    fixture_data = json.loads(FIXTURE_PATH.read_text())
    diagram = fixture_data["detail"]["diagrams"][0]

    user_id = "9e76689c-634c-4824-9081-322a67f286d3"
    web_id = "36d4beb4-5c74-47ab-943e-4d0920e7be74"

    existing_cell_threat = {
        "id": "EXIST-1",
        "title": "Existing TD threat",
        "type": "T",
        "status": "Open",
        "severity": "Medium",
        "description": "Legacy Threat Dragon entry",
        "mitigation": "",
        "references": [],
        "score": 4.0,
        "affected": ["Web"],
        "confidence": 0.5,
    }
    for cell in diagram["cells"]:
        if cell.get("id") == web_id:
            cell.setdefault("data", {})["threats"] = [existing_cell_threat]
            cell["data"]["hasOpenThreats"] = True
            break

    diagram["threats"] = [
        {
            "id": "EXIST-D",
            "title": "Legacy diagram threat",
            "type": "I",
            "status": "Mitigated",
            "severity": "Low",
            "description": "Existing diagram-level threat",
            "mitigation": "",
            "references": [],
            "score": 1.0,
            "affected": [],
            "confidence": 0.4,
        }
    ]

    tmp_file = tmp_path / "td_with_existing_threats.json"
    tmp_file.write_text(json.dumps(fixture_data))
    graph, _ = parse_threat_dragon(str(tmp_file))

    threats = [
        Threat(
            id="EXIST-1",
            title="New web threat",
            stride=["T"],
            severity="High",
            score=7.0,
            affected=["Web"],
            why="Threat Thinker suggestion",
            references=[],
            recommended_action="Harden web",
            evidence_nodes=[web_id],
            evidence_edges=[],
        ),
        Threat(
            id="EXIST-D",
            title="New diagram threat",
            stride=["I"],
            severity="Medium",
            score=5.0,
            affected=[],
            why="Diagram level gap",
            references=[],
            recommended_action="Document controls",
            evidence_nodes=[],
            evidence_edges=[],
        ),
    ]

    output = export_threat_dragon(threats, graph, None)
    data = json.loads(output)
    diagram_out = (data.get("detail") or {}).get("diagrams", [])[0]
    cells = {
        cell["id"]: cell
        for cell in diagram_out.get("cells", [])
        if isinstance(cell, dict) and cell.get("id")
    }

    web_cell = cells[web_id]
    cell_titles = [t.get("title") for t in web_cell["data"]["threats"]]
    cell_ids = [t.get("id") for t in web_cell["data"]["threats"]]
    assert "Existing TD threat" in cell_titles
    assert any(title.startswith("[Threat Thinker] ") for title in cell_titles)
    assert len(set(cell_ids)) == len(cell_ids)
    assert "EXIST-1" in cell_ids
    assert any(id_.startswith("EXIST-1-tt") for id_ in cell_ids if id_ != "EXIST-1")
    assert web_cell["data"]["hasOpenThreats"] is True

    diagram_titles = [t.get("title") for t in diagram_out.get("threats", [])]
    diagram_ids = [t.get("id") for t in diagram_out.get("threats", [])]
    assert "Legacy diagram threat" in diagram_titles
    assert any(title.startswith("[Threat Thinker] ") for title in diagram_titles)
    assert len(set(diagram_ids)) == len(diagram_ids)
    assert "EXIST-D" in diagram_ids
    assert any(id_.startswith("EXIST-D-tt") for id_ in diagram_ids if id_ != "EXIST-D")


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
