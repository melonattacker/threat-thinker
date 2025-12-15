"""
Tests for threat_analyzer module
"""

import os
import sys
import json

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_thinker.threat_analyzer import graph_to_prompt, denoise_threats
from threat_thinker.models import Graph, Node, Edge, Threat


class TestGraphToPrompt:
    """Test cases for graph_to_prompt function"""

    def test_empty_graph_to_prompt(self):
        """Test converting empty graph to prompt"""
        graph = Graph()

        result = graph_to_prompt(graph)

        data = json.loads(result)
        assert data["nodes"] == []
        assert data["edges"] == []

    def test_simple_graph_to_prompt(self):
        """Test converting simple graph to prompt"""
        graph = Graph()
        node_a = Node(id="A", label="User", zone="external", type="actor")
        node_b = Node(id="B", label="API", zone="dmz", type="service", data=["PII"])
        graph.nodes["A"] = node_a
        graph.nodes["B"] = node_b

        edge = Edge(
            src="A",
            dst="B",
            label="HTTP Request",
            protocol="HTTPS",
            data=["Credentials"],
        )
        graph.edges.append(edge)

        result = graph_to_prompt(graph)

        data = json.loads(result)
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1

        # Check node data
        node_data = {n["id"]: n for n in data["nodes"]}
        assert node_data["A"]["label"] == "User"
        assert node_data["A"]["zone"] == "external"
        assert node_data["A"]["type"] == "actor"
        assert node_data["B"]["data"] == ["PII"]

        # Check edge data
        edge_data = data["edges"][0]
        assert edge_data["src"] == "A"
        assert edge_data["dst"] == "B"
        assert edge_data["label"] == "HTTP Request"
        assert edge_data["protocol"] == "HTTPS"
        assert edge_data["data"] == ["Credentials"]

    def test_graph_with_none_values_to_prompt(self):
        """Test converting graph with None values to prompt"""
        graph = Graph()
        node = Node(id="A", label="Test", zone=None, type=None, auth=None, notes=None)
        graph.nodes["A"] = node

        edge = Edge(src="A", dst="A", label=None, protocol=None)
        graph.edges.append(edge)

        result = graph_to_prompt(graph)

        data = json.loads(result)
        assert len(data["nodes"]) == 1
        assert len(data["edges"]) == 1

        # Should handle None values properly
        node_data = data["nodes"][0]
        assert node_data["zone"] is None
        assert node_data["type"] is None

        edge_data = data["edges"][0]
        assert edge_data["label"] is None
        assert edge_data["protocol"] is None


class TestDenoiseThreats:
    """Test cases for denoise_threats function"""

    def test_denoise_empty_threats(self):
        """Test denoising empty threats list"""
        threats = []

        result = denoise_threats(threats)

        assert result == []

    def test_denoise_require_asvs_filter(self):
        """Test filtering threats requiring ASVS references"""
        threat_with_asvs = Threat(
            id="T001",
            title="Valid Threat",
            stride=["T"],
            severity="High",
            score=8.0,
            affected=["API"],
            why="Input validation missing",
            references=["ASVS V5.1.1", "CWE-89"],
            recommended_action="Test recommended action",
            evidence_nodes=["API"],
            confidence=0.9,
        )

        threat_without_asvs = Threat(
            id="T002",
            title="Invalid Threat",
            stride=["I"],
            severity="Medium",
            score=6.0,
            affected=["DB"],
            why="No encryption",
            references=["CWE-319"],
            recommended_action="Test recommended action",
            evidence_nodes=["DB"],
            confidence=0.8,
        )

        threats = [threat_with_asvs, threat_without_asvs]

        # Test with require_asvs=True (default)
        result = denoise_threats(threats, require_asvs=True)
        assert len(result) == 1
        assert result[0].id == "T001"

        # Test with require_asvs=False
        result = denoise_threats(threats, require_asvs=False)
        assert len(result) == 2

    def test_denoise_confidence_filter(self):
        """Test filtering threats by confidence threshold"""
        high_confidence = Threat(
            id="T001",
            title="High Confidence Threat",
            stride=["T"],
            severity="High",
            score=8.0,
            affected=["API"],
            why="Input validation missing",
            references=["ASVS V5.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["API"],
            confidence=0.9,
        )

        low_confidence = Threat(
            id="T002",
            title="Low Confidence Threat",
            stride=["I"],
            severity="Medium",
            score=6.0,
            affected=["DB"],
            why="No encryption",
            references=["ASVS V2.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["DB"],
            confidence=0.3,
        )

        none_confidence = Threat(
            id="T003",
            title="None Confidence Threat",
            stride=["D"],
            severity="Low",
            score=4.0,
            affected=["Cache"],
            why="Data exposure",
            references=["ASVS V1.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["Cache"],
            confidence=None,
        )

        threats = [high_confidence, low_confidence, none_confidence]

        # Test with min_confidence=0.5
        result = denoise_threats(threats, min_confidence=0.5)
        assert len(result) == 2  # High confidence + None confidence (None passes)
        threat_titles = {t.title for t in result}
        assert "High Confidence Threat" in threat_titles
        assert "None Confidence Threat" in threat_titles

    def test_denoise_evidence_filter(self):
        """Test filtering threats requiring evidence"""
        with_evidence = Threat(
            id="T001",
            title="Threat with Evidence",
            stride=["T"],
            severity="High",
            score=8.0,
            affected=["API"],
            why="Input validation missing",
            references=["ASVS V5.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["API"],
            confidence=0.9,
        )

        without_evidence = Threat(
            id="T002",
            title="Threat without Evidence",
            stride=["I"],
            severity="Medium",
            score=6.0,
            affected=["DB"],
            why="No encryption",
            references=["ASVS V2.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=[],
            evidence_edges=[],
            confidence=0.8,
        )

        threats = [with_evidence, without_evidence]

        result = denoise_threats(threats)
        assert len(result) == 1
        assert result[0].id == "T001"

    def test_denoise_why_field_filter(self):
        """Test filtering threats with too short 'why' field"""
        valid_why = Threat(
            id="T001",
            title="Valid Why",
            stride=["T"],
            severity="High",
            score=8.0,
            affected=["API"],
            why="Input validation is missing from user input fields",
            references=["ASVS V5.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["API"],
            confidence=0.9,
        )

        short_why = Threat(
            id="T002",
            title="Short Why",
            stride=["I"],
            severity="Medium",
            score=6.0,
            affected=["DB"],
            why="Bad",  # Too short (< 6 chars)
            references=["ASVS V2.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["DB"],
            confidence=0.8,
        )

        threats = [valid_why, short_why]

        result = denoise_threats(threats)
        assert len(result) == 1
        assert result[0].id == "T001"

    def test_denoise_sorting(self):
        """Test sorting by score, severity, title"""
        threat_high_score = Threat(
            id="T001",
            title="B_Threat",
            stride=["T"],
            severity="Medium",
            score=9.0,
            affected=["API"],
            why="High score threat",
            references=["ASVS V5.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["API"],
            confidence=0.9,
        )

        threat_medium_score = Threat(
            id="T002",
            title="A_Threat",
            stride=["I"],
            severity="High",
            score=7.0,
            affected=["DB"],
            why="Medium score threat",
            references=["ASVS V2.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["DB"],
            confidence=0.8,
        )

        threat_same_score_1 = Threat(
            id="T003",
            title="Z_Title",
            stride=["D"],
            severity="Low",
            score=5.0,
            affected=["Cache"],
            why="Same score threat 1",
            references=["ASVS V1.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["Cache"],
            confidence=0.7,
        )

        threat_same_score_2 = Threat(
            id="T004",
            title="A_Title",
            stride=["S"],
            severity="Low",
            score=5.0,
            affected=["Queue"],
            why="Same score threat 2",
            references=["ASVS V1.2.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["Queue"],
            confidence=0.6,
        )

        threats = [
            threat_medium_score,
            threat_high_score,
            threat_same_score_1,
            threat_same_score_2,
        ]

        result = denoise_threats(threats)

        # Should be sorted by: score desc, then severity, then title
        assert len(result) == 4
        assert result[0].title == "B_Threat"  # Highest score (9.0)
        assert result[1].title == "A_Threat"  # Second highest score (7.0)
        # For same score (5.0), sorted by severity then title
        assert result[2].title == "A_Title"  # Low severity, A_Title
        assert result[3].title == "Z_Title"  # Low severity, Z_Title

    def test_denoise_topn_limit(self):
        """Test limiting results with topn parameter"""
        threats = []
        for i in range(5):
            threat = Threat(
                id=f"T{i:03d}",
                title=f"Threat {i}",
                stride=["T"],
                severity="Medium",
                score=float(i),
                affected=[f"System{i}"],
                why=f"Threat reason {i}",
                references=["ASVS V1.1.1"],
                recommended_action="Test recommended action",
                evidence_nodes=[f"Node{i}"],
                confidence=0.8,
            )
            threats.append(threat)

        result = denoise_threats(threats, topn=3)
        assert len(result) == 3
        # Should be top 3 by score (descending)
        assert result[0].score == 4.0
        assert result[1].score == 3.0
        assert result[2].score == 2.0

    def test_denoise_duplicate_merging(self):
        """Test merging near-duplicate threats"""
        threat1 = Threat(
            id="T001",
            title="SQL Injection",
            stride=["T"],
            severity="High",
            score=8.0,
            affected=["API"],
            why="Input validation missing",
            references=["ASVS V5.1.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["API", "DB"],
            evidence_edges=["API->DB"],
            confidence=0.9,
        )

        # Duplicate with same title and evidence
        threat2 = Threat(
            id="T002",
            title="sql injection",  # Different case
            stride=["T", "I"],
            severity="High",
            score=7.5,
            affected=["Database"],
            why="No input validation",
            references=["ASVS V5.1.2"],
            recommended_action="Test recommended action",
            evidence_nodes=["DB", "API"],  # Different order
            evidence_edges=["API->DB"],
            confidence=0.8,
        )

        # Different threat
        threat3 = Threat(
            id="T003",
            title="XSS Attack",
            stride=["T"],
            severity="Medium",
            score=6.0,
            affected=["Frontend"],
            why="No output encoding",
            references=["ASVS V5.3.1"],
            recommended_action="Test recommended action",
            evidence_nodes=["WebApp"],
            evidence_edges=[],
            confidence=0.7,
        )

        threats = [threat1, threat2, threat3]

        result = denoise_threats(threats)

        # Should merge duplicates, keeping only SQL Injection and XSS Attack
        assert len(result) == 2
        threat_titles = {t.title for t in result}
        assert "SQL Injection" in threat_titles  # Higher score, kept
        assert "XSS Attack" in threat_titles
        # sql injection (lowercase) should be merged with SQL Injection
