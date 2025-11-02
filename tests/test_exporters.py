"""
Tests for exporters module
"""

import os
import sys
import tempfile
import json

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from exporters import export_json, export_md, diff_reports
from models import Threat, ImportMetrics


class TestExportJson:
    """Test cases for export_json function"""

    def test_export_empty_threats_list(self):
        """Test exporting empty threats list"""
        threats = []

        result = export_json(threats, None)

        data = json.loads(result)
        assert data["count"] == 0
        assert data["threats"] == []
        assert "generated_at" in data
        assert data["generated_at"].endswith("Z")

    def test_export_single_threat(self):
        """Test exporting single threat"""
        threat = Threat(
            id="T001",
            title="SQL Injection",
            stride=["T", "I"],
            severity="High",
            score=8.5,
            affected=["Database", "API"],
            why="Input validation missing",
            references=["ASVS V5.1.1", "CWE-89"],
            evidence_nodes=["DB", "API"],
            evidence_edges=["API->DB"],
            confidence=0.9,
        )
        threats = [threat]

        result = export_json(threats, None)

        data = json.loads(result)
        assert data["count"] == 1
        assert len(data["threats"]) == 1
        threat_data = data["threats"][0]
        assert threat_data["id"] == "T001"
        assert threat_data["title"] == "SQL Injection"
        assert threat_data["stride"] == ["T", "I"]
        assert threat_data["severity"] == "High"
        assert threat_data["score"] == 8.5
        assert threat_data["confidence"] == 0.9

    def test_export_with_metrics(self):
        """Test exporting with import metrics"""
        threats = []
        metrics = ImportMetrics(
            total_lines=10,
            edge_candidates=5,
            edges_parsed=4,
            node_label_candidates=3,
            node_labels_parsed=2,
        )

        result = export_json(threats, None, metrics)

        data = json.loads(result)
        assert "import_metrics" in data
        assert data["import_metrics"]["total_lines"] == 10
        assert data["import_metrics"]["edges_parsed"] == 4
        assert data["import_metrics"]["import_success_rate"] == 0.75  # (4+2)/(5+3)

    def test_export_to_file(self):
        """Test exporting to file"""
        threats = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            result = export_json(threats, temp_path)

            # Check file was created
            assert os.path.exists(temp_path)

            # Check file content
            with open(temp_path, "r", encoding="utf-8") as f:
                file_data = json.load(f)

            result_data = json.loads(result)
            assert file_data == result_data
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestExportMd:
    """Test cases for export_md function"""

    def test_export_empty_threats_markdown(self):
        """Test exporting empty threats to markdown"""
        threats = []

        result = export_md(threats, None)

        assert "# Threat Thinker Report" in result
        assert "Generated:" in result
        assert "| Severity | Title |" in result  # Table header

    def test_export_single_threat_markdown(self):
        """Test exporting single threat to markdown"""
        threat = Threat(
            id="T001",
            title="XSS Attack",
            stride=["T", "I"],
            severity="Medium",
            score=6.0,
            affected=["Frontend"],
            why="No input sanitization",
            references=["ASVS V5.3.1"],
            evidence_nodes=["WebApp"],
            evidence_edges=["User->WebApp"],
            confidence=0.8,
        )
        threats = [threat]

        result = export_md(threats, None)

        assert "XSS Attack" in result
        assert "Medium" in result
        assert "No input sanitization" in result
        assert "Frontend" in result
        assert "T, I" in result
        assert "6" in result  # Score should be integer

    def test_export_with_metrics_markdown(self):
        """Test exporting with metrics to markdown"""
        threats = []
        metrics = ImportMetrics(
            total_lines=10,
            edge_candidates=8,
            edges_parsed=6,
            node_label_candidates=4,
            node_labels_parsed=3,
        )

        result = export_md(threats, None, metrics)

        assert "Import Success: 75.0%" in result  # (6+3)/(8+4) = 75%
        assert "edges 6/8" in result
        assert "labels 3/4" in result

    def test_markdown_pipe_escaping(self):
        """Test that pipes in content are escaped"""
        threat = Threat(
            id="T001",
            title="Title|with|pipes",
            stride=["T"],
            severity="Low",
            score=3.0,
            affected=["System|A"],
            why="Reason|with|pipes",
            references=["Ref|1"],
            evidence_nodes=["Node|1"],
            evidence_edges=["A|B->C|D"],
        )
        threats = [threat]

        result = export_md(threats, None)

        # Pipes should be replaced with /
        assert "Title/with/pipes" in result
        assert "System/A" in result
        assert "Reason/with/pipes" in result


class TestDiffReports:
    """Test cases for diff_reports function"""

    def test_diff_identical_reports(self):
        """Test diffing identical reports"""
        threat_data = {"threats": [{"id": "T001", "title": "Test Threat"}]}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f1:
            json.dump(threat_data, f1)
            path1 = f1.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f2:
            json.dump(threat_data, f2)
            path2 = f2.name

        try:
            result = diff_reports(path1, path2)

            assert result["count_added"] == 0
            assert result["count_removed"] == 0
            assert result["added"] == []
            assert result["removed"] == []
        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_diff_with_additions_and_removals(self):
        """Test diffing reports with additions and removals"""
        current_data = {
            "threats": [
                {"id": "T001", "title": "Common Threat"},
                {"id": "T002", "title": "New Threat"},
            ]
        }

        baseline_data = {
            "threats": [
                {"id": "T001", "title": "Common Threat"},
                {"id": "T003", "title": "Old Threat"},
            ]
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f1:
            json.dump(current_data, f1)
            current_path = f1.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f2:
            json.dump(baseline_data, f2)
            baseline_path = f2.name

        try:
            result = diff_reports(current_path, baseline_path)

            assert result["count_added"] == 1
            assert result["count_removed"] == 1
            assert len(result["added"]) == 1
            assert len(result["removed"]) == 1
            assert result["added"][0]["id"] == "T002"
            assert result["removed"][0]["id"] == "T003"
        finally:
            os.unlink(current_path)
            os.unlink(baseline_path)

    def test_diff_empty_reports(self):
        """Test diffing empty reports"""
        empty_data = {"threats": []}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f1:
            json.dump(empty_data, f1)
            path1 = f1.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f2:
            json.dump(empty_data, f2)
            path2 = f2.name

        try:
            result = diff_reports(path1, path2)

            assert result["count_added"] == 0
            assert result["count_removed"] == 0
        finally:
            os.unlink(path1)
            os.unlink(path2)
