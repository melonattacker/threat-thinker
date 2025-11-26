import os
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from main import _prepare_diff_output_paths, _prepare_output_paths


def test_prepare_output_paths_uses_diagram_stem(tmp_path: Path):
    out_root = tmp_path / "reports"
    out_dir, json_path, md_path, html_path = _prepare_output_paths(
        "diagrams/system.mmd", out_root
    )

    assert out_dir == out_root
    assert json_path.parent == out_root
    assert json_path.name == "system_report.json"
    assert md_path.name == "system_report.md"
    assert html_path.name == "system_report.html"
    assert out_dir.exists()


def test_prepare_output_paths_defaults(tmp_path: Path):
    out_dir, json_path, md_path, html_path = _prepare_output_paths(
        "", tmp_path / "reports2"
    )

    assert out_dir.exists()
    assert json_path.name == "threat_report.json"
    assert md_path.name == "threat_report.md"
    assert html_path.name == "threat_report.html"


def test_prepare_output_paths_with_override(tmp_path: Path):
    out_dir, json_path, md_path, html_path = _prepare_output_paths(
        "diagrams/system.mmd", tmp_path / "reports3", "custom-base"
    )

    assert json_path.name == "custom-base_report.json"
    assert md_path.name == "custom-base_report.md"
    assert html_path.name == "custom-base_report.html"


def test_prepare_diff_output_paths_use_after_stem(tmp_path: Path):
    out_dir, json_path, md_path = _prepare_diff_output_paths(
        "results/new-report.json", tmp_path / "diffs"
    )

    assert out_dir.exists()
    assert json_path.parent == out_dir
    assert json_path.name == "new-report_diff.json"
    assert md_path.name == "new-report_diff.md"
