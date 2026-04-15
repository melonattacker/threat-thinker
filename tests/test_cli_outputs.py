import os
import sys
from pathlib import Path
from types import SimpleNamespace

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import threat_thinker.main as cli
from threat_thinker.main import (
    _prepare_diff_output_paths,
    _prepare_output_paths,
    _select_think_input,
)
from threat_thinker.input_loader import INPUT_FORMAT_IR, INPUT_FORMAT_THREAT_DRAGON


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


def test_version_command_prints_installed_version(monkeypatch, capsys):
    monkeypatch.setattr(cli, "get_threat_thinker_version", lambda: "9.8.7")
    monkeypatch.setattr(sys, "argv", ["threat-thinker", "version"])

    cli.main()

    captured = capsys.readouterr()
    assert captured.out == "9.8.7 (Threat Thinker)\n"
    assert captured.err == ""


def test_version_flags_print_installed_version(monkeypatch, capsys):
    monkeypatch.setattr(cli, "get_threat_thinker_version", lambda: "9.8.7")

    for version_flag in ("-v", "--version", "--verison"):
        monkeypatch.setattr(sys, "argv", ["threat-thinker", version_flag])
        try:
            cli.main()
        except SystemExit as exc:
            assert exc.code == 0

        captured = capsys.readouterr()
        assert captured.out == "9.8.7 (Threat Thinker)\n"
        assert captured.err == ""


def test_get_threat_thinker_version_uses_package_metadata(monkeypatch):
    monkeypatch.setattr(cli, "package_version", lambda package_name: "1.2.3")

    assert cli.get_threat_thinker_version() == "1.2.3"


def test_get_threat_thinker_version_falls_back_to_pyproject(monkeypatch):
    def _raise_package_not_found(package_name: str):
        raise cli.PackageNotFoundError(package_name)

    monkeypatch.setattr(cli, "package_version", _raise_package_not_found)
    monkeypatch.setattr(cli, "_read_pyproject_version", lambda: "4.5.6")

    assert cli.get_threat_thinker_version() == "4.5.6"


def test_select_think_input_supports_ir():
    args = SimpleNamespace(
        diagram=None,
        mermaid=None,
        drawio=None,
        threat_dragon=None,
        image=None,
        ir="graphs/system.ir.json",
    )

    diagram_file, diagram_format = _select_think_input(args)

    assert diagram_file == "graphs/system.ir.json"
    assert diagram_format == INPUT_FORMAT_IR


def test_select_think_input_keeps_json_autodetect_as_threat_dragon():
    fixture_path = Path(__file__).parent / "fixtures" / "threat_dragon_simple.json"
    args = SimpleNamespace(
        diagram=str(fixture_path),
        mermaid=None,
        drawio=None,
        threat_dragon=None,
        image=None,
        ir=None,
    )

    diagram_file, diagram_format = _select_think_input(args)

    assert diagram_file == str(fixture_path)
    assert diagram_format == INPUT_FORMAT_THREAT_DRAGON
