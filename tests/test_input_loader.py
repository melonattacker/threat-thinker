from pathlib import Path

import threat_thinker.input_loader as loader


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_load_input_dispatches_ir(monkeypatch):
    captured = {}

    def _fake_parse_ir(path):
        captured["path"] = path
        return "graph", "metrics"

    monkeypatch.setattr(loader, "parse_ir", _fake_parse_ir)

    result = loader.load_input(loader.INPUT_FORMAT_IR, "/tmp/system.ir.json")

    assert result == ("graph", "metrics")
    assert captured["path"] == "/tmp/system.ir.json"


def test_detect_input_format_keeps_json_as_threat_dragon():
    fixture_path = FIXTURE_DIR / "threat_dragon_simple.json"

    detected = loader.detect_input_format(str(fixture_path))

    assert detected == loader.INPUT_FORMAT_THREAT_DRAGON


def test_suffix_for_text_input_supports_ir():
    assert loader.suffix_for_text_input(loader.INPUT_FORMAT_IR) == ".json"
