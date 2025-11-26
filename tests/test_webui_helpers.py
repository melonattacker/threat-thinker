import gradio as gr
import pytest

import webui


def test_normalize_embed_model():
    assert (
        webui._normalize_embed_model("openai:text-embedding-3-small")
        == "text-embedding-3-small"
    )
    assert (
        webui._normalize_embed_model("text-embedding-3-large")
        == "text-embedding-3-large"
    )
    assert webui._normalize_embed_model("") == webui.DEFAULT_EMBED_MODEL


def test_validate_kb_name_rejects_invalid():
    with pytest.raises(gr.Error):
        webui._validate_kb_name("")
    with pytest.raises(gr.Error):
        webui._validate_kb_name("../bad")
    assert webui._validate_kb_name("kb-good") == "kb-good"


def test_copy_uploaded_files_to_kb(tmp_path, monkeypatch):
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(tmp_path))
    source_file = tmp_path / "doc.txt"
    source_file.write_text("hello", encoding="utf-8")

    copied = webui._copy_uploaded_files_to_kb("kb1", [str(source_file)], clean_raw=True)

    expected = tmp_path / "kb1" / "raw" / "doc.txt"
    assert copied == [str(expected)]
    assert expected.exists()
    assert expected.read_text(encoding="utf-8") == "hello"


def test_copy_uploaded_files_to_kb_rejects_unsupported(tmp_path, monkeypatch):
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(tmp_path))
    unsupported = tmp_path / "notes.csv"
    unsupported.write_text("bad", encoding="utf-8")

    with pytest.raises(gr.Error):
        webui._copy_uploaded_files_to_kb("kb2", [str(unsupported)], clean_raw=True)


def test_delete_kb(tmp_path, monkeypatch):
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(tmp_path))
    kb_dir = tmp_path / "kb-del"
    kb_dir.mkdir(parents=True, exist_ok=True)
    # create minimal meta to appear in listings
    (kb_dir / "meta.json").write_text("{}", encoding="utf-8")

    status, _, _, _ = webui._delete_kb("kb-del")

    assert "Removed knowledge base" in status
    assert not kb_dir.exists()
