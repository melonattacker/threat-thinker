import gradio as gr
import pytest
from types import SimpleNamespace

import threat_thinker.webui as webui


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


def test_validate_text_input_format_supports_ir():
    assert webui._validate_text_input_format("ir") == "ir"
    with pytest.raises(gr.Error):
        webui._validate_text_input_format("unknown")


def test_translate_lookup_returns_expected_copy():
    assert webui._t("en", "system_description_label") == "System Description"
    assert webui._t("ja", "system_description_label") == "システム説明"


def test_output_language_sync_respects_manual_override():
    assert webui._sync_output_language_with_locale("ja", "en", False) == ("ja", False)
    assert webui._sync_output_language_with_locale("ja", "fr", True) == ("fr", True)
    assert webui._output_language_is_manual("fr", "en") is True
    assert webui._output_language_is_manual("en", "en") is False


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


def test_normalize_context_uploads_accepts_supported_files(tmp_path):
    context = tmp_path / "scope.md"
    context.write_text("business context", encoding="utf-8")

    assert webui._normalize_context_uploads([str(context)]) == [str(context)]


def test_normalize_context_uploads_rejects_unsupported(tmp_path):
    unsupported = tmp_path / "scope.csv"
    unsupported.write_text("bad", encoding="utf-8")

    with pytest.raises(gr.Error):
        webui._normalize_context_uploads([str(unsupported)])


def test_delete_kb(tmp_path, monkeypatch):
    monkeypatch.setenv("THREAT_THINKER_KB_ROOT", str(tmp_path))
    kb_dir = tmp_path / "kb-del"
    kb_dir.mkdir(parents=True, exist_ok=True)
    # create minimal meta to appear in listings
    (kb_dir / "meta.json").write_text("{}", encoding="utf-8")

    status, _, _, _ = webui._delete_kb("kb-del", "ja")

    assert "削除しました" in status
    assert not kb_dir.exists()


def test_build_webui_smoke():
    demo = webui._build_webui()

    assert isinstance(demo, gr.Blocks)
    assert demo.title == "Threat Thinker WebUI"
    assert len(demo.blocks) > 0


def test_build_webui_has_system_description_entrypoint():
    demo = webui._build_webui()
    labels = {
        getattr(block, "label", None)
        for block in demo.blocks.values()
        if getattr(block, "label", None)
    }

    assert "System Description" in labels
    assert "Business Context (supplemental PDF, Markdown, Text)" in labels
    assert "Diagram Content" in labels
    assert "Download generated DFD JSON (description inputs only)" in labels


def test_build_webui_supports_japanese_initial_locale():
    demo = webui._build_webui("ja")
    labels = {
        getattr(block, "label", None)
        for block in demo.blocks.values()
        if getattr(block, "label", None)
    }

    assert "システム説明" in labels
    assert "図の内容" in labels
    assert "生成された DFD JSON をダウンロード（説明入力時のみ）" in labels


def test_build_incomplete_dfd_markdown_localizes():
    result = SimpleNamespace(
        summary="Summary text",
        assumptions=["Assumption A"],
        clarifying_questions=["Question A"],
    )

    markdown = webui._build_incomplete_dfd_markdown(result, "ja")

    assert "システム説明の詳細が不足しています" in markdown
    assert "前提" in markdown
    assert "確認したい点" in markdown


def test_localize_webui_updates_labels_and_preserves_manual_output_language():
    updates = webui._localize_webui(
        "ja",
        webui._INPUT_METHOD_TEXT,
        "en",
        False,
        "fr",
        True,
        [],
        None,
        webui._t("en", "report_preview_default"),
        webui._t("en", "kb_status_default"),
        webui._t("en", "diff_report_preview_default"),
    )

    assert updates[0] == "ja"
    assert updates[1] is False
    assert updates[2] is True
    assert updates[7]["label"] == "システム説明"
    assert updates[10]["choices"][0][0] == "テキスト"
    assert updates[24]["value"] == "ja"
    assert (
        updates[38]["value"]
        == "レポートを生成すると、ここにプレビューが表示されます..."
    )
    assert (
        updates[53]["value"]
        == "文書をアップロードし、構築をクリックしてナレッジベースを作成してください。"
    )
    assert updates[66]["value"] == "fr"


def test_kb_list_markdown_localizes(monkeypatch, tmp_path):
    monkeypatch.setattr(
        webui,
        "list_kbs",
        lambda: [
            {
                "name": "secure-web",
                "updated_at": "2026-04-29",
                "num_chunks": 12,
                "num_documents": 3,
                "embedding_model": "text-embedding-3-small",
            }
        ],
    )
    monkeypatch.setattr(webui, "get_kb_root", lambda: tmp_path)

    markdown = webui._kb_list_markdown("ja")

    assert "利用可能なナレッジベース" in markdown
    assert "3 件の文書から 12 チャンク" in markdown
    assert "保存先" in markdown


def test_build_kb_from_uploads_localizes_missing_openai_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(gr.Error, match="OPENAI_API_KEY"):
        webui._build_kb_from_uploads(
            "kb1",
            [],
            f"openai:{webui.DEFAULT_EMBED_MODEL}",
            webui.DEFAULT_CHUNK_TOKENS,
            webui.DEFAULT_CHUNK_OVERLAP,
            True,
            "ja",
        )


def test_generate_diff_report_localizes_missing_files():
    with pytest.raises(gr.Error, match="JSON ファイル"):
        webui._generate_diff_report(
            "",
            "",
            "openai",
            "gpt-4.1",
            "",
            "",
            "",
            "ja",
            "ja",
        )


def test_generate_report_returns_clarifying_questions_for_empty_dfd(monkeypatch):
    monkeypatch.setattr(
        webui,
        "llm_generate_dfd_from_description",
        lambda *args, **kwargs: {
            "summary": "A drone delivery service.",
            "graph": {"nodes": {}, "edges": [], "zones": {}},
            "assumptions": ["The service has a backend API."],
            "clarifying_questions": [
                "Who places orders?",
                "How are payments processed?",
            ],
        },
    )

    markdown_report, report_text, md_path, json_path, html_path, td_path, dfd_path = (
        webui._generate_report(
            system_description="Drone food delivery.",
            context_files=[],
            input_method=webui._INPUT_METHOD_TEXT,
            diagram_text="",
            diagram_format="mermaid",
            drawio_page="",
            image_file="",
            infer_hints=False,
            llm_api="openai",
            llm_model="gpt-4.1",
            aws_profile="",
            aws_region="",
            ollama_host="",
            topn=10,
            min_confidence=0.5,
            require_asvs=False,
            lang="en",
            use_rag=False,
            kb_names=[],
            rag_topk=5,
            rag_strategy=webui.DEFAULT_RAG_STRATEGY,
            rag_reranker=webui.DEFAULT_RAG_RERANKER,
            rag_candidates=webui.DEFAULT_RAG_CANDIDATES,
            rag_min_score=webui.DEFAULT_RAG_MIN_SCORE,
            prompt_token_limit=1000,
            ui_locale="ja",
        )
    )

    assert "システム説明の詳細が不足しています" in markdown_report
    assert "確認したい点" in markdown_report
    assert "Who places orders?" in report_text
    assert "生成された DFD が空のため、脅威推論をスキップしました" in report_text
    assert md_path is None
    assert json_path is None
    assert html_path is None
    assert td_path is None
    assert dfd_path is not None
