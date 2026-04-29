#!/usr/bin/env python3
"""
Threat Thinker - CLI
"Throw in an architecture diagram, get a prioritized threat list."

Inputs:
- Mermaid file (.mmd/.mermaid)

Outputs:
- Markdown table or JSON with threats (LLM-driven), each with 1-line "why" and ASVS refs (+ evidence IDs).
- Optional diff vs baseline JSON.

Examples:
  export OPENAI_API_KEY=***
    python main.py think --mermaid examples.mmd --infer-hints --llm-api openai --llm-model gpt-4o-mini --out-dir reports/
    python main.py think --drawio examples.drawio --infer-hints --llm-api openai --llm-model gpt-4o-mini --lang ja --out-dir reports/
    python main.py think --image examples/architecture.png --infer-hints --llm-api openai --llm-model gpt-4o --out-dir reports/
    python main.py think --diagram examples/system.xml --infer-hints --llm-api openai --llm-model gpt-4o-mini --lang ko --out-dir reports/
    python main.py think --mermaid examples.mmd --infer-hints --llm-api openai --llm-model gpt-4o-mini --lang zh --out-dir reports/
  export ANTHROPIC_API_KEY=***
    python main.py think --mermaid examples.mmd --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --out-dir reports/
    python main.py think --image examples/system_diagram.jpg --infer-hints --llm-api anthropic --llm-model claude-3-5-sonnet-20241022 --out-dir reports/
    python main.py think --diagram examples/system.xml --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --lang pt --out-dir reports/
    python main.py think --drawio examples.drawio --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --lang ru --out-dir reports/
  For AWS Bedrock:
    # Option 1: Use AWS Profile
    aws configure --profile my-profile
    python main.py think --mermaid examples.mmd --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --aws-profile my-profile --aws-region us-east-1 --out-dir reports/
    python main.py think --image examples/architecture.png --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20241022-v1:0 --aws-profile my-profile --aws-region us-east-1 --out-dir reports/
    python main.py think --drawio examples.drawio --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --aws-profile my-profile --aws-region us-east-1 --lang ar --out-dir reports/
    python main.py think --diagram examples/system.xml --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --aws-profile my-profile --aws-region us-east-1 --lang hi --out-dir reports/
    # Option 2: Use environment variables
    export AWS_ACCESS_KEY_ID=***
    export AWS_SECRET_ACCESS_KEY=***
    export AWS_SESSION_TOKEN=***  # if using temporary credentials
    export AWS_DEFAULT_REGION=us-east-1
    python main.py think --mermaid examples.mmd --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --lang th --out-dir reports/
  python main.py diff --after report.json --before old.json
"""

import argparse
import json
import logging
import os
import sys
import time
import tomllib
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path

from threat_thinker.input_loader import (
    INPUT_FORMAT_DRAWIO,
    INPUT_FORMAT_IMAGE,
    INPUT_FORMAT_IR,
    INPUT_FORMAT_MERMAID,
    INPUT_FORMAT_THREAT_DRAGON,
    detect_input_format,
    load_input,
)
from threat_thinker.business_context import (
    BusinessContextDfdResult,
    dfd_result_from_payload,
    dfd_result_to_sidecar_json,
)
from threat_thinker.hint_processor import merge_llm_hints
from threat_thinker.llm.inference import (
    llm_generate_dfd_from_description,
    llm_infer_hints,
    llm_infer_threats,
    llm_rerank_chunks,
)
from threat_thinker.threat_analyzer import denoise_threats
from threat_thinker.exporters import (
    export_json,
    export_md,
    diff_reports,
    export_diff_md,
    export_html,
    export_threat_dragon,
)
from threat_thinker.cliui import ui, set_locale, set_verbose
from threat_thinker.context_loader import (
    ContextDocumentError,
    context_summary,
    format_context_documents,
    load_context_documents,
)
from threat_thinker.rag import (
    KnowledgeBaseError,
    DEFAULT_CHUNK_OVERLAP,
    DEFAULT_CHUNK_TOKENS,
    DEFAULT_EMBED_MODEL,
    DEFAULT_TOPK,
    DEFAULT_RAG_STRATEGY,
    DEFAULT_RAG_RERANKER,
    DEFAULT_RAG_CANDIDATES,
    DEFAULT_RAG_MIN_SCORE,
    RAG_STRATEGIES,
    RAG_RERANKERS,
    RetrievalOptions,
    build_kb,
    list_kbs,
    search_kb,
    remove_kb,
    retrieve_context_for_graph,
    attach_rag_sources_to_threats,
    get_kb_root,
)
from threat_thinker.serve.api import create_app
from threat_thinker.serve.config import load_config
from threat_thinker.worker.main import run_worker
import threat_thinker.webui as webui
import uvicorn


def _read_pyproject_version() -> str | None:
    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    try:
        with open(pyproject_path, "rb") as f:
            pyproject = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return None

    project = pyproject.get("project")
    if not isinstance(project, dict):
        return None

    version = project.get("version")
    if not isinstance(version, str):
        return None
    return version


def get_threat_thinker_version() -> str:
    try:
        return package_version("threat-thinker")
    except PackageNotFoundError:
        return _read_pyproject_version() or "unknown"


def format_version_output() -> str:
    return f"{get_threat_thinker_version()} (Threat Thinker)"


_DEFAULT_UI_LOCALE = "en"
_MAIN_TEXT = {
    "en": {
        "output_language_help": "Report and CLI output language code (ISO 639-1, e.g., en, ja, fr, de, es, zh, ko, pt, it, ru, ar, hi, th, vi, etc.)",
        "unsupported_diagram_title": "Unsupported diagram file format for {path}",
        "unsupported_diagram_json_detail": "Only Threat Dragon v2 JSON files are accepted for --diagram JSON inputs. Use --ir for native IR JSON.",
        "unsupported_diagram_detail": "Supported: Mermaid (.mmd/.mermaid), Draw.io (.drawio/.xml), Threat Dragon JSON (.json), or images (.jpg/.jpeg/.png/.gif/.bmp/.webp). Use --ir for native IR JSON.",
        "loaded_documents": "Loaded {count} {label} document(s), approximately {tokens} tokens",
        "documents_list": "{label} documents: {sources}",
        "failed_load_documents": "Failed to load {label} documents",
        "generated_dfd_summary": "Generated DFD summary",
        "generated_dfd_assumptions": "Generated DFD assumptions",
        "generated_dfd_questions": "Generated DFD clarifying questions",
        "no_input_title": "No input specified",
        "no_input_detail": "Provide a diagram with --diagram/--mermaid/--drawio/--threat-dragon/--image/--ir, or provide --description/--description-file to generate a DFD.",
        "invalid_llm_api_title": "Invalid LLM API: {api}",
        "invalid_llm_api_detail": "Must be one of {supported}",
        "openai_key_title": "OPENAI_API_KEY is not set",
        "openai_key_detail": "Please set your OpenAI API key in environment variables",
        "anthropic_key_title": "ANTHROPIC_API_KEY is not set",
        "anthropic_key_detail": "Please set your Anthropic API key in environment variables",
        "aws_credentials_title": "AWS credentials not fully configured",
        "aws_credentials_detail": "For bedrock API, either set --aws-profile or AWS environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)",
        "ollama_image_title": "Image diagrams are not supported with the Ollama backend.",
        "ollama_image_detail": "Use OpenAI/Anthropic/Bedrock for image extraction or provide a Mermaid/Draw.io/Threat Dragon file.",
        "rag_openai_title": "OPENAI_API_KEY is required for --rag",
        "rag_openai_detail": "Local RAG relies on OpenAI embeddings for semantic search.",
        "rag_kb_required_title": "--kb is required when --rag is enabled",
        "rag_kb_required_detail": "Provide a comma-separated list of knowledge base names.",
        "rag_kb_invalid_title": "No valid knowledge base names provided",
        "rag_kb_invalid_detail": "Example: --kb owasp,internal-standards",
        "rag_topk_positive": "--rag-topk must be a positive integer.",
        "rag_candidates_positive": "--rag-candidates must be a positive integer.",
        "rag_min_score_range": "--rag-min-score must be between 0 and 1.",
        "prompt_token_limit_positive": "--prompt-token-limit must be a positive integer.",
        "loading_system_description": "Loading system description",
        "system_description_empty_title": "System description is empty",
        "system_description_empty_detail": "Provide text with --description or readable files with --description-file.",
        "parsing_architecture_diagram": "Parsing architecture diagram",
        "loading_diagram": "Loading {diagram_format} diagram: {path}",
        "parsing_diagram_structure": "Parsing diagram structure",
        "parsed_diagram_success": "Successfully parsed diagram",
        "failed_parse_diagram": "Failed to parse diagram",
        "generating_dfd": "Generating DFD from system description",
        "reconstructing_architecture_graph": "AI is reconstructing the architecture graph",
        "generated_dfd_success": "Generated DFD with {nodes} nodes and {edges} edges",
        "generated_dfd_graph_details": "Generated DFD graph details",
        "dfd_too_vague_title": "System description is too vague to generate a useful DFD",
        "dfd_too_vague_detail": "Answer the clarifying questions and rerun with a more specific --description.",
        "failed_generate_dfd": "Failed to generate DFD from system description",
        "inferring_attributes": "Inferring node and edge attributes",
        "analyzing_components": "AI is analyzing diagram components to infer security-relevant attributes",
        "inferring_component_attributes": "AI is inferring component attributes",
        "inferred_attributes_success": "Successfully inferred component attributes",
        "failed_infer_hints": "Failed to infer hints",
        "skipping_inference": "Skipping attribute inference",
        "using_basic_attributes": "Using basic component attributes from diagram",
        "loading_business_context": "Loading business context",
        "retrieving_local_knowledge": "Retrieving local knowledge",
        "retrieved_knowledge": "Retrieved {chunks} knowledge chunks from {kbs}",
        "rag_strategy": "{strategy} (reranker={reranker})",
        "no_knowledge_title": "No knowledge snippets retrieved",
        "no_knowledge_detail": "Proceeding without additional context.",
        "failed_retrieve_knowledge": "Failed to retrieve local knowledge",
        "analyzing_threats": "Analyzing potential security threats",
        "performing_threat_analysis": "AI is performing comprehensive security threat analysis",
        "identifying_security_threats": "AI is identifying security threats",
        "excluded_uncited_threats": "Excluded {count} threats without RAG document attribution",
        "identified_potential_threats": "Identified {count} potential threats",
        "failed_analyze_threats": "Failed to analyze threats",
        "filtering_threats": "Filtering and prioritizing threats",
        "applying_filtering": "Applying threat filtering criteria",
        "filtered_low_confidence": "Filtered out {count} low-confidence threats",
        "finalized_threats": "Finalized {count} high-priority threats",
        "failed_filter_threats": "Failed to filter threats",
        "generating_reports": "Generating reports",
        "exporting_reports": "Exporting reports to {out_dir} ({json_name}, {md_name}, {html_name})",
        "td_saved": "Threat Dragon report saved to: {path}",
        "td_skipped": "Threat Dragon export skipped",
        "json_saved": "JSON report saved to: {path}",
        "md_saved": "Markdown report saved to: {path}",
        "html_saved": "HTML report saved to: {path}",
        "dfd_sidecar_saved": "Generated DFD sidecar saved to: {path}",
        "json_output": "JSON Output:",
        "markdown_output": "Markdown Output:",
        "html_output": "HTML Output:",
        "td_output": "Threat Dragon Output:",
        "failed_export_reports": "Failed to export reports",
        "comparing_reports": "Comparing reports: {before} → {after}",
        "analyzing_report_differences": "AI is analyzing report differences",
        "diff_completed": "Diff analysis completed",
        "changes_summary": "Changes summary:",
        "nodes_delta": "Nodes: +{added} -{removed}",
        "edges_delta": "Edges: +{added} -{removed}",
        "threats_delta": "Threats: +{added} -{removed}",
        "diff_json_saved": "Diff JSON saved to: {path}",
        "diff_md_saved": "Diff Markdown saved to: {path}",
        "markdown_diff_output": "Markdown diff output:",
        "json_diff_output": "JSON diff output:",
        "failed_generate_diff": "Failed to generate diff",
        "diff_completed_in": "Diff completed in {seconds:.1f}s",
    },
    "ja": {
        "output_language_help": "レポートおよび CLI 出力の言語コード (ISO 639-1。例: en, ja, fr, de, es, zh, ko, pt, it, ru, ar, hi, th, vi など)",
        "unsupported_diagram_title": "{path} の図ファイル形式はサポートされていません",
        "unsupported_diagram_json_detail": "--diagram で JSON を指定する場合は Threat Dragon v2 JSON のみ対応しています。ネイティブ IR JSON は --ir を使用してください。",
        "unsupported_diagram_detail": "対応形式: Mermaid (.mmd/.mermaid)、Draw.io (.drawio/.xml)、Threat Dragon JSON (.json)、画像 (.jpg/.jpeg/.png/.gif/.bmp/.webp)。ネイティブ IR JSON は --ir を使用してください。",
        "loaded_documents": "{count} 件の{label}ドキュメントを読み込みました。推定 {tokens} トークンです",
        "documents_list": "{label}ドキュメント: {sources}",
        "failed_load_documents": "{label}ドキュメントの読み込みに失敗しました",
        "generated_dfd_summary": "生成された DFD の要約",
        "generated_dfd_assumptions": "生成された DFD の前提",
        "generated_dfd_questions": "生成された DFD の確認事項",
        "no_input_title": "入力が指定されていません",
        "no_input_detail": "--diagram/--mermaid/--drawio/--threat-dragon/--image/--ir で図を指定するか、--description/--description-file で DFD 生成用の説明を指定してください。",
        "invalid_llm_api_title": "無効な LLM API です: {api}",
        "invalid_llm_api_detail": "次のいずれかを指定してください: {supported}",
        "openai_key_title": "OPENAI_API_KEY が設定されていません",
        "openai_key_detail": "環境変数に OpenAI API キーを設定してください",
        "anthropic_key_title": "ANTHROPIC_API_KEY が設定されていません",
        "anthropic_key_detail": "環境変数に Anthropic API キーを設定してください",
        "aws_credentials_title": "AWS 認証情報が十分に設定されていません",
        "aws_credentials_detail": "bedrock API を使うには、--aws-profile か AWS 環境変数 (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) を設定してください",
        "ollama_image_title": "Ollama バックエンドでは画像図を処理できません。",
        "ollama_image_detail": "画像抽出には OpenAI / Anthropic / Bedrock を使うか、Mermaid / Draw.io / Threat Dragon のファイルを指定してください。",
        "rag_openai_title": "--rag には OPENAI_API_KEY が必要です",
        "rag_openai_detail": "ローカル RAG の意味検索は OpenAI 埋め込みを使用します。",
        "rag_kb_required_title": "--rag を有効にする場合は --kb が必要です",
        "rag_kb_required_detail": "カンマ区切りでナレッジベース名を指定してください。",
        "rag_kb_invalid_title": "有効なナレッジベース名が指定されていません",
        "rag_kb_invalid_detail": "例: --kb owasp,internal-standards",
        "rag_topk_positive": "--rag-topk には正の整数を指定してください。",
        "rag_candidates_positive": "--rag-candidates には正の整数を指定してください。",
        "rag_min_score_range": "--rag-min-score は 0 から 1 の範囲で指定してください。",
        "prompt_token_limit_positive": "--prompt-token-limit には正の整数を指定してください。",
        "loading_system_description": "システム説明を読み込み中",
        "system_description_empty_title": "システム説明が空です",
        "system_description_empty_detail": "--description にテキストを指定するか、--description-file で読めるファイルを指定してください。",
        "parsing_architecture_diagram": "アーキテクチャ図を解析中",
        "loading_diagram": "{diagram_format} 図を読み込み中: {path}",
        "parsing_diagram_structure": "図の構造を解析中",
        "parsed_diagram_success": "図の解析に成功しました",
        "failed_parse_diagram": "図の解析に失敗しました",
        "generating_dfd": "システム説明から DFD を生成中",
        "reconstructing_architecture_graph": "AI がアーキテクチャグラフを再構成中",
        "generated_dfd_success": "{nodes} 個のノードと {edges} 本のエッジを持つ DFD を生成しました",
        "generated_dfd_graph_details": "生成された DFD グラフ詳細",
        "dfd_too_vague_title": "有用な DFD を生成するにはシステム説明が曖昧すぎます",
        "dfd_too_vague_detail": "確認事項に答えたうえで、より具体的な --description で再実行してください。",
        "failed_generate_dfd": "システム説明からの DFD 生成に失敗しました",
        "inferring_attributes": "ノードとエッジの属性を推定中",
        "analyzing_components": "AI がセキュリティに関係する属性を推定するために図の構成要素を分析中",
        "inferring_component_attributes": "AI がコンポーネント属性を推定中",
        "inferred_attributes_success": "コンポーネント属性の推定に成功しました",
        "failed_infer_hints": "ヒントの推定に失敗しました",
        "skipping_inference": "属性推定をスキップします",
        "using_basic_attributes": "図から取得した基本属性を使用します",
        "loading_business_context": "ビジネスコンテキストを読み込み中",
        "retrieving_local_knowledge": "ローカルナレッジを取得中",
        "retrieved_knowledge": "{kbs} から {chunks} 件のナレッジチャンクを取得しました",
        "rag_strategy": "{strategy} (reranker={reranker})",
        "no_knowledge_title": "ナレッジスニペットを取得できませんでした",
        "no_knowledge_detail": "追加コンテキストなしで続行します。",
        "failed_retrieve_knowledge": "ローカルナレッジの取得に失敗しました",
        "analyzing_threats": "潜在的なセキュリティ脅威を分析中",
        "performing_threat_analysis": "AI が包括的なセキュリティ脅威分析を実行中",
        "identifying_security_threats": "AI がセキュリティ脅威を特定中",
        "excluded_uncited_threats": "RAG 文書の根拠がない脅威を {count} 件除外しました",
        "identified_potential_threats": "{count} 件の潜在的な脅威を特定しました",
        "failed_analyze_threats": "脅威分析に失敗しました",
        "filtering_threats": "脅威をフィルタリングして優先度付け中",
        "applying_filtering": "脅威フィルタリング条件を適用中",
        "filtered_low_confidence": "信頼度の低い脅威を {count} 件除外しました",
        "finalized_threats": "優先度の高い脅威を {count} 件に絞り込みました",
        "failed_filter_threats": "脅威のフィルタリングに失敗しました",
        "generating_reports": "レポートを生成中",
        "exporting_reports": "{out_dir} にレポートを書き出します ({json_name}, {md_name}, {html_name})",
        "td_saved": "Threat Dragon レポートを保存しました: {path}",
        "td_skipped": "Threat Dragon 出力をスキップしました",
        "json_saved": "JSON レポートを保存しました: {path}",
        "md_saved": "Markdown レポートを保存しました: {path}",
        "html_saved": "HTML レポートを保存しました: {path}",
        "dfd_sidecar_saved": "生成した DFD サイドカーを保存しました: {path}",
        "json_output": "JSON 出力:",
        "markdown_output": "Markdown 出力:",
        "html_output": "HTML 出力:",
        "td_output": "Threat Dragon 出力:",
        "failed_export_reports": "レポート出力に失敗しました",
        "comparing_reports": "レポートを比較中: {before} → {after}",
        "analyzing_report_differences": "AI がレポート差分を分析中",
        "diff_completed": "差分分析が完了しました",
        "changes_summary": "変更サマリー:",
        "nodes_delta": "ノード: +{added} -{removed}",
        "edges_delta": "エッジ: +{added} -{removed}",
        "threats_delta": "脅威: +{added} -{removed}",
        "diff_json_saved": "差分 JSON を保存しました: {path}",
        "diff_md_saved": "差分 Markdown を保存しました: {path}",
        "markdown_diff_output": "Markdown 差分出力:",
        "json_diff_output": "JSON 差分出力:",
        "failed_generate_diff": "差分生成に失敗しました",
        "diff_completed_in": "差分処理が {seconds:.1f}秒で完了しました",
    },
}


def _normalize_ui_locale(lang: str | None) -> str:
    return "ja" if (lang or "").strip().lower().startswith("ja") else _DEFAULT_UI_LOCALE


def _main_t(lang: str | None, key: str, **kwargs) -> str:
    template = _MAIN_TEXT[_normalize_ui_locale(lang)][key]
    return template.format(**kwargs) if kwargs else template


def _normalize_embed_model(embed_arg: str) -> str:
    value = (embed_arg or "").strip()
    if ":" in value:
        value = value.split(":", 1)[-1]
    return value or DEFAULT_EMBED_MODEL


def _prepare_output_paths(
    diagram_file: str, out_dir: str, base_name_override: str | None = None
) -> tuple[Path, Path, Path, Path]:
    """Return output directory and file paths for full report exports."""
    target_dir = Path(out_dir).expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)
    base_source = base_name_override or Path(diagram_file).stem or "threat"
    base_name = Path(base_source).stem or "threat"
    json_path = target_dir / f"{base_name}_report.json"
    md_path = target_dir / f"{base_name}_report.md"
    html_path = target_dir / f"{base_name}_report.html"
    return target_dir, json_path, md_path, html_path


def _default_report_base_name(
    diagram_file: str | None, description_files: list[str] | None = None
) -> str:
    if diagram_file:
        return Path(diagram_file).stem or "threat"
    if description_files:
        return Path(description_files[0]).stem or "description"
    return "description"


def _prepare_dfd_sidecar_path(report_json_path: Path) -> Path:
    return report_json_path.with_name(f"{report_json_path.stem}_dfd.json")


def _prepare_diff_output_paths(
    after_report: str, out_dir: str
) -> tuple[Path, Path, Path]:
    """Return output directory and file paths for diff exports."""
    target_dir = Path(out_dir).expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)
    base_name = Path(after_report).stem or "diff"
    json_path = target_dir / f"{base_name}_diff.json"
    md_path = target_dir / f"{base_name}_diff.md"
    return target_dir, json_path, md_path


def _select_think_input(args) -> tuple[str | None, str | None]:
    if args.diagram:
        diagram_file = args.diagram
        diagram_format = detect_input_format(diagram_file)
        if not diagram_format:
            if diagram_file.lower().endswith(".json"):
                ui.error(
                    _main_t(ui.locale, "unsupported_diagram_title", path=diagram_file),
                    _main_t(ui.locale, "unsupported_diagram_json_detail"),
                )
            else:
                ui.error(
                    _main_t(ui.locale, "unsupported_diagram_title", path=diagram_file),
                    _main_t(ui.locale, "unsupported_diagram_detail"),
                )
            sys.exit(2)
        return diagram_file, diagram_format
    if args.mermaid:
        return args.mermaid, INPUT_FORMAT_MERMAID
    if args.drawio:
        return args.drawio, INPUT_FORMAT_DRAWIO
    if args.threat_dragon:
        return args.threat_dragon, INPUT_FORMAT_THREAT_DRAGON
    if args.image:
        return args.image, INPUT_FORMAT_IMAGE
    if args.ir:
        return args.ir, INPUT_FORMAT_IR

    return None, None


def _combine_text_blocks(*blocks: str | None) -> str | None:
    combined = "\n\n".join(block.strip() for block in blocks if block and block.strip())
    return combined or None


def _load_document_text(paths: list[str], model: str, *, label: str) -> str | None:
    if not paths:
        return None
    try:
        docs = load_context_documents(paths, model)
        doc_count, token_count, sources = context_summary(docs)
        ui.success(
            _main_t(
                ui.locale,
                "loaded_documents",
                count=doc_count,
                label=label,
                tokens=token_count,
            )
        )
        ui.info(
            _main_t(
                ui.locale,
                "documents_list",
                label=label.title(),
                sources=", ".join(sources),
            )
        )
        return format_context_documents(docs)
    except ContextDocumentError as e:
        ui.error(_main_t(ui.locale, "failed_load_documents", label=label), str(e))
        sys.exit(2)


def _load_description_text(args) -> str | None:
    inline = "\n\n".join(
        text.strip()
        for text in (getattr(args, "description", None) or [])
        if text.strip()
    )
    file_text = _load_document_text(
        getattr(args, "description_file", None) or [],
        args.llm_model,
        label="description",
    )
    return _combine_text_blocks(inline, file_text)


def _load_context_text(args) -> str | None:
    context_paths = list(getattr(args, "context", None) or [])
    context_paths.extend(getattr(args, "context_file", None) or [])
    return _load_document_text(context_paths, args.llm_model, label="context")


def _show_dfd_notes(result: BusinessContextDfdResult) -> None:
    if result.summary:
        ui.info(_main_t(ui.locale, "generated_dfd_summary"), result.summary)
    if result.assumptions:
        ui.warning(
            _main_t(ui.locale, "generated_dfd_assumptions"),
            "\n".join(f"- {item}" for item in result.assumptions),
        )
    if result.clarifying_questions:
        ui.warning(
            _main_t(ui.locale, "generated_dfd_questions"),
            "\n".join(f"- {item}" for item in result.clarifying_questions),
        )


def main():
    p = argparse.ArgumentParser(prog="threat_thinker", description="Threat Thinker CLI")
    p.add_argument(
        "-v",
        "--version",
        "--verison",
        action="version",
        version=format_version_output(),
        help="Show the installed Threat Thinker version",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("version", help="Show the installed Threat Thinker version")

    p_think = sub.add_parser(
        "think", help="Parse diagram and generate threats (LLM required)"
    )
    p_think.add_argument("--mermaid", type=str, help="Path to Mermaid (.mmd/.mermaid)")
    p_think.add_argument("--drawio", type=str, help="Path to Draw.io (.drawio/.xml)")
    p_think.add_argument(
        "--drawio-page",
        type=str,
        help="Optional Draw.io page selector (page id, page name, or 0-based index)",
    )
    p_think.add_argument(
        "--threat-dragon", type=str, help="Path to Threat Dragon JSON (.json)"
    )
    p_think.add_argument("--ir", type=str, help="Path to native Graph IR JSON (.json)")
    p_think.add_argument(
        "--image", type=str, help="Path to image file (.jpg/.jpeg/.png/.gif/.bmp/.webp)"
    )
    p_think.add_argument(
        "--diagram",
        type=str,
        help="Path to diagram file (auto-detects format from extension)",
    )
    p_think.add_argument(
        "--context",
        type=str,
        action="append",
        default=[],
        help="Business context document path to inject into the threat prompt. Repeat for multiple PDF, Markdown, or text files.",
    )
    p_think.add_argument(
        "--context-file",
        type=str,
        action="append",
        default=[],
        help="Alias for --context. Business context document path to inject into the threat prompt.",
    )
    p_think.add_argument(
        "--description",
        type=str,
        action="append",
        default=[],
        help="Natural-language system description. Used to generate a DFD when no diagram input is provided; also injected into the threat prompt.",
    )
    p_think.add_argument(
        "--description-file",
        type=str,
        action="append",
        default=[],
        help="System description document path. Repeat for multiple PDF, Markdown, or text files.",
    )
    p_think.add_argument(
        "--infer-hints",
        action="store_true",
        help="Infer node/edge attributes from Mermaid via LLM (multilingual)",
    )
    p_think.add_argument(
        "--out-dir",
        type=str,
        required=True,
        help="Directory to write all report formats (json, md, html)",
    )
    p_think.add_argument(
        "--out-name",
        type=str,
        help="Base filename for reports (default: <diagram-stem>_report.*)",
    )
    p_think.add_argument(
        "--llm-api",
        type=str,
        default="openai",
        help="LLM provider to use ('openai', 'anthropic', or 'bedrock')",
    )
    p_think.add_argument(
        "--llm-model", type=str, default="gpt-4o-mini", help="LLM model identifier"
    )
    p_think.add_argument(
        "--aws-profile", type=str, help="AWS profile name (for bedrock provider only)"
    )
    p_think.add_argument(
        "--aws-region",
        type=str,
        help="AWS region (for bedrock provider only, defaults to us-east-1)",
    )
    p_think.add_argument(
        "--ollama-host",
        type=str,
        help="Ollama host URL (default: http://localhost:11434 or env OLLAMA_HOST)",
    )
    p_think.add_argument(
        "--prompt-token-limit",
        type=int,
        help="Fail if the assembled threat prompt exceeds this token budget.",
    )

    p_think.add_argument(
        "--topn", type=int, default=10, help="Keep top-N threats after de-noise"
    )
    p_think.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="Drop threats below this confidence",
    )
    p_think.add_argument(
        "--require-asvs",
        action="store_true",
        help="Require at least one ASVS reference",
    )
    p_think.add_argument(
        "--lang",
        type=str,
        default="en",
        help=_main_t("en", "output_language_help"),
    )
    p_think.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output with detailed logs",
    )
    p_think.add_argument(
        "--rag",
        action="store_true",
        help="Enable local RAG enrichment using knowledge bases built with `kb build`",
    )
    p_think.add_argument(
        "--kb",
        type=str,
        help="Comma-separated knowledge base names to use when --rag is enabled",
    )
    p_think.add_argument(
        "--rag-topk",
        type=int,
        default=DEFAULT_TOPK,
        help=f"Number of retrieved knowledge chunks to inject (default: {DEFAULT_TOPK})",
    )
    p_think.add_argument(
        "--rag-strategy",
        type=str,
        default=DEFAULT_RAG_STRATEGY,
        choices=sorted(RAG_STRATEGIES),
        help=f"RAG retrieval strategy (default: {DEFAULT_RAG_STRATEGY})",
    )
    p_think.add_argument(
        "--rag-reranker",
        type=str,
        default=DEFAULT_RAG_RERANKER,
        choices=sorted(RAG_RERANKERS),
        help=f"RAG reranker backend (default: {DEFAULT_RAG_RERANKER})",
    )
    p_think.add_argument(
        "--rag-candidates",
        type=int,
        default=DEFAULT_RAG_CANDIDATES,
        help=f"Candidate pool size before reranking/MMR (default: {DEFAULT_RAG_CANDIDATES})",
    )
    p_think.add_argument(
        "--rag-min-score",
        type=float,
        default=DEFAULT_RAG_MIN_SCORE,
        help=f"Minimum normalized retrieval score [0..1] after reranking (default: {DEFAULT_RAG_MIN_SCORE})",
    )

    p_kb = sub.add_parser("kb", help="Manage local knowledge bases for RAG")
    p_kb.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output with detailed logs",
    )
    kb_sub = p_kb.add_subparsers(dest="kb_cmd", required=True)

    kb_build = kb_sub.add_parser(
        "build", help="Chunk documents in raw/ and create embeddings"
    )
    kb_build.add_argument("kb_name", type=str, help="Knowledge base name")
    kb_build.add_argument(
        "--embedder",
        type=str,
        default=f"openai:{DEFAULT_EMBED_MODEL}",
        help="Embedding backend (OpenAI only). Format: openai:<model>",
    )
    kb_build.add_argument(
        "--chunk-tokens",
        type=int,
        default=DEFAULT_CHUNK_TOKENS,
        help=f"Max tokens per chunk (default: {DEFAULT_CHUNK_TOKENS})",
    )
    kb_build.add_argument(
        "--chunk-overlap",
        type=int,
        default=DEFAULT_CHUNK_OVERLAP,
        help=f"Token overlap between chunks (default: {DEFAULT_CHUNK_OVERLAP})",
    )

    kb_sub.add_parser("list", help="List available knowledge bases")

    kb_search = kb_sub.add_parser(
        "search", help="Query a knowledge base with semantic similarity"
    )
    kb_search.add_argument("kb_name", type=str, help="Knowledge base name")
    kb_search.add_argument("query", type=str, help="Search query")
    kb_search.add_argument(
        "--topk",
        type=int,
        default=DEFAULT_TOPK,
        help=f"Number of chunks to return (default: {DEFAULT_TOPK})",
    )
    kb_search.add_argument(
        "--show",
        action="store_true",
        help="Print retrieved chunk text to stdout",
    )

    kb_remove = kb_sub.add_parser("remove", help="Delete a knowledge base directory")
    kb_remove.add_argument("kb_name", type=str, help="Knowledge base name")
    kb_remove.add_argument(
        "--force", action="store_true", help="Remove without confirmation"
    )

    p_diff = sub.add_parser("diff", help="Diff two JSON reports")
    p_diff.add_argument(
        "--after", type=str, required=True, help="Path to after report JSON"
    )
    p_diff.add_argument(
        "--before", type=str, required=True, help="Path to before report JSON"
    )
    p_diff.add_argument(
        "--out-dir",
        type=str,
        required=True,
        help="Directory to write diff reports (json and markdown)",
    )
    p_diff.add_argument(
        "--llm-api",
        type=str,
        default="openai",
        help="LLM provider to use ('openai', 'anthropic', or 'bedrock')",
    )
    p_diff.add_argument(
        "--llm-model", type=str, default="gpt-4o-mini", help="LLM model identifier"
    )
    p_diff.add_argument(
        "--aws-profile", type=str, help="AWS profile name (for bedrock provider only)"
    )
    p_diff.add_argument(
        "--aws-region",
        type=str,
        help="AWS region (for bedrock provider only, defaults to us-east-1)",
    )
    p_diff.add_argument(
        "--ollama-host",
        type=str,
        help="Ollama host URL (default: http://localhost:11434 or env OLLAMA_HOST)",
    )
    p_diff.add_argument(
        "--lang",
        type=str,
        default="en",
        help=_main_t("en", "output_language_help"),
    )
    p_diff.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output with detailed logs",
    )

    p_webui = sub.add_parser("webui", help="Launch the Gradio Web UI")
    p_webui.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Interface to bind (default: 127.0.0.1)",
    )
    p_webui.add_argument("--port", type=int, help="Port to bind")

    p_serve = sub.add_parser("serve", help="Run the FastAPI serve endpoint")
    p_serve.add_argument(
        "--config", type=str, required=True, help="Path to serve YAML configuration"
    )

    p_worker = sub.add_parser("worker", help="Run the background analysis worker")
    p_worker.add_argument(
        "--config", type=str, required=True, help="Path to serve YAML configuration"
    )

    args = p.parse_args()

    if args.cmd == "version":
        print(format_version_output())

    elif args.cmd == "think":
        start_time = time.time()

        # Set verbose mode
        set_verbose(args.verbose)
        set_locale(args.lang)

        has_context_files = bool(args.context or args.context_file)
        has_description_input = bool(args.description or args.description_file)

        # Set up progress tracking
        total_steps = (
            5
            + (1 if args.rag else 0)
            + (1 if has_context_files else 0)
            + (1 if has_description_input else 0)
        )
        ui.set_total_steps(total_steps)

        # Determine optional diagram file and format
        diagram_file, diagram_format = _select_think_input(args)
        if not diagram_file and not has_description_input:
            ui.error(
                _main_t(args.lang, "no_input_title"),
                _main_t(args.lang, "no_input_detail"),
            )
            sys.exit(2)

        supported_apis = ["openai", "anthropic", "bedrock", "ollama"]
        if args.llm_api.lower() not in supported_apis:
            ui.error(
                _main_t(args.lang, "invalid_llm_api_title", api=args.llm_api),
                _main_t(
                    args.lang,
                    "invalid_llm_api_detail",
                    supported=supported_apis,
                ),
            )
            sys.exit(2)

        supported_apis = ["openai", "anthropic", "bedrock", "ollama"]
        if args.llm_api.lower() not in supported_apis:
            ui.error(
                _main_t(args.lang, "invalid_llm_api_title", api=args.llm_api),
                _main_t(
                    args.lang,
                    "invalid_llm_api_detail",
                    supported=supported_apis,
                ),
            )
            sys.exit(2)

        # Check for required API keys/credentials
        if args.llm_api.lower() == "openai" and not os.getenv("OPENAI_API_KEY"):
            ui.error(
                _main_t(args.lang, "openai_key_title"),
                _main_t(args.lang, "openai_key_detail"),
            )
            sys.exit(2)
        elif args.llm_api.lower() == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
            ui.error(
                _main_t(args.lang, "anthropic_key_title"),
                _main_t(args.lang, "anthropic_key_detail"),
            )
            sys.exit(2)
        elif args.llm_api.lower() == "bedrock":
            # For bedrock, we check credentials later in the provider initialization
            # Here we just validate that if aws-profile is provided, it's for bedrock
            if not args.aws_profile and not (
                os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
            ):
                ui.warning(
                    _main_t(args.lang, "aws_credentials_title"),
                    _main_t(args.lang, "aws_credentials_detail"),
                )
        elif args.llm_api.lower() == "ollama":
            if args.image:
                ui.error(
                    _main_t(args.lang, "ollama_image_title"),
                    _main_t(args.lang, "ollama_image_detail"),
                )
                sys.exit(2)

        ollama_host = (
            args.ollama_host or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
        )
        if args.llm_api.lower() == "ollama":
            normalized_model = (args.llm_model or "").strip().lower()
            if not normalized_model or normalized_model.startswith("gpt-4"):
                args.llm_model = "llama3.1"

        rag_kbs: list[str] = []
        if args.rag:
            if not os.getenv("OPENAI_API_KEY"):
                ui.error(
                    _main_t(args.lang, "rag_openai_title"),
                    _main_t(args.lang, "rag_openai_detail"),
                )
                sys.exit(2)
            if not args.kb:
                ui.error(
                    _main_t(args.lang, "rag_kb_required_title"),
                    _main_t(args.lang, "rag_kb_required_detail"),
                )
                sys.exit(2)
            rag_kbs = [kb.strip() for kb in args.kb.split(",") if kb.strip()]
            if not rag_kbs:
                ui.error(
                    _main_t(args.lang, "rag_kb_invalid_title"),
                    _main_t(args.lang, "rag_kb_invalid_detail"),
                )
                sys.exit(2)
            if args.rag_topk <= 0:
                ui.error(_main_t(args.lang, "rag_topk_positive"))
                sys.exit(2)
            if args.rag_candidates <= 0:
                ui.error(_main_t(args.lang, "rag_candidates_positive"))
                sys.exit(2)
            if args.rag_min_score < 0.0 or args.rag_min_score > 1.0:
                ui.error(_main_t(args.lang, "rag_min_score_range"))
                sys.exit(2)
        if args.prompt_token_limit is not None and args.prompt_token_limit <= 0:
            ui.error(_main_t(args.lang, "prompt_token_limit_positive"))
            sys.exit(2)

        description_text = None
        if has_description_input:
            ui.step(_main_t(args.lang, "loading_system_description"))
            description_text = _load_description_text(args)
            if not description_text:
                ui.error(
                    _main_t(args.lang, "system_description_empty_title"),
                    _main_t(args.lang, "system_description_empty_detail"),
                )
                sys.exit(2)

        dfd_result = None
        if diagram_file and diagram_format:
            # 1) Parse diagram to skeleton graph (+ metrics)
            ui.step(_main_t(args.lang, "parsing_architecture_diagram"))
            ui.info(
                _main_t(
                    args.lang,
                    "loading_diagram",
                    diagram_format=diagram_format,
                    path=diagram_file,
                )
            )

            thinking = ui.create_thinking_indicator(
                _main_t(args.lang, "parsing_diagram_structure")
            )
            thinking.start()

            try:
                g, metrics = load_input(
                    diagram_format,
                    diagram_file,
                    drawio_page=args.drawio_page,
                    api=args.llm_api,
                    model=args.llm_model,
                    aws_profile=args.aws_profile,
                    aws_region=args.aws_region,
                    ollama_host=ollama_host,
                )

                thinking.stop()
                ui.success(_main_t(args.lang, "parsed_diagram_success"))
                ui.show_metrics_summary(metrics)
                ui.debug("Parsed graph details", str(g))

            except Exception as e:
                thinking.stop()
                ui.error(_main_t(args.lang, "failed_parse_diagram"), str(e))
                sys.exit(2)
        else:
            ui.step(_main_t(args.lang, "generating_dfd"))
            thinking = ui.create_thinking_indicator(
                _main_t(args.lang, "reconstructing_architecture_graph")
            )
            thinking.start()
            try:
                payload = llm_generate_dfd_from_description(
                    description_text or "",
                    args.llm_api,
                    args.llm_model,
                    args.aws_profile,
                    args.aws_region,
                    ollama_host,
                    args.prompt_token_limit,
                    lang=args.lang,
                )
                dfd_result = dfd_result_from_payload(payload)
                dfd_result.metrics.total_lines = len(
                    (description_text or "").splitlines()
                )
                g = dfd_result.graph
                metrics = dfd_result.metrics
                thinking.stop()
                ui.success(
                    _main_t(
                        args.lang,
                        "generated_dfd_success",
                        nodes=len(g.nodes),
                        edges=len(g.edges),
                    )
                )
                ui.show_metrics_summary(metrics)
                _show_dfd_notes(dfd_result)
                ui.debug(_main_t(args.lang, "generated_dfd_graph_details"), str(g))
                if not g.nodes:
                    ui.error(
                        _main_t(args.lang, "dfd_too_vague_title"),
                        _main_t(args.lang, "dfd_too_vague_detail"),
                    )
                    sys.exit(2)
            except Exception as e:
                thinking.stop()
                ui.error(_main_t(args.lang, "failed_generate_dfd"), str(e))
                sys.exit(2)

        # 2) (Optional) LLM-based attribute inference from skeleton
        if args.infer_hints and diagram_file:
            ui.step(_main_t(args.lang, "inferring_attributes"))
            ui.thinking(_main_t(args.lang, "analyzing_components"))

            skeleton = json.dumps(
                {
                    "nodes": [{"id": n.id, "label": n.label} for n in g.nodes.values()],
                    "edges": [
                        {"from": e.src, "to": e.dst, "label": e.label} for e in g.edges
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )

            thinking = ui.create_thinking_indicator(
                _main_t(args.lang, "inferring_component_attributes")
            )
            thinking.start()

            try:
                inferred = llm_infer_hints(
                    skeleton,
                    args.llm_api,
                    args.llm_model,
                    args.aws_profile,
                    args.aws_region,
                    ollama_host,
                    args.lang,
                )
                g = merge_llm_hints(g, inferred)
                thinking.stop()
                ui.success(_main_t(args.lang, "inferred_attributes_success"))
                ui.debug("Graph after LLM-inferred hints", str(g))

            except Exception as e:
                thinking.stop()
                ui.error(_main_t(args.lang, "failed_infer_hints"), str(e))
                sys.exit(2)
        elif diagram_file:
            ui.step(_main_t(args.lang, "skipping_inference"))
            ui.info(_main_t(args.lang, "using_basic_attributes"))

        context_text = None
        if has_context_files:
            ui.step(_main_t(args.lang, "loading_business_context"))
            context_text = _load_context_text(args)
        business_context_text = _combine_text_blocks(description_text, context_text)

        rag_context_text = None
        retrieval = None
        rerank_fn = None
        if args.rag:
            ui.step(_main_t(args.lang, "retrieving_local_knowledge"))
            try:
                retrieval_options = RetrievalOptions(
                    strategy=args.rag_strategy,
                    reranker=args.rag_reranker,
                    candidates=args.rag_candidates,
                    min_score=args.rag_min_score,
                )
                if args.rag_reranker in {"auto", "llm"}:

                    def _rerank_with_llm(q, candidates):
                        return llm_rerank_chunks(
                            q,
                            candidates,
                            args.llm_api,
                            args.llm_model,
                            args.aws_profile,
                            args.aws_region,
                            ollama_host,
                        )

                    rerank_fn = _rerank_with_llm
                retrieval = retrieve_context_for_graph(
                    g,
                    rag_kbs,
                    topk=args.rag_topk or DEFAULT_TOPK,
                    options=retrieval_options,
                    rerank_fn=rerank_fn,
                )
                rag_context_text = retrieval.get("context_text") or ""
                num_chunks = len(retrieval.get("results", []))
                if rag_context_text and num_chunks:
                    ui.success(
                        _main_t(
                            args.lang,
                            "retrieved_knowledge",
                            chunks=num_chunks,
                            kbs=", ".join(rag_kbs),
                        )
                    )
                    ui.debug(
                        "RAG strategy",
                        _main_t(
                            args.lang,
                            "rag_strategy",
                            strategy=args.rag_strategy,
                            reranker=retrieval.get("reranker_backend", "off"),
                        ),
                    )
                    ui.debug("RAG query", retrieval.get("query", ""))
                else:
                    ui.warning(
                        _main_t(args.lang, "no_knowledge_title"),
                        _main_t(args.lang, "no_knowledge_detail"),
                    )
            except KnowledgeBaseError as e:
                ui.error(_main_t(args.lang, "failed_retrieve_knowledge"), str(e))
                sys.exit(2)

        # 4) LLM-driven threat inference
        ui.step(_main_t(args.lang, "analyzing_threats"))
        ui.thinking(_main_t(args.lang, "performing_threat_analysis"))

        thinking = ui.create_thinking_indicator(
            _main_t(args.lang, "identifying_security_threats")
        )
        thinking.start()

        try:
            threats = llm_infer_threats(
                g,
                args.llm_api,
                args.llm_model,
                args.aws_profile,
                args.aws_region,
                ollama_host,
                args.lang,
                rag_context=rag_context_text,
                rag_candidates=(retrieval or {}).get("candidate_results"),
                business_context=business_context_text,
                prompt_token_limit=args.prompt_token_limit,
            )
            if args.rag:
                threats, dropped_by_citation = attach_rag_sources_to_threats(
                    threats,
                    retrieval,
                    reranker_backend=(retrieval or {}).get("reranker_backend", "off"),
                    rerank_fn=rerank_fn,
                    min_score=args.rag_min_score,
                    max_sources_per_threat=2,
                )
                if dropped_by_citation > 0:
                    ui.info(
                        _main_t(
                            args.lang,
                            "excluded_uncited_threats",
                            count=dropped_by_citation,
                        )
                    )
            thinking.stop()
            ui.success(
                _main_t(args.lang, "identified_potential_threats", count=len(threats))
            )
            ui.debug("LLM inferred threats", "\n".join(str(t) for t in threats))

        except Exception as e:
            thinking.stop()
            ui.error(_main_t(args.lang, "failed_analyze_threats"), str(e))
            sys.exit(2)

        # 5) De-noise & trim
        ui.step(_main_t(args.lang, "filtering_threats"))
        ui.info(_main_t(args.lang, "applying_filtering"))

        try:
            original_count = len(threats)
            threats = denoise_threats(
                threats,
                require_asvs=args.require_asvs,
                min_confidence=args.min_confidence,
                topn=args.topn,
            )

            filtered_count = original_count - len(threats)
            if filtered_count > 0:
                ui.info(
                    _main_t(args.lang, "filtered_low_confidence", count=filtered_count)
                )

            ui.success(_main_t(args.lang, "finalized_threats", count=len(threats)))
            ui.show_threats_preview(threats)
            ui.debug(
                "Threats after de-noising/filtering", "\n".join(str(t) for t in threats)
            )

        except Exception as e:
            ui.error(_main_t(args.lang, "failed_filter_threats"), str(e))
            sys.exit(2)

        # 6) Export
        ui.step(_main_t(args.lang, "generating_reports"))
        base_name = args.out_name or _default_report_base_name(
            diagram_file,
            getattr(args, "description_file", None) or [],
        )
        out_dir, out_json, out_md, out_html = _prepare_output_paths(
            diagram_file or base_name, args.out_dir, base_name
        )
        ui.info(
            _main_t(
                args.lang,
                "exporting_reports",
                out_dir=out_dir,
                json_name=out_json.name,
                md_name=out_md.name,
                html_name=out_html.name,
            )
        )

        try:
            json_output = export_json(threats, str(out_json), metrics, g)
            md_output = export_md(threats, str(out_md), args.lang)
            html_output = export_html(threats, str(out_html), g, args.lang)
            td_output = None
            td_path = None
            if g.source_format == "threat-dragon" and g.threat_dragon:
                td_path = out_dir / f"{out_json.stem}.threat-dragon.json"
                try:
                    td_output = export_threat_dragon(threats, g, str(td_path))
                    ui.success(_main_t(args.lang, "td_saved", path=td_path))
                except Exception as exc:
                    ui.warning(_main_t(args.lang, "td_skipped"), str(exc))

            ui.success(_main_t(args.lang, "json_saved", path=out_json))
            ui.success(_main_t(args.lang, "md_saved", path=out_md))
            ui.success(_main_t(args.lang, "html_saved", path=out_html))
            if dfd_result:
                dfd_path = _prepare_dfd_sidecar_path(out_json)
                dfd_path.write_text(
                    dfd_result_to_sidecar_json(dfd_result), encoding="utf-8"
                )
                ui.success(_main_t(args.lang, "dfd_sidecar_saved", path=dfd_path))

            if args.verbose:
                print(f"\n{_main_t(args.lang, 'json_output')}")
                print(json_output)
                print(f"\n{_main_t(args.lang, 'markdown_output')}")
                print(md_output)
                print(f"\n{_main_t(args.lang, 'html_output')}")
                print(html_output)
                if td_output:
                    print(f"\n{_main_t(args.lang, 'td_output')}")
                    print(td_output)
            else:
                ui.debug("JSON output", json_output)
                ui.debug("Markdown output", md_output)
                ui.debug("HTML output", html_output)
                if td_output:
                    ui.debug("Threat Dragon output", td_output)

        except Exception as e:
            ui.error(_main_t(args.lang, "failed_export_reports"), str(e))
            sys.exit(2)

        # Show final summary
        end_time = time.time()
        processing_time = end_time - start_time
        ui.show_summary(len(threats), processing_time)

    elif args.cmd == "kb":
        set_verbose(args.verbose)

        if args.kb_cmd == "list":
            entries = list_kbs()
            root = get_kb_root()
            if not entries:
                ui.info(
                    f"No knowledge bases found under {root}.",
                    "Use `threat-thinker kb build <name>` after adding documents to raw/.",
                )
            else:
                ui.info(f"Knowledge bases stored in {root}:")
                for entry in entries:
                    updated = entry.get("updated_at") or "unknown"
                    num_chunks = entry.get("num_chunks", 0)
                    num_docs = entry.get("num_documents", 0)
                    model = entry.get("embedding_model") or DEFAULT_EMBED_MODEL
                    print(
                        f"  • {entry['name']}: {num_chunks} chunks from {num_docs} docs (model={model}, updated={updated})"
                    )
        elif args.kb_cmd == "build":
            if not os.getenv("OPENAI_API_KEY"):
                ui.error(
                    "OPENAI_API_KEY is required to build a knowledge base.",
                    "Set your OpenAI key before invoking embeddings.",
                )
                sys.exit(2)
            embed_model = _normalize_embed_model(args.embedder)
            try:
                meta = build_kb(
                    args.kb_name,
                    embed_model=embed_model,
                    chunk_tokens=args.chunk_tokens,
                    chunk_overlap=args.chunk_overlap,
                )
                ui.success(
                    f"KB '{args.kb_name}' built with {meta['num_chunks']} chunks using {meta['embedding_model']}"
                )
            except KnowledgeBaseError as e:
                ui.error("Failed to build knowledge base", str(e))
                sys.exit(2)
        elif args.kb_cmd == "search":
            if not os.getenv("OPENAI_API_KEY"):
                ui.error(
                    "OPENAI_API_KEY is required for semantic search.",
                    "Set your OpenAI key before executing `kb search`.",
                )
                sys.exit(2)
            try:
                results = search_kb(
                    args.kb_name,
                    args.query,
                    topk=args.topk,
                )
            except KnowledgeBaseError as e:
                ui.error("KB search failed", str(e))
                sys.exit(2)

            if not results:
                ui.info("No chunks matched the query.")
            else:
                ui.info(f"Top {len(results)} chunks:")
                for idx, item in enumerate(results, 1):
                    print(
                        f"  {idx}. KB={item['kb']} chunk={item['chunk_id']} "
                        f"score={item['score']:.3f} source={item.get('source')}"
                    )
                    if args.show:
                        snippet = (item["text"] or "").strip()
                        if len(snippet) > 400:
                            snippet = snippet[:400] + "..."
                        print(f"     {snippet}")
        elif args.kb_cmd == "remove":
            kb_name = args.kb_name
            if not args.force:
                confirmation = input(
                    f"Delete knowledge base '{kb_name}'? This cannot be undone. [y/N]: "
                ).strip()
                if confirmation.lower() not in {"y", "yes"}:
                    ui.info("Aborted knowledge base removal.")
                    return
            try:
                remove_kb(kb_name)
                ui.success(f"Removed knowledge base '{kb_name}'.")
            except KnowledgeBaseError as e:
                ui.error("KB removal failed", str(e))
                sys.exit(2)

    elif args.cmd == "diff":
        start_time = time.time()

        # Set verbose mode
        set_verbose(args.verbose)
        set_locale(args.lang)

        # Check for required API keys/credentials
        if args.llm_api.lower() == "openai" and not os.getenv("OPENAI_API_KEY"):
            ui.error(
                _main_t(args.lang, "openai_key_title"),
                _main_t(args.lang, "openai_key_detail"),
            )
            sys.exit(2)
        elif args.llm_api.lower() == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
            ui.error(
                _main_t(args.lang, "anthropic_key_title"),
                _main_t(args.lang, "anthropic_key_detail"),
            )
            sys.exit(2)
        elif args.llm_api.lower() == "bedrock":
            if not args.aws_profile and not (
                os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
            ):
                ui.warning(
                    _main_t(args.lang, "aws_credentials_title"),
                    _main_t(args.lang, "aws_credentials_detail"),
                )

        ollama_host = (
            args.ollama_host or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
        )
        if args.llm_api.lower() == "ollama":
            normalized_model = (args.llm_model or "").strip().lower()
            if not normalized_model or normalized_model.startswith("gpt-4"):
                args.llm_model = "llama3.1"

        ui.info(
            _main_t(
                args.lang, "comparing_reports", before=args.before, after=args.after
            )
        )
        out_dir, diff_json_path, diff_md_path = _prepare_diff_output_paths(
            args.after, args.out_dir
        )

        thinking = ui.create_thinking_indicator(
            _main_t(args.lang, "analyzing_report_differences")
        )
        thinking.start()

        try:
            d = diff_reports(
                args.after,
                args.before,
                args.llm_api,
                args.llm_model,
                args.aws_profile,
                args.aws_region,
                ollama_host,
                args.lang,
            )
            thinking.stop()

            # Show summary of changes
            graph_changes = d.get("graph_changes", {})
            threat_changes = d.get("threat_changes", {})

            ui.success(_main_t(args.lang, "diff_completed"))
            ui.info(_main_t(args.lang, "changes_summary"))
            print(
                "  • "
                + _main_t(
                    args.lang,
                    "nodes_delta",
                    added=graph_changes.get("count_nodes_added", 0),
                    removed=graph_changes.get("count_nodes_removed", 0),
                )
            )
            print(
                "  • "
                + _main_t(
                    args.lang,
                    "edges_delta",
                    added=graph_changes.get("count_edges_added", 0),
                    removed=graph_changes.get("count_edges_removed", 0),
                )
            )
            print(
                "  • "
                + _main_t(
                    args.lang,
                    "threats_delta",
                    added=threat_changes.get("count_added", 0),
                    removed=threat_changes.get("count_removed", 0),
                )
            )

            s = json.dumps(d, ensure_ascii=False, indent=2)
            with open(diff_json_path, "w", encoding="utf-8") as f:
                f.write(s)
            ui.success(_main_t(args.lang, "diff_json_saved", path=diff_json_path))

            md_output = export_diff_md(d, str(diff_md_path), args.lang)
            ui.success(_main_t(args.lang, "diff_md_saved", path=diff_md_path))
            if args.verbose:
                print(f"\n{_main_t(args.lang, 'markdown_diff_output')}")
                print(md_output)

            if args.verbose:
                print(f"\n{_main_t(args.lang, 'json_diff_output')}")
                print(s)

        except Exception as e:
            thinking.stop()
            ui.error(_main_t(args.lang, "failed_generate_diff"), str(e))
            sys.exit(2)

        end_time = time.time()
        processing_time = end_time - start_time
        ui.info(_main_t(args.lang, "diff_completed_in", seconds=processing_time))
    elif args.cmd == "serve":
        cfg = load_config(args.config)
        logging.basicConfig(level=cfg.observability.log_level.upper())
        app = create_app(cfg)
        uvicorn.run(
            app,
            host=cfg.server.bind,
            port=cfg.server.port,
            log_level=cfg.observability.log_level.lower(),
        )
    elif args.cmd == "worker":
        cfg = load_config(args.config)
        logging.basicConfig(level=cfg.observability.log_level.upper())
        run_worker(cfg)
    elif args.cmd == "webui":
        ui.info("Starting Threat Thinker Web UI")

        webui.launch_webui(
            server_name=args.host,
            server_port=args.port,
        )


if __name__ == "__main__":
    main()
