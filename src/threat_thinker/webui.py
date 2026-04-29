"""
Threat Thinker WebUI powered by Gradio.
"""

import atexit
import json
import os
import shutil
import tempfile
import traceback
import html
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import gradio as gr

import threat_thinker.main as cli
from threat_thinker.business_context import (
    dfd_result_from_payload,
    dfd_result_to_sidecar_json,
)
from threat_thinker.constants import AI_OUTPUT_DISCLAIMER_EN, AI_OUTPUT_DISCLAIMER_JA
from threat_thinker.input_loader import (
    INPUT_FORMAT_DRAWIO,
    INPUT_FORMAT_IR,
    INPUT_FORMAT_MERMAID,
    INPUT_FORMAT_THREAT_DRAGON,
    TEXT_INPUT_FORMATS,
    load_input,
    suffix_for_text_input,
)
from threat_thinker.exporters import diff_reports, export_diff_md
from threat_thinker.context_loader import (
    ContextDocumentError,
    SUPPORTED_CONTEXT_EXTENSIONS,
    context_summary,
    format_context_documents,
    load_context_documents,
)
from threat_thinker.rag import (
    KnowledgeBaseError,
    DEFAULT_CHUNK_OVERLAP,
    DEFAULT_CHUNK_TOKENS,
    DEFAULT_TOPK,
    DEFAULT_RAG_STRATEGY,
    DEFAULT_RAG_RERANKER,
    DEFAULT_RAG_CANDIDATES,
    DEFAULT_RAG_MIN_SCORE,
    DEFAULT_EMBED_MODEL,
    RAG_STRATEGIES,
    RAG_RERANKERS,
    RetrievalOptions,
    build_kb,
    get_kb_root,
    list_kbs,
    remove_kb,
    retrieve_context_for_graph,
    attach_rag_sources_to_threats,
)
from threat_thinker.llm.inference import (
    llm_generate_dfd_from_description,
    llm_rerank_chunks,
)
from threat_thinker.rag.local import SUPPORTED_EXTENSIONS


_DOWNLOAD_PATHS: set[str] = set()
_DEFAULT_UI_LOCALE = "en"
_SUPPORTED_UI_LOCALES = ("en", "ja")
_INPUT_METHOD_TEXT = "text"
_INPUT_METHOD_IMAGE = "image"
_UI_TEXT = {
    "en": {
        "intro_heading": "## Threat Thinker WebUI",
        "intro_body": "Analyze system diagrams for security threats or compare threat reports.",
        "ui_language_label": "UI Language / 表示言語",
        "think_tab": "Think - Threat Analysis",
        "kb_tab": "KB - Knowledge Base",
        "diff_tab": "Diff - Report Comparison",
        "system_description_label": "System Description",
        "system_description_placeholder": (
            "Describe the system, users, data, deployment, and external services. "
            "Example: Customers use a web app to manage orders. The app runs on AWS behind a load balancer, "
            "stores PII in Postgres, and sends emails through a third-party provider."
        ),
        "business_context_label": "Business Context (supplemental PDF, Markdown, Text)",
        "advanced_diagram_accordion": "Advanced: provide an existing DFD or diagram",
        "diagram_input_method_label": "Diagram Input Method",
        "input_method_text": "Text",
        "input_method_image": "Image",
        "diagram_content_label": "Diagram Content",
        "diagram_content_placeholder": "Paste Mermaid, Draw.io XML, Threat Dragon JSON, or native IR JSON...",
        "diagram_format_label": "Diagram Format",
        "drawio_page_label": "Draw.io Page (optional)",
        "drawio_page_placeholder": "Page id, name, or 0-based index",
        "upload_diagram_image_label": "Upload Diagram Image (JPG, PNG, GIF, BMP, WebP)",
        "llm_api_label": "LLM API",
        "llm_model_label": "LLM Model",
        "llm_model_placeholder": "e.g., gpt-4.1, claude-3-haiku-20240307, anthropic.claude-3-5-sonnet-20240620-v1:0",
        "aws_profile_label": "AWS Profile (for Bedrock only)",
        "aws_profile_placeholder": "e.g., my-profile (optional, leave empty to use default credentials)",
        "aws_region_label": "AWS Region (for Bedrock only)",
        "aws_region_placeholder": "e.g., us-east-1 (optional, defaults to us-east-1)",
        "ollama_host_label": "Ollama Host",
        "ollama_host_placeholder": "http://localhost:11434",
        "infer_hints_label": "Infer hints with LLM",
        "require_asvs_label": "Require ASVS references",
        "topn_label": "Top N threats",
        "min_confidence_label": "Minimum confidence",
        "output_language_label": "Output language (ISO code) - LLM will generate reports in this language.",
        "output_language_placeholder": "e.g., en, ja, fr, de, es, zh, ko, pt, it, ru, ar, hi, th, vi",
        "use_kb_label": "Use Knowledge Base (local RAG)",
        "knowledge_bases_label": "Knowledge Bases",
        "knowledge_bases_info": "Build or refresh knowledge bases in the Knowledge Base tab.",
        "rag_topk_label": "RAG top-k (retrieved chunks)",
        "rag_advanced_accordion": "RAG Advanced Settings",
        "rag_strategy_label": "RAG strategy",
        "rag_reranker_label": "RAG reranker",
        "rag_candidates_label": "RAG candidates before reranking",
        "rag_min_score_label": "RAG min score",
        "prompt_advanced_accordion": "Prompt Advanced Settings",
        "prompt_token_limit_label": "Prompt token limit",
        "prompt_token_limit_info": "Leave empty to use the provider default.",
        "generate_report_button": "Generate Report",
        "markdown_preview_tab": "Markdown Preview",
        "raw_text_tab": "Raw Text",
        "report_preview_markdown_label": "Report Preview (Markdown)",
        "report_preview_default": "Generate a report to see the preview here...",
        "report_preview_raw_label": "Report Preview (Raw)",
        "download_md_label": "Download Markdown report",
        "download_json_label": "Download JSON report",
        "download_html_label": "Download HTML report",
        "download_td_label": "Download Threat Dragon JSON (Threat Dragon inputs only)",
        "download_dfd_label": "Download generated DFD JSON (description inputs only)",
        "kb_intro_md": (
            "### Build Knowledge Base\n"
            "Upload documents to create a local knowledge base for retrieval in threat analysis."
        ),
        "kb_name_label": "Knowledge Base Name",
        "kb_name_placeholder": "e.g., security-standards",
        "kb_upload_label": "Upload documents (PDF, Markdown, Text, HTML)",
        "kb_embedder_label": "Embedding model (OpenAI)",
        "kb_embedder_placeholder": "openai:text-embedding-3-small",
        "kb_replace_raw_label": "Replace existing raw documents",
        "chunk_tokens_label": "Chunk tokens",
        "chunk_overlap_label": "Chunk overlap",
        "build_kb_button": "Build Knowledge Base",
        "kb_status_default": "Upload documents and click build to create a knowledge base.",
        "refresh_kbs_button": "Refresh Knowledge Bases",
        "kb_delete_select_label": "Select KB to delete",
        "delete_kb_button": "Delete Selected KB",
        "diff_intro_md": (
            "### Compare Threat Reports\n"
            "Upload two JSON threat reports to analyze differences and generate a comparison report."
        ),
        "before_report_label": "Before Report (JSON)",
        "after_report_label": "After Report (JSON)",
        "generate_diff_button": "Generate Diff Report",
        "diff_report_preview_markdown_label": "Diff Report Preview (Markdown)",
        "diff_report_preview_default": "Upload two JSON reports and generate a diff to see the comparison here...",
        "diff_report_preview_raw_label": "Diff Report Preview (Raw JSON)",
        "download_md_diff_label": "Download Markdown diff report",
        "download_json_diff_label": "Download JSON diff report",
        "incomplete_dfd_title": "## System Description Needs More Detail",
        "incomplete_dfd_reason": "Threat inference did not run because the generated DFD was empty.",
        "summary_label": "Summary",
        "assumptions_label": "Assumptions",
        "clarifying_questions_label": "Clarifying Questions",
        "error_unsupported_diagram_format": "Unsupported diagram format: {value}",
        "error_kb_name_required": "Knowledge base name is required.",
        "error_kb_name_path_separators": "Knowledge base name cannot contain path separators.",
        "kb_list_empty": "No knowledge bases found under {kb_root}.",
        "kb_list_empty_hint": "Use the Knowledge Base tab to upload documents and build one.",
        "kb_list_available": "Available knowledge bases:",
        "kb_list_unknown_updated": "unknown",
        "kb_list_entry": "- `{name}`: {chunks} chunks from {docs} docs (model={model}, updated={updated})",
        "kb_list_storage": "Storage location: {kb_root}",
        "error_upload_doc_required": "Please upload at least one document to build the knowledge base.",
        "error_uploaded_file_not_found": "Uploaded file not found: {path}",
        "error_unsupported_file_type": "Unsupported file type: {suffix}. Supported: {supported}",
        "error_context_file_not_found": "Uploaded context file not found: {path}",
        "error_unsupported_context_file_type": "Unsupported context file type: {suffix}. Supported: {supported}",
        "error_failed_remove_kb": "Failed to remove knowledge base: {error}",
        "status_removed_kb": "Removed knowledge base `{name}`.",
        "error_openai_key_required_build_kb": "OPENAI_API_KEY is required to build a knowledge base.\nSet the environment variable and retry.",
        "error_chunk_tokens_positive": "Chunk tokens must be a positive integer.",
        "error_chunk_overlap_nonnegative": "Chunk overlap cannot be negative.",
        "status_stored_documents": "Stored {count} documents under `{path}`.",
        "status_built_kb": "Built KB `{name}` with {chunks} chunks from {docs} documents.",
        "status_embedding_model": "Embedding model: `{model}`",
        "error_failed_build_kb": "Failed to build knowledge base: {error}",
        "error_diff_files_required": "Both before and after JSON files are required for diff analysis.",
        "file_label_before": "Before",
        "file_label_after": "After",
        "error_file_must_be_json": "{label} file must be a JSON file.",
        "error_failed_generate_diff_report": "Failed to generate diff report: {error}",
        "error_system_description_required": "System description is required when no diagram is provided.",
        "error_unsupported_image_format": "Unsupported image format: {ext}. Supported formats: {supported}",
        "error_prompt_token_limit_positive": "Prompt token limit must be a positive integer.",
        "error_ollama_image_not_supported": (
            "Image diagrams are not supported with the Ollama backend. "
            "Use OpenAI/Anthropic/Bedrock for image extraction or provide Mermaid/Draw.io/Threat Dragon/IR input."
        ),
        "error_openai_key_required_rag": "OPENAI_API_KEY is required for local RAG. Set it and retry.",
        "error_select_kb_for_rag": "Select at least one knowledge base when RAG is enabled.",
        "error_rag_topk_positive": "RAG top-k must be a positive integer.",
        "error_rag_candidates_positive": "RAG candidates must be a positive integer.",
        "error_rag_min_score_range": "RAG min score must be between 0 and 1.",
        "error_unsupported_rag_strategy": "Unsupported rag strategy: {value}. Supported: {supported}",
        "error_unsupported_rag_reranker": "Unsupported rag reranker: {value}. Supported: {supported}",
        "status_parsed_diagram": "Parsed {diagram_format} diagram: {nodes} nodes, {edges} edges.",
        "status_parsed_image_diagram": "Parsed image diagram: {nodes} nodes, {edges} edges.",
        "status_generated_dfd": "Generated DFD from system description: {nodes} nodes, {edges} edges.",
        "status_dfd_summary": "DFD summary: {summary}",
        "status_assumptions": "Assumptions: {items}",
        "status_clarifying_questions": "Clarifying questions: {items}",
        "status_threat_inference_skipped_empty_dfd": "Threat inference skipped because the generated DFD is empty. Expand the system description and retry.",
        "status_label": "Status",
        "status_generated_dfd_json": "Generated DFD JSON",
        "status_import_success": "Import success ~{percent:.1f}% (edges {edges_parsed}/{edge_candidates}, labels {labels_parsed}/{label_candidates})",
        "status_applied_llm_hints": "Applied LLM-inferred hints.",
        "status_loaded_business_context": "Loaded {count} business context document(s), approximately {tokens} tokens: {sources}.",
        "error_failed_load_business_context": "Failed to load business context: {error}",
        "status_retrieved_knowledge_chunks": "Retrieved {count} knowledge chunks from {kb_names}.",
        "status_rag_strategy": "RAG strategy={strategy}, reranker={reranker}.",
        "status_no_knowledge_snippets": "No knowledge snippets retrieved; continuing without RAG context.",
        "error_failed_retrieve_local_knowledge": "Failed to retrieve local knowledge: {error}",
        "status_excluded_threats_without_rag": "Excluded {count} threats without RAG document attribution.",
        "status_llm_returned_threats": "LLM returned {count} threats before filtering.",
        "status_threats_after_filter": "{count} threats after filtering.",
        "status_td_generated": "Threat Dragon JSON generated from Threat Dragon input.",
        "status_td_export_skipped": "Threat Dragon export skipped: {error}",
        "status_report_generated_successfully": "Report generated successfully.",
        "status_json_report": "JSON Report",
        "status_markdown_report": "Markdown Report",
        "status_html_report": "HTML Report",
        "status_td_report": "Threat Dragon Report",
        "error_failed_generate_report": "Failed to generate report: {error}",
    },
    "ja": {
        "intro_heading": "## Threat Thinker WebUI",
        "intro_body": "システム構成図を解析してセキュリティ脅威を洗い出すか、脅威レポート同士を比較します。",
        "ui_language_label": "表示言語 / UI Language",
        "think_tab": "Think - 脅威分析",
        "kb_tab": "KB - ナレッジベース",
        "diff_tab": "Diff - レポート比較",
        "system_description_label": "システム説明",
        "system_description_placeholder": (
            "システム、利用者、データ、配置、外部サービスを説明してください。"
            "例: 顧客は注文管理のために Web アプリを利用する。アプリはロードバランサ配下の AWS 上で動作し、"
            "顧客の個人情報を Postgres に保存し、サードパーティのメールサービスを利用する。"
        ),
        "business_context_label": "Business Context（補足 PDF / Markdown / Text）",
        "advanced_diagram_accordion": "詳細設定: 既存の DFD または図を指定",
        "diagram_input_method_label": "図の入力方法",
        "input_method_text": "テキスト",
        "input_method_image": "画像",
        "diagram_content_label": "図の内容",
        "diagram_content_placeholder": "Mermaid、Draw.io XML、Threat Dragon JSON、またはネイティブ IR JSON を貼り付け...",
        "diagram_format_label": "図の形式",
        "drawio_page_label": "Draw.io ページ（任意）",
        "drawio_page_placeholder": "ページ ID、名前、または 0 始まりのインデックス",
        "upload_diagram_image_label": "図の画像をアップロード（JPG, PNG, GIF, BMP, WebP）",
        "llm_api_label": "LLM API",
        "llm_model_label": "LLM モデル",
        "llm_model_placeholder": "例: gpt-4.1, claude-3-haiku-20240307, anthropic.claude-3-5-sonnet-20240620-v1:0",
        "aws_profile_label": "AWS Profile（Bedrock のみ）",
        "aws_profile_placeholder": "例: my-profile（任意、空なら既定の認証情報を使用）",
        "aws_region_label": "AWS Region（Bedrock のみ）",
        "aws_region_placeholder": "例: us-east-1（任意、既定は us-east-1）",
        "ollama_host_label": "Ollama ホスト",
        "ollama_host_placeholder": "http://localhost:11434",
        "infer_hints_label": "LLM でヒントを推論する",
        "require_asvs_label": "ASVS 参照を必須にする",
        "topn_label": "上位 N 件の脅威",
        "min_confidence_label": "最小信頼度",
        "output_language_label": "出力言語（ISO コード）- レポートはこの言語で生成されます。",
        "output_language_placeholder": "例: en, ja, fr, de, es, zh, ko, pt, it, ru, ar, hi, th, vi",
        "use_kb_label": "ナレッジベースを使う（ローカル RAG）",
        "knowledge_bases_label": "ナレッジベース",
        "knowledge_bases_info": "ナレッジベースの作成や更新は Knowledge Base タブで行います。",
        "rag_topk_label": "RAG top-k（取得チャンク数）",
        "rag_advanced_accordion": "RAG 詳細設定",
        "rag_strategy_label": "RAG 戦略",
        "rag_reranker_label": "RAG リランカー",
        "rag_candidates_label": "リランキング前の RAG 候補数",
        "rag_min_score_label": "RAG 最小スコア",
        "prompt_advanced_accordion": "プロンプト詳細設定",
        "prompt_token_limit_label": "プロンプトのトークン上限",
        "prompt_token_limit_info": "空欄の場合はプロバイダ既定値を使います。",
        "generate_report_button": "レポートを生成",
        "markdown_preview_tab": "Markdown プレビュー",
        "raw_text_tab": "Raw Text",
        "report_preview_markdown_label": "レポートプレビュー（Markdown）",
        "report_preview_default": "レポートを生成すると、ここにプレビューが表示されます...",
        "report_preview_raw_label": "レポートプレビュー（Raw）",
        "download_md_label": "Markdown レポートをダウンロード",
        "download_json_label": "JSON レポートをダウンロード",
        "download_html_label": "HTML レポートをダウンロード",
        "download_td_label": "Threat Dragon JSON をダウンロード（Threat Dragon 入力時のみ）",
        "download_dfd_label": "生成された DFD JSON をダウンロード（説明入力時のみ）",
        "kb_intro_md": (
            "### ナレッジベースを構築\n"
            "文書をアップロードして、脅威分析時に参照できるローカルナレッジベースを作成します。"
        ),
        "kb_name_label": "ナレッジベース名",
        "kb_name_placeholder": "例: security-standards",
        "kb_upload_label": "文書をアップロード（PDF, Markdown, Text, HTML）",
        "kb_embedder_label": "埋め込みモデル（OpenAI）",
        "kb_embedder_placeholder": "openai:text-embedding-3-small",
        "kb_replace_raw_label": "既存の raw 文書を置き換える",
        "chunk_tokens_label": "チャンクのトークン数",
        "chunk_overlap_label": "チャンク重複数",
        "build_kb_button": "ナレッジベースを構築",
        "kb_status_default": "文書をアップロードし、構築をクリックしてナレッジベースを作成してください。",
        "refresh_kbs_button": "ナレッジベースを更新",
        "kb_delete_select_label": "削除する KB を選択",
        "delete_kb_button": "選択した KB を削除",
        "diff_intro_md": (
            "### 脅威レポートを比較\n"
            "2 つの JSON 脅威レポートをアップロードして差分を解析し、比較レポートを生成します。"
        ),
        "before_report_label": "変更前レポート（JSON）",
        "after_report_label": "変更後レポート（JSON）",
        "generate_diff_button": "差分レポートを生成",
        "diff_report_preview_markdown_label": "差分レポートプレビュー（Markdown）",
        "diff_report_preview_default": "2 つの JSON レポートをアップロードして差分を生成すると、ここに比較結果が表示されます...",
        "diff_report_preview_raw_label": "差分レポートプレビュー（Raw JSON）",
        "download_md_diff_label": "Markdown 差分レポートをダウンロード",
        "download_json_diff_label": "JSON 差分レポートをダウンロード",
        "incomplete_dfd_title": "## システム説明の詳細が不足しています",
        "incomplete_dfd_reason": "生成された DFD が空だったため、脅威推論は実行されませんでした。",
        "summary_label": "要約",
        "assumptions_label": "前提",
        "clarifying_questions_label": "確認したい点",
        "error_unsupported_diagram_format": "未対応の図形式です: {value}",
        "error_kb_name_required": "ナレッジベース名は必須です。",
        "error_kb_name_path_separators": "ナレッジベース名にパス区切り文字は使えません。",
        "kb_list_empty": "{kb_root} 配下にナレッジベースがありません。",
        "kb_list_empty_hint": "Knowledge Base タブから文書をアップロードして作成してください。",
        "kb_list_available": "利用可能なナレッジベース:",
        "kb_list_unknown_updated": "不明",
        "kb_list_entry": "- `{name}`: {docs} 件の文書から {chunks} チャンク（model={model}, updated={updated}）",
        "kb_list_storage": "保存先: {kb_root}",
        "error_upload_doc_required": "ナレッジベース構築には少なくとも 1 つの文書をアップロードしてください。",
        "error_uploaded_file_not_found": "アップロードされたファイルが見つかりません: {path}",
        "error_unsupported_file_type": "未対応のファイル形式です: {suffix}。対応形式: {supported}",
        "error_context_file_not_found": "アップロードされたコンテキストファイルが見つかりません: {path}",
        "error_unsupported_context_file_type": "未対応のコンテキスト形式です: {suffix}。対応形式: {supported}",
        "error_failed_remove_kb": "ナレッジベースの削除に失敗しました: {error}",
        "status_removed_kb": "ナレッジベース `{name}` を削除しました。",
        "error_openai_key_required_build_kb": "ナレッジベース構築には OPENAI_API_KEY が必要です。\n環境変数を設定して再実行してください。",
        "error_chunk_tokens_positive": "チャンクのトークン数は正の整数である必要があります。",
        "error_chunk_overlap_nonnegative": "チャンク重複数は 0 以上である必要があります。",
        "status_stored_documents": "{count} 件の文書を `{path}` に保存しました。",
        "status_built_kb": "KB `{name}` を構築しました。{docs} 件の文書から {chunks} チャンクを作成しました。",
        "status_embedding_model": "埋め込みモデル: `{model}`",
        "error_failed_build_kb": "ナレッジベースの構築に失敗しました: {error}",
        "error_diff_files_required": "差分分析には変更前後の JSON ファイルが両方必要です。",
        "file_label_before": "変更前",
        "file_label_after": "変更後",
        "error_file_must_be_json": "{label} ファイルは JSON である必要があります。",
        "error_failed_generate_diff_report": "差分レポートの生成に失敗しました: {error}",
        "error_system_description_required": "図がない場合はシステム説明が必要です。",
        "error_unsupported_image_format": "未対応の画像形式です: {ext}。対応形式: {supported}",
        "error_prompt_token_limit_positive": "プロンプトのトークン上限は正の整数である必要があります。",
        "error_ollama_image_not_supported": (
            "Ollama バックエンドでは画像図をサポートしていません。"
            "画像抽出には OpenAI / Anthropic / Bedrock を使うか、Mermaid / Draw.io / Threat Dragon / IR 入力を指定してください。"
        ),
        "error_openai_key_required_rag": "ローカル RAG には OPENAI_API_KEY が必要です。設定して再実行してください。",
        "error_select_kb_for_rag": "RAG を有効にした場合は少なくとも 1 つのナレッジベースを選択してください。",
        "error_rag_topk_positive": "RAG top-k は正の整数である必要があります。",
        "error_rag_candidates_positive": "RAG 候補数は正の整数である必要があります。",
        "error_rag_min_score_range": "RAG 最小スコアは 0 から 1 の間で指定してください。",
        "error_unsupported_rag_strategy": "未対応の rag strategy です: {value}。対応: {supported}",
        "error_unsupported_rag_reranker": "未対応の rag reranker です: {value}。対応: {supported}",
        "status_parsed_diagram": "{diagram_format} 図を解析しました: ノード {nodes} 件、エッジ {edges} 件。",
        "status_parsed_image_diagram": "画像図を解析しました: ノード {nodes} 件、エッジ {edges} 件。",
        "status_generated_dfd": "システム説明から DFD を生成しました: ノード {nodes} 件、エッジ {edges} 件。",
        "status_dfd_summary": "DFD 要約: {summary}",
        "status_assumptions": "前提: {items}",
        "status_clarifying_questions": "確認したい点: {items}",
        "status_threat_inference_skipped_empty_dfd": "生成された DFD が空のため、脅威推論をスキップしました。システム説明を詳しくして再実行してください。",
        "status_label": "ステータス",
        "status_generated_dfd_json": "生成された DFD JSON",
        "status_import_success": "入力解析成功率 約 {percent:.1f}%（edges {edges_parsed}/{edge_candidates}, labels {labels_parsed}/{label_candidates}）",
        "status_applied_llm_hints": "LLM が推論したヒントを適用しました。",
        "status_loaded_business_context": "Business Context 文書 {count} 件を読み込みました。概算 {tokens} トークン: {sources}。",
        "error_failed_load_business_context": "Business Context の読み込みに失敗しました: {error}",
        "status_retrieved_knowledge_chunks": "{kb_names} から {count} 件のナレッジチャンクを取得しました。",
        "status_rag_strategy": "RAG strategy={strategy}, reranker={reranker}。",
        "status_no_knowledge_snippets": "ナレッジ断片を取得できなかったため、RAG コンテキストなしで続行します。",
        "error_failed_retrieve_local_knowledge": "ローカルナレッジの取得に失敗しました: {error}",
        "status_excluded_threats_without_rag": "RAG 文書の根拠がない脅威 {count} 件を除外しました。",
        "status_llm_returned_threats": "フィルタ前の脅威件数: {count} 件。",
        "status_threats_after_filter": "フィルタ後の脅威件数: {count} 件。",
        "status_td_generated": "Threat Dragon 入力から Threat Dragon JSON を生成しました。",
        "status_td_export_skipped": "Threat Dragon エクスポートをスキップしました: {error}",
        "status_report_generated_successfully": "レポートを生成しました。",
        "status_json_report": "JSON レポート",
        "status_markdown_report": "Markdown レポート",
        "status_html_report": "HTML レポート",
        "status_td_report": "Threat Dragon レポート",
        "error_failed_generate_report": "レポート生成に失敗しました: {error}",
    },
}


def _normalize_ui_locale(ui_locale: Optional[str]) -> str:
    value = (ui_locale or _DEFAULT_UI_LOCALE).strip().lower()
    if value not in _SUPPORTED_UI_LOCALES:
        return _DEFAULT_UI_LOCALE
    return value


def _t(ui_locale: Optional[str], key: str, **kwargs) -> str:
    locale = _normalize_ui_locale(ui_locale)
    template = _UI_TEXT[locale][key]
    return template.format(**kwargs) if kwargs else template


def _disclaimer_markdown(ui_locale: Optional[str]) -> str:
    message = (
        AI_OUTPUT_DISCLAIMER_JA
        if _normalize_ui_locale(ui_locale) == "ja"
        else AI_OUTPUT_DISCLAIMER_EN
    )
    return f"> [!IMPORTANT]\n> {message}"


def _intro_markdown(ui_locale: Optional[str]) -> str:
    return "\n".join(
        [
            _t(ui_locale, "intro_heading"),
            _t(ui_locale, "intro_body"),
            "",
            _disclaimer_markdown(ui_locale),
        ]
    )


def _default_output_language(ui_locale: Optional[str]) -> str:
    return "ja" if _normalize_ui_locale(ui_locale) == "ja" else "en"


def _input_method_choices(ui_locale: Optional[str]) -> list[tuple[str, str]]:
    return [
        (_t(ui_locale, "input_method_text"), _INPUT_METHOD_TEXT),
        (_t(ui_locale, "input_method_image"), _INPUT_METHOD_IMAGE),
    ]


def _preserve_or_localize_default(
    current_value: Optional[str], ui_locale: Optional[str], key: str
) -> str:
    known_defaults = {_UI_TEXT[locale][key] for locale in _SUPPORTED_UI_LOCALES}
    if not current_value or current_value in known_defaults:
        return _t(ui_locale, key)
    return current_value


def _sync_output_language_with_locale(
    ui_locale: Optional[str], current_value: Optional[str], is_manual: bool
) -> tuple[str, bool]:
    next_auto = _default_output_language(ui_locale)
    current = (current_value or "").strip()
    if not current or not is_manual:
        return next_auto, False
    return current, True


def _output_language_is_manual(
    current_value: Optional[str], ui_locale: Optional[str]
) -> bool:
    value = (current_value or "").strip()
    return bool(value) and value != _default_output_language(ui_locale)


def _cleanup_downloads(exclude: Optional[str] = None) -> None:
    """Remove generated download files from disk."""
    for path in list(_DOWNLOAD_PATHS):
        if exclude and path == exclude:
            continue
        if os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass
        _DOWNLOAD_PATHS.discard(path)


atexit.register(_cleanup_downloads)


def _setup_gradio_temp_dir() -> Callable[[], None]:
    """Ensure Gradio writes to a dedicated temp directory we can clean up."""
    prev_dir = os.environ.get("GRADIO_TEMP_DIR")
    temp_dir = tempfile.mkdtemp(prefix="threat_thinker_gradio_")
    os.environ["GRADIO_TEMP_DIR"] = temp_dir
    cleaned = {"done": False}

    def _cleanup() -> None:
        if cleaned["done"]:
            return
        cleaned["done"] = True
        _cleanup_downloads()
        shutil.rmtree(temp_dir, ignore_errors=True)
        if prev_dir is None:
            os.environ.pop("GRADIO_TEMP_DIR", None)
        else:
            os.environ["GRADIO_TEMP_DIR"] = prev_dir

    atexit.register(_cleanup)
    return _cleanup


def _write_temp_file(content: str, suffix: str) -> str:
    """Write content to a temporary file and return its path."""
    tmp = tempfile.NamedTemporaryFile(
        "w", delete=False, encoding="utf-8", suffix=suffix
    )
    try:
        tmp.write(content)
    finally:
        tmp.close()
    return tmp.name


def _build_incomplete_dfd_markdown(result, ui_locale: str = _DEFAULT_UI_LOCALE) -> str:
    lines = [
        _t(ui_locale, "incomplete_dfd_title"),
        "",
        _t(ui_locale, "incomplete_dfd_reason"),
    ]
    if result.summary:
        lines.extend(["", f"{_t(ui_locale, 'summary_label')}: {result.summary}"])
    if result.assumptions:
        lines.extend(["", f"### {_t(ui_locale, 'assumptions_label')}"])
        lines.extend(f"- {item}" for item in result.assumptions)
    if result.clarifying_questions:
        lines.extend(["", f"### {_t(ui_locale, 'clarifying_questions_label')}"])
        lines.extend(f"- {item}" for item in result.clarifying_questions)
    return "\n".join(lines)


def _validate_text_input_format(
    diagram_format: str, ui_locale: str = _DEFAULT_UI_LOCALE
) -> str:
    value = (diagram_format or INPUT_FORMAT_MERMAID).strip().lower()
    if value not in TEXT_INPUT_FORMATS:
        raise gr.Error(_t(ui_locale, "error_unsupported_diagram_format", value=value))
    return value


def _normalize_embed_model(embed_arg: str) -> str:
    value = (embed_arg or "").strip()
    if ":" in value:
        value = value.split(":", 1)[-1]
    return value or DEFAULT_EMBED_MODEL


def _validate_kb_name(kb_name: str, ui_locale: str = _DEFAULT_UI_LOCALE) -> str:
    name = (kb_name or "").strip()
    if not name:
        raise gr.Error(_t(ui_locale, "error_kb_name_required"))
    separators = {sep for sep in ("/", "\\", os.sep, os.altsep) if sep}
    if name in {".", ".."} or any(sep in name for sep in separators):
        raise gr.Error(_t(ui_locale, "error_kb_name_path_separators"))
    return name


def _kb_choices() -> list[str]:
    return sorted(entry["name"] for entry in list_kbs())


def _kb_list_markdown(ui_locale: str = _DEFAULT_UI_LOCALE) -> str:
    entries = list_kbs()
    kb_root = get_kb_root()
    if not entries:
        return (
            f"{_t(ui_locale, 'kb_list_empty', kb_root=kb_root)}\n"
            f"{_t(ui_locale, 'kb_list_empty_hint')}"
        )

    lines = [_t(ui_locale, "kb_list_available")]
    for entry in entries:
        updated = entry.get("updated_at") or _t(ui_locale, "kb_list_unknown_updated")
        chunks = entry.get("num_chunks", 0)
        docs = entry.get("num_documents", 0)
        model = entry.get("embedding_model") or DEFAULT_EMBED_MODEL
        lines.append(
            _t(
                ui_locale,
                "kb_list_entry",
                name=html.escape(entry["name"]),
                chunks=chunks,
                docs=docs,
                model=html.escape(model),
                updated=html.escape(str(updated)),
            )
        )
    lines.append(f"\n{_t(ui_locale, 'kb_list_storage', kb_root=kb_root)}")
    return "\n".join(lines)


def _copy_uploaded_files_to_kb(
    kb_name: str,
    upload_files: List[str],
    clean_raw: bool,
    ui_locale: str = _DEFAULT_UI_LOCALE,
) -> list[str]:
    valid_files = [f for f in upload_files if f]
    if not valid_files:
        raise gr.Error(_t(ui_locale, "error_upload_doc_required"))

    raw_dir = get_kb_root() / kb_name / "raw"
    if clean_raw and raw_dir.exists():
        shutil.rmtree(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)

    supported = {ext.lower() for ext in SUPPORTED_EXTENSIONS}
    stored: list[str] = []
    for file_path in valid_files:
        src = Path(file_path)
        if not src.exists():
            raise gr.Error(_t(ui_locale, "error_uploaded_file_not_found", path=src))
        if src.suffix.lower() not in supported:
            raise gr.Error(
                _t(
                    ui_locale,
                    "error_unsupported_file_type",
                    suffix=src.suffix,
                    supported=", ".join(sorted(supported)),
                )
            )
        dest = raw_dir / src.name
        shutil.copy(src, dest)
        stored.append(str(dest))
    return stored


def _normalize_context_uploads(
    context_files, ui_locale: str = _DEFAULT_UI_LOCALE
) -> list[str]:
    if context_files is None:
        return []
    if isinstance(context_files, list):
        files = [str(f) for f in context_files if f]
    else:
        files = [str(context_files)]

    supported = {ext.lower() for ext in SUPPORTED_CONTEXT_EXTENSIONS}
    for file_path in files:
        src = Path(file_path)
        if not src.exists():
            raise gr.Error(_t(ui_locale, "error_context_file_not_found", path=src))
        if src.suffix.lower() not in supported:
            raise gr.Error(
                _t(
                    ui_locale,
                    "error_unsupported_context_file_type",
                    suffix=src.suffix,
                    supported=", ".join(sorted(supported)),
                )
            )
    return files


def _refresh_kb_inventory(
    select_value: Optional[list[str]] = None, ui_locale: str = _DEFAULT_UI_LOCALE
):
    choices = _kb_choices()
    value = [kb for kb in (select_value or []) if kb in choices]
    return (
        _kb_list_markdown(ui_locale),
        gr.update(choices=choices, value=value),
        gr.update(choices=choices),
    )


def _delete_kb(kb_name: str, ui_locale: str = _DEFAULT_UI_LOCALE):
    name = _validate_kb_name(kb_name, ui_locale)
    try:
        remove_kb(name)
    except KnowledgeBaseError as exc:
        raise gr.Error(str(exc))
    except Exception as exc:
        traceback.print_exc()
        raise gr.Error(_t(ui_locale, "error_failed_remove_kb", error=exc))

    list_md, selector_update, delete_update = _refresh_kb_inventory([], ui_locale)
    status = _t(ui_locale, "status_removed_kb", name=html.escape(name))
    return status, list_md, selector_update, delete_update


def _build_kb_from_uploads(
    kb_name: str,
    upload_files,
    embedder: str,
    chunk_tokens: int,
    chunk_overlap: int,
    clean_raw: bool,
    ui_locale: str = _DEFAULT_UI_LOCALE,
):
    name = _validate_kb_name(kb_name, ui_locale)

    if not os.getenv("OPENAI_API_KEY"):
        raise gr.Error(_t(ui_locale, "error_openai_key_required_build_kb"))

    files: list[str]
    if upload_files is None:
        files = []
    elif isinstance(upload_files, list):
        files = [str(f) for f in upload_files if f]
    else:
        files = [str(upload_files)]

    try:
        token_limit = int(chunk_tokens or DEFAULT_CHUNK_TOKENS)
        overlap = int(chunk_overlap or DEFAULT_CHUNK_OVERLAP)
        if token_limit <= 0:
            raise gr.Error(_t(ui_locale, "error_chunk_tokens_positive"))
        if overlap < 0:
            raise gr.Error(_t(ui_locale, "error_chunk_overlap_nonnegative"))

        stored = _copy_uploaded_files_to_kb(name, files, clean_raw, ui_locale)
        meta = build_kb(
            name,
            embed_model=_normalize_embed_model(embedder),
            chunk_tokens=token_limit,
            chunk_overlap=overlap,
        )
        safe_name = html.escape(name)
        status_lines = [
            _t(
                ui_locale,
                "status_stored_documents",
                count=len(stored),
                path=get_kb_root() / name / "raw",
            ),
            _t(
                ui_locale,
                "status_built_kb",
                name=safe_name,
                chunks=meta.get("num_chunks"),
                docs=meta.get("num_documents"),
            ),
            _t(
                ui_locale,
                "status_embedding_model",
                model=html.escape(meta.get("embedding_model", "")),
            ),
        ]
    except gr.Error:
        raise
    except KnowledgeBaseError as exc:
        raise gr.Error(str(exc))
    except Exception as exc:
        traceback.print_exc()
        raise gr.Error(_t(ui_locale, "error_failed_build_kb", error=exc))

    list_md, selector_update, delete_update = _refresh_kb_inventory([name], ui_locale)
    return "\n".join(status_lines), list_md, selector_update, delete_update


def _generate_diff_report(
    before_file: str,
    after_file: str,
    llm_api: str,
    llm_model: str,
    aws_profile: str,
    aws_region: str,
    ollama_host: str,
    lang: str,
    ui_locale: str = _DEFAULT_UI_LOCALE,
) -> Tuple[str, str, Optional[str], Optional[str]]:
    """Generate diff report between two JSON files."""
    if not before_file or not after_file:
        raise gr.Error(_t(ui_locale, "error_diff_files_required"))

    # Validate file extensions
    for file_path, label_key in [
        (before_file, "file_label_before"),
        (after_file, "file_label_after"),
    ]:
        if not file_path.lower().endswith(".json"):
            raise gr.Error(
                _t(ui_locale, "error_file_must_be_json", label=_t(ui_locale, label_key))
            )

    llm_api = (llm_api or "openai").strip().lower()
    llm_model = (llm_model or "").strip() or "gpt-4.1"
    aws_profile = (aws_profile or "").strip() or None
    aws_region = (aws_region or "").strip() or None
    lang = (lang or "en").strip()
    ollama_host = (
        (ollama_host or "").strip()
        or os.getenv("OLLAMA_HOST")
        or "http://localhost:11434"
    )
    if llm_api == "ollama":
        normalized_model = llm_model.lower()
        if not normalized_model or normalized_model.startswith("gpt-4"):
            llm_model = "llama3.1"

    try:
        # Generate diff analysis
        diff_data = diff_reports(
            after_file,
            before_file,
            llm_api,
            llm_model,
            aws_profile,
            aws_region,
            ollama_host,
            lang,
        )

        # Generate markdown report
        md_report = export_diff_md(diff_data)

        # Generate JSON report
        json_report = json.dumps(diff_data, ensure_ascii=False, indent=2)

        # Remove any previous download files before generating a new one
        _cleanup_downloads()

        # Create download files
        download_md_path = _write_temp_file(md_report, ".md")
        download_json_path = _write_temp_file(json_report, ".json")
        _DOWNLOAD_PATHS.add(download_md_path)
        _DOWNLOAD_PATHS.add(download_json_path)

        return (
            md_report,
            json_report,
            download_md_path,
            download_json_path,
        )
    except gr.Error:
        raise
    except Exception as exc:
        traceback.print_exc()
        raise gr.Error(_t(ui_locale, "error_failed_generate_diff_report", error=exc))


def _generate_report(
    system_description: str,
    context_files,
    input_method: str,
    diagram_text: str,
    diagram_format: str,
    drawio_page: str,
    image_file: str,
    infer_hints: bool,
    llm_api: str,
    llm_model: str,
    aws_profile: str,
    aws_region: str,
    ollama_host: str,
    topn: int,
    min_confidence: float,
    require_asvs: bool,
    lang: str,
    use_rag: bool,
    kb_names,
    rag_topk: int,
    rag_strategy: str,
    rag_reranker: str,
    rag_candidates: int,
    rag_min_score: float,
    prompt_token_limit: int,
    ui_locale: str = _DEFAULT_UI_LOCALE,
) -> Tuple[
    str,
    str,
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[str],
]:
    system_description = (system_description or "").strip()
    diagram_text = (diagram_text or "").strip()
    diagram_format = _validate_text_input_format(diagram_format, ui_locale)
    drawio_page = (drawio_page or "").strip() or None
    has_text_diagram = input_method == _INPUT_METHOD_TEXT and bool(diagram_text)
    has_image_diagram = input_method == _INPUT_METHOD_IMAGE and bool(image_file)
    has_diagram = has_text_diagram or has_image_diagram
    if not has_diagram and not system_description:
        raise gr.Error(_t(ui_locale, "error_system_description_required"))
    context_paths = _normalize_context_uploads(context_files, ui_locale)

    if has_image_diagram:
        ext = Path(image_file).suffix.lower()
        supported_formats = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}
        if ext not in supported_formats:
            raise gr.Error(
                _t(
                    ui_locale,
                    "error_unsupported_image_format",
                    ext=ext,
                    supported=", ".join(sorted(supported_formats)),
                )
            )

    llm_api = (llm_api or "openai").strip().lower()
    llm_model = (llm_model or "").strip() or "gpt-4.1"
    aws_profile = (aws_profile or "").strip() or None
    aws_region = (aws_region or "").strip() or None
    rag_topk_val = int(rag_topk or DEFAULT_TOPK)
    rag_candidates_val = int(rag_candidates or DEFAULT_RAG_CANDIDATES)
    rag_min_score_val = float(rag_min_score or DEFAULT_RAG_MIN_SCORE)
    rag_strategy = (rag_strategy or DEFAULT_RAG_STRATEGY).strip().lower()
    rag_reranker = (rag_reranker or DEFAULT_RAG_RERANKER).strip().lower()
    prompt_token_limit_val = (
        int(prompt_token_limit) if prompt_token_limit is not None else None
    )
    if prompt_token_limit_val is not None and prompt_token_limit_val <= 0:
        raise gr.Error(_t(ui_locale, "error_prompt_token_limit_positive"))
    ollama_host = (
        (ollama_host or "").strip()
        or os.getenv("OLLAMA_HOST")
        or "http://localhost:11434"
    )
    if llm_api == "ollama":
        if has_image_diagram:
            raise gr.Error(_t(ui_locale, "error_ollama_image_not_supported"))
        normalized_model = llm_model.lower()
        if not normalized_model or normalized_model.startswith("gpt-4"):
            llm_model = "llama3.1"

    kb_list: list[str] = []
    if use_rag:
        if not os.getenv("OPENAI_API_KEY"):
            raise gr.Error(_t(ui_locale, "error_openai_key_required_rag"))
        if kb_names is None:
            kb_list = []
        elif isinstance(kb_names, list):
            kb_list = [kb for kb in kb_names if kb]
        else:
            kb_list = [str(kb_names)]
        if not kb_list:
            raise gr.Error(_t(ui_locale, "error_select_kb_for_rag"))
        if rag_topk_val <= 0:
            raise gr.Error(_t(ui_locale, "error_rag_topk_positive"))
        if rag_candidates_val <= 0:
            raise gr.Error(_t(ui_locale, "error_rag_candidates_positive"))
        if rag_min_score_val < 0.0 or rag_min_score_val > 1.0:
            raise gr.Error(_t(ui_locale, "error_rag_min_score_range"))
        if rag_strategy not in RAG_STRATEGIES:
            raise gr.Error(
                _t(
                    ui_locale,
                    "error_unsupported_rag_strategy",
                    value=rag_strategy,
                    supported=sorted(RAG_STRATEGIES),
                )
            )
        if rag_reranker not in RAG_RERANKERS:
            raise gr.Error(
                _t(
                    ui_locale,
                    "error_unsupported_rag_reranker",
                    value=rag_reranker,
                    supported=sorted(RAG_RERANKERS),
                )
            )

    # Prepare diagram file path
    diagram_path = None
    if has_text_diagram:
        diagram_path = _write_temp_file(
            diagram_text, suffix_for_text_input(diagram_format)
        )
    elif has_image_diagram:
        diagram_path = image_file

    status_lines = []
    business_context_text = system_description or None
    dfd_result = None
    rag_context_text = None
    retrieval = None
    rerank_fn = None

    try:
        if has_text_diagram:
            graph, metrics = load_input(
                diagram_format,
                diagram_path,
                drawio_page=drawio_page,
            )
            status_lines.append(
                _t(
                    ui_locale,
                    "status_parsed_diagram",
                    diagram_format=diagram_format,
                    nodes=len(graph.nodes),
                    edges=len(graph.edges),
                )
            )
        elif has_image_diagram:
            graph, metrics = load_input(
                "image",
                diagram_path,
                api=llm_api,
                model=llm_model,
                aws_profile=aws_profile,
                aws_region=aws_region,
                ollama_host=ollama_host,
            )
            status_lines.append(
                _t(
                    ui_locale,
                    "status_parsed_image_diagram",
                    nodes=len(graph.nodes),
                    edges=len(graph.edges),
                )
            )
        else:
            payload = llm_generate_dfd_from_description(
                system_description,
                llm_api,
                llm_model,
                aws_profile,
                aws_region,
                ollama_host,
                prompt_token_limit_val,
                lang=lang,
            )
            dfd_result = dfd_result_from_payload(payload)
            dfd_result.metrics.total_lines = len(system_description.splitlines())
            graph = dfd_result.graph
            metrics = dfd_result.metrics
            status_lines.append(
                _t(
                    ui_locale,
                    "status_generated_dfd",
                    nodes=len(graph.nodes),
                    edges=len(graph.edges),
                )
            )
            if dfd_result.summary:
                status_lines.append(
                    _t(ui_locale, "status_dfd_summary", summary=dfd_result.summary)
                )
            if dfd_result.assumptions:
                status_lines.append(
                    _t(
                        ui_locale,
                        "status_assumptions",
                        items="; ".join(dfd_result.assumptions),
                    )
                )
            if dfd_result.clarifying_questions:
                status_lines.append(
                    _t(
                        ui_locale,
                        "status_clarifying_questions",
                        items="; ".join(dfd_result.clarifying_questions),
                    )
                )
            if not graph.nodes:
                status_lines.append(
                    _t(ui_locale, "status_threat_inference_skipped_empty_dfd")
                )
                _cleanup_downloads()
                dfd_download_path = _write_temp_file(
                    dfd_result_to_sidecar_json(dfd_result), ".dfd.json"
                )
                _DOWNLOAD_PATHS.add(dfd_download_path)
                status_text = "\n".join(status_lines)
                report_text = (
                    f"{_t(ui_locale, 'status_label')}:\n{status_text}\n\n"
                    f"{_t(ui_locale, 'status_generated_dfd_json')}:\n{dfd_result_to_sidecar_json(dfd_result)}"
                )
                return (
                    _build_incomplete_dfd_markdown(dfd_result, ui_locale),
                    report_text,
                    None,
                    None,
                    None,
                    None,
                    dfd_download_path,
                )

        status_lines.append(
            _t(
                ui_locale,
                "status_import_success",
                percent=metrics.import_success_rate * 100,
                edges_parsed=metrics.edges_parsed,
                edge_candidates=metrics.edge_candidates,
                labels_parsed=metrics.node_labels_parsed,
                label_candidates=metrics.node_label_candidates,
            )
        )

        if has_diagram and infer_hints:
            skeleton = json.dumps(
                {
                    "nodes": [
                        {"id": node.id, "label": node.label}
                        for node in graph.nodes.values()
                    ],
                    "edges": [
                        {"from": edge.src, "to": edge.dst, "label": edge.label}
                        for edge in graph.edges
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
            inferred = cli.llm_infer_hints(
                skeleton,
                llm_api,
                llm_model,
                aws_profile,
                aws_region,
                ollama_host,
                lang,
            )
            graph = cli.merge_llm_hints(graph, inferred)
            status_lines.append(_t(ui_locale, "status_applied_llm_hints"))

        if context_paths:
            try:
                context_docs = load_context_documents(context_paths, llm_model)
                doc_count, token_count, sources = context_summary(context_docs)
                context_text = format_context_documents(context_docs)
                business_context_text = "\n\n".join(
                    text
                    for text in [business_context_text, context_text]
                    if text and text.strip()
                )
                status_lines.append(
                    _t(
                        ui_locale,
                        "status_loaded_business_context",
                        count=doc_count,
                        tokens=token_count,
                        sources=", ".join(sources),
                    )
                )
            except ContextDocumentError as exc:
                raise gr.Error(
                    _t(ui_locale, "error_failed_load_business_context", error=exc)
                )

        if use_rag:
            try:
                retrieval_options = RetrievalOptions(
                    strategy=rag_strategy,
                    reranker=rag_reranker,
                    candidates=rag_candidates_val,
                    min_score=rag_min_score_val,
                )
                if rag_reranker in {"auto", "llm"}:

                    def _rerank_with_llm(q, candidates):
                        return llm_rerank_chunks(
                            q,
                            candidates,
                            llm_api,
                            llm_model,
                            aws_profile,
                            aws_region,
                            ollama_host,
                        )

                    rerank_fn = _rerank_with_llm
                retrieval = retrieve_context_for_graph(
                    graph,
                    kb_list,
                    topk=rag_topk_val,
                    options=retrieval_options,
                    rerank_fn=rerank_fn,
                )
                rag_context_text = retrieval.get("context_text") or ""
                num_chunks = len(retrieval.get("results", []))
                if rag_context_text and num_chunks:
                    status_lines.append(
                        _t(
                            ui_locale,
                            "status_retrieved_knowledge_chunks",
                            count=num_chunks,
                            kb_names=", ".join(kb_list),
                        )
                    )
                    status_lines.append(
                        _t(
                            ui_locale,
                            "status_rag_strategy",
                            strategy=rag_strategy,
                            reranker=retrieval.get("reranker_backend", "off"),
                        )
                    )
                else:
                    status_lines.append(_t(ui_locale, "status_no_knowledge_snippets"))
            except KnowledgeBaseError as exc:
                raise gr.Error(
                    _t(
                        ui_locale,
                        "error_failed_retrieve_local_knowledge",
                        error=exc,
                    )
                )

        threats = cli.llm_infer_threats(
            graph,
            llm_api,
            llm_model,
            aws_profile,
            aws_region,
            ollama_host,
            lang,
            rag_context=rag_context_text,
            rag_candidates=(retrieval or {}).get("candidate_results"),
            business_context=business_context_text,
            prompt_token_limit=prompt_token_limit_val,
        )
        if use_rag:
            threats, dropped_by_citation = attach_rag_sources_to_threats(
                threats,
                retrieval,
                reranker_backend=(retrieval or {}).get("reranker_backend", "off"),
                rerank_fn=rerank_fn,
                min_score=rag_min_score_val,
                max_sources_per_threat=2,
            )
            if dropped_by_citation:
                status_lines.append(
                    _t(
                        ui_locale,
                        "status_excluded_threats_without_rag",
                        count=dropped_by_citation,
                    )
                )
        status_lines.append(
            _t(ui_locale, "status_llm_returned_threats", count=len(threats))
        )

        filtered = cli.denoise_threats(
            threats,
            require_asvs=require_asvs,
            min_confidence=float(min_confidence or 0.0),
            topn=int(topn or 0),
        )
        status_lines.append(
            _t(ui_locale, "status_threats_after_filter", count=len(filtered))
        )

        # Remove any previous download files before generating a new one
        _cleanup_downloads()

        json_report = cli.export_json(filtered, None, metrics, graph)
        md_report = cli.export_md(filtered, None)
        html_report = cli.export_html(filtered, None, graph)
        td_report = None
        td_download_path = None
        if graph.source_format == "threat-dragon" and graph.threat_dragon:
            try:
                td_report = cli.export_threat_dragon(filtered, graph, None)
                td_download_path = _write_temp_file(td_report, ".threat-dragon.json")
                status_lines.append(
                    _t(ui_locale, "status_td_generated")
                )
            except Exception as exc:
                status_lines.append(
                    _t(ui_locale, "status_td_export_skipped", error=exc)
                )

        download_md_path = _write_temp_file(md_report, ".md")
        download_json_path = _write_temp_file(json_report, ".json")
        download_html_path = _write_temp_file(html_report, ".html")
        dfd_download_path = None
        if dfd_result:
            dfd_download_path = _write_temp_file(
                dfd_result_to_sidecar_json(dfd_result), ".dfd.json"
            )
        download_paths = {download_md_path, download_json_path, download_html_path}
        if td_download_path:
            download_paths.add(td_download_path)
        if dfd_download_path:
            download_paths.add(dfd_download_path)
        _DOWNLOAD_PATHS.update(download_paths)

        status_lines.append(_t(ui_locale, "status_report_generated_successfully"))
        status_text = "\n".join(status_lines)
        report_text = (
            f"{_t(ui_locale, 'status_label')}:\n{status_text}\n\n"
            f"{_t(ui_locale, 'status_json_report')}:\n{json_report}\n\n"
            f"{_t(ui_locale, 'status_markdown_report')}:\n{md_report}\n\n"
            f"{_t(ui_locale, 'status_html_report')}:\n{html_report}"
        )
        if td_report:
            report_text += f"\n\n{_t(ui_locale, 'status_td_report')}:\n{td_report}"

        markdown_report = md_report

        return (
            markdown_report,
            report_text,
            download_md_path,
            download_json_path,
            download_html_path,
            td_download_path,
            dfd_download_path,
        )
    except gr.Error:
        raise
    except Exception as exc:
        traceback.print_exc()
        raise gr.Error(_t(ui_locale, "error_failed_generate_report", error=exc))
    finally:
        # clean up intermediate files; keep the report download file around
        cleanup_paths = []
        if has_text_diagram and diagram_path:
            cleanup_paths.append(diagram_path)

        for path in cleanup_paths:
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass


def _localize_webui(
    ui_locale: str,
    input_method_value: str,
    think_lang_value: str,
    think_lang_manual: bool,
    diff_lang_value: str,
    diff_lang_manual: bool,
    kb_selection,
    kb_delete_value,
    report_markdown_value: str,
    kb_status_value: str,
    diff_markdown_value: str,
):
    locale = _normalize_ui_locale(ui_locale)
    think_lang_value, think_lang_manual = _sync_output_language_with_locale(
        locale, think_lang_value, think_lang_manual
    )
    diff_lang_value, diff_lang_manual = _sync_output_language_with_locale(
        locale, diff_lang_value, diff_lang_manual
    )
    report_markdown_value = _preserve_or_localize_default(
        report_markdown_value, locale, "report_preview_default"
    )
    kb_status_value = _preserve_or_localize_default(
        kb_status_value, locale, "kb_status_default"
    )
    diff_markdown_value = _preserve_or_localize_default(
        diff_markdown_value, locale, "diff_report_preview_default"
    )
    kb_choices = _kb_choices()
    kb_value = [kb for kb in (kb_selection or []) if kb in kb_choices]
    delete_value = kb_delete_value if kb_delete_value in kb_choices else None

    return (
        locale,
        think_lang_manual,
        diff_lang_manual,
        gr.update(value=_intro_markdown(locale)),
        gr.update(label=_t(locale, "think_tab")),
        gr.update(label=_t(locale, "kb_tab")),
        gr.update(label=_t(locale, "diff_tab")),
        gr.update(
            label=_t(locale, "system_description_label"),
            placeholder=_t(locale, "system_description_placeholder"),
        ),
        gr.update(label=_t(locale, "business_context_label")),
        gr.update(label=_t(locale, "advanced_diagram_accordion")),
        gr.update(
            label=_t(locale, "diagram_input_method_label"),
            choices=_input_method_choices(locale),
            value=input_method_value,
        ),
        gr.update(
            label=_t(locale, "diagram_content_label"),
            placeholder=_t(locale, "diagram_content_placeholder"),
        ),
        gr.update(label=_t(locale, "diagram_format_label")),
        gr.update(
            label=_t(locale, "drawio_page_label"),
            placeholder=_t(locale, "drawio_page_placeholder"),
        ),
        gr.update(label=_t(locale, "upload_diagram_image_label")),
        gr.update(label=_t(locale, "llm_api_label")),
        gr.update(
            label=_t(locale, "llm_model_label"),
            placeholder=_t(locale, "llm_model_placeholder"),
        ),
        gr.update(
            label=_t(locale, "aws_profile_label"),
            placeholder=_t(locale, "aws_profile_placeholder"),
        ),
        gr.update(
            label=_t(locale, "aws_region_label"),
            placeholder=_t(locale, "aws_region_placeholder"),
        ),
        gr.update(
            label=_t(locale, "ollama_host_label"),
            placeholder=_t(locale, "ollama_host_placeholder"),
        ),
        gr.update(label=_t(locale, "infer_hints_label")),
        gr.update(label=_t(locale, "require_asvs_label")),
        gr.update(label=_t(locale, "topn_label")),
        gr.update(label=_t(locale, "min_confidence_label")),
        gr.update(
            label=_t(locale, "output_language_label"),
            placeholder=_t(locale, "output_language_placeholder"),
            value=think_lang_value,
        ),
        gr.update(label=_t(locale, "use_kb_label")),
        gr.update(
            label=_t(locale, "knowledge_bases_label"),
            info=_t(locale, "knowledge_bases_info"),
            choices=kb_choices,
            value=kb_value,
        ),
        gr.update(label=_t(locale, "rag_topk_label")),
        gr.update(label=_t(locale, "rag_advanced_accordion")),
        gr.update(label=_t(locale, "rag_strategy_label")),
        gr.update(label=_t(locale, "rag_reranker_label")),
        gr.update(label=_t(locale, "rag_candidates_label")),
        gr.update(label=_t(locale, "rag_min_score_label")),
        gr.update(label=_t(locale, "prompt_advanced_accordion")),
        gr.update(
            label=_t(locale, "prompt_token_limit_label"),
            info=_t(locale, "prompt_token_limit_info"),
        ),
        gr.update(value=_t(locale, "generate_report_button")),
        gr.update(label=_t(locale, "markdown_preview_tab")),
        gr.update(label=_t(locale, "raw_text_tab")),
        gr.update(
            label=_t(locale, "report_preview_markdown_label"),
            value=report_markdown_value,
        ),
        gr.update(label=_t(locale, "report_preview_raw_label")),
        gr.update(label=_t(locale, "download_md_label")),
        gr.update(label=_t(locale, "download_json_label")),
        gr.update(label=_t(locale, "download_html_label")),
        gr.update(label=_t(locale, "download_td_label")),
        gr.update(label=_t(locale, "download_dfd_label")),
        gr.update(value=_t(locale, "kb_intro_md")),
        gr.update(
            label=_t(locale, "kb_name_label"),
            placeholder=_t(locale, "kb_name_placeholder"),
        ),
        gr.update(label=_t(locale, "kb_upload_label")),
        gr.update(
            label=_t(locale, "kb_embedder_label"),
            placeholder=_t(locale, "kb_embedder_placeholder"),
        ),
        gr.update(label=_t(locale, "kb_replace_raw_label")),
        gr.update(label=_t(locale, "chunk_tokens_label")),
        gr.update(label=_t(locale, "chunk_overlap_label")),
        gr.update(value=_t(locale, "build_kb_button")),
        gr.update(value=kb_status_value),
        gr.update(value=_kb_list_markdown(locale)),
        gr.update(value=_t(locale, "refresh_kbs_button")),
        gr.update(
            label=_t(locale, "kb_delete_select_label"),
            choices=kb_choices,
            value=delete_value,
        ),
        gr.update(value=_t(locale, "delete_kb_button")),
        gr.update(value=_t(locale, "diff_intro_md")),
        gr.update(label=_t(locale, "before_report_label")),
        gr.update(label=_t(locale, "after_report_label")),
        gr.update(label=_t(locale, "llm_api_label")),
        gr.update(
            label=_t(locale, "llm_model_label"),
            placeholder=_t(locale, "llm_model_placeholder"),
        ),
        gr.update(
            label=_t(locale, "aws_profile_label"),
            placeholder=_t(locale, "aws_profile_placeholder"),
        ),
        gr.update(
            label=_t(locale, "aws_region_label"),
            placeholder=_t(locale, "aws_region_placeholder"),
        ),
        gr.update(
            label=_t(locale, "ollama_host_label"),
            placeholder=_t(locale, "ollama_host_placeholder"),
        ),
        gr.update(
            label=_t(locale, "output_language_label"),
            placeholder=_t(locale, "output_language_placeholder"),
            value=diff_lang_value,
        ),
        gr.update(value=_t(locale, "generate_diff_button")),
        gr.update(label=_t(locale, "markdown_preview_tab")),
        gr.update(label=_t(locale, "raw_text_tab")),
        gr.update(
            label=_t(locale, "diff_report_preview_markdown_label"),
            value=diff_markdown_value,
        ),
        gr.update(label=_t(locale, "diff_report_preview_raw_label")),
        gr.update(label=_t(locale, "download_md_diff_label")),
        gr.update(label=_t(locale, "download_json_diff_label")),
    )


def _build_webui(ui_locale: str = _DEFAULT_UI_LOCALE) -> gr.Blocks:
    """Construct the Gradio Web UI without launching a server."""
    locale = _normalize_ui_locale(ui_locale)
    default_report_lang = _default_output_language(locale)

    with gr.Blocks(title="Threat Thinker WebUI") as demo:
        ui_locale_state = gr.State(locale)
        think_lang_manual_state = gr.State(False)
        diff_lang_manual_state = gr.State(False)

        intro_markdown = gr.Markdown(_intro_markdown(locale))
        ui_locale_selector = gr.Radio(
            label=_t(locale, "ui_language_label"),
            choices=[("English", "en"), ("日本語", "ja")],
            value=locale,
        )

        with gr.Tabs():
            with gr.Tab(_t(locale, "think_tab")) as think_tab:
                system_description_input = gr.TextArea(
                    label=_t(locale, "system_description_label"),
                    placeholder=_t(locale, "system_description_placeholder"),
                    lines=10,
                    autofocus=True,
                )

                context_files_input = gr.File(
                    label=_t(locale, "business_context_label"),
                    file_types=sorted(SUPPORTED_CONTEXT_EXTENSIONS),
                    type="filepath",
                    file_count="multiple",
                )

                with gr.Accordion(
                    _t(locale, "advanced_diagram_accordion"), open=False
                ) as advanced_diagram_accordion:
                    input_method = gr.Radio(
                        label=_t(locale, "diagram_input_method_label"),
                        choices=_input_method_choices(locale),
                        value=_INPUT_METHOD_TEXT,
                    )

                    diagram_input = gr.TextArea(
                        label=_t(locale, "diagram_content_label"),
                        placeholder=_t(locale, "diagram_content_placeholder"),
                        lines=16,
                        visible=True,
                    )
                    diagram_format_input = gr.Radio(
                        label=_t(locale, "diagram_format_label"),
                        choices=[
                            INPUT_FORMAT_MERMAID,
                            INPUT_FORMAT_DRAWIO,
                            INPUT_FORMAT_THREAT_DRAGON,
                            INPUT_FORMAT_IR,
                        ],
                        value=INPUT_FORMAT_MERMAID,
                        visible=True,
                    )
                    drawio_page_input = gr.Textbox(
                        label=_t(locale, "drawio_page_label"),
                        placeholder=_t(locale, "drawio_page_placeholder"),
                        visible=False,
                    )

                    image_input = gr.File(
                        label=_t(locale, "upload_diagram_image_label"),
                        file_types=["image"],
                        type="filepath",
                        visible=False,
                    )

                with gr.Row():
                    llm_api_input = gr.Dropdown(
                        label=_t(locale, "llm_api_label"),
                        choices=["openai", "anthropic", "bedrock", "ollama"],
                        value="openai",
                        interactive=True,
                    )
                    llm_model_input = gr.Textbox(
                        label=_t(locale, "llm_model_label"),
                        value="gpt-4.1",
                        placeholder=_t(locale, "llm_model_placeholder"),
                    )
                    aws_profile_input = gr.Textbox(
                        label=_t(locale, "aws_profile_label"),
                        value="",
                        placeholder=_t(locale, "aws_profile_placeholder"),
                    )
                    aws_region_input = gr.Textbox(
                        label=_t(locale, "aws_region_label"),
                        value="",
                        placeholder=_t(locale, "aws_region_placeholder"),
                    )
                    ollama_host_input = gr.Textbox(
                        label=_t(locale, "ollama_host_label"),
                        value=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
                        placeholder=_t(locale, "ollama_host_placeholder"),
                    )

                with gr.Row():
                    infer_hints_input = gr.Checkbox(
                        label=_t(locale, "infer_hints_label"),
                        value=True,
                    )
                    require_asvs_input = gr.Checkbox(
                        label=_t(locale, "require_asvs_label"),
                        value=True,
                    )

                with gr.Row():
                    topn_input = gr.Slider(
                        label=_t(locale, "topn_label"),
                        minimum=1,
                        maximum=10,
                        step=1,
                        value=10,
                    )
                    min_confidence_input = gr.Slider(
                        label=_t(locale, "min_confidence_label"),
                        minimum=0.0,
                        maximum=1.0,
                        step=0.05,
                        value=0.5,
                    )
                lang_input = gr.Textbox(
                    label=_t(locale, "output_language_label"),
                    value=default_report_lang,
                    placeholder=_t(locale, "output_language_placeholder"),
                )

                use_rag_input = gr.Checkbox(
                    label=_t(locale, "use_kb_label"),
                    value=False,
                )
                kb_selector = gr.Dropdown(
                    label=_t(locale, "knowledge_bases_label"),
                    choices=_kb_choices(),
                    multiselect=True,
                    value=[],
                    interactive=False,
                    allow_custom_value=False,
                    info=_t(locale, "knowledge_bases_info"),
                )
                rag_topk_input = gr.Slider(
                    label=_t(locale, "rag_topk_label"),
                    minimum=1,
                    maximum=20,
                    step=1,
                    value=DEFAULT_TOPK,
                    interactive=False,
                )
                with gr.Accordion(
                    _t(locale, "rag_advanced_accordion"), open=False
                ) as rag_advanced_accordion:
                    rag_strategy_input = gr.Dropdown(
                        label=_t(locale, "rag_strategy_label"),
                        choices=sorted(RAG_STRATEGIES),
                        value=DEFAULT_RAG_STRATEGY,
                        interactive=False,
                    )
                    rag_reranker_input = gr.Dropdown(
                        label=_t(locale, "rag_reranker_label"),
                        choices=sorted(RAG_RERANKERS),
                        value=DEFAULT_RAG_RERANKER,
                        interactive=False,
                    )
                    rag_candidates_input = gr.Slider(
                        label=_t(locale, "rag_candidates_label"),
                        minimum=5,
                        maximum=100,
                        step=1,
                        value=DEFAULT_RAG_CANDIDATES,
                        interactive=False,
                    )
                    rag_min_score_input = gr.Slider(
                        label=_t(locale, "rag_min_score_label"),
                        minimum=0.0,
                        maximum=1.0,
                        step=0.05,
                        value=DEFAULT_RAG_MIN_SCORE,
                        interactive=False,
                    )
                with gr.Accordion(
                    _t(locale, "prompt_advanced_accordion"), open=False
                ) as prompt_advanced_accordion:
                    prompt_token_limit_input = gr.Number(
                        label=_t(locale, "prompt_token_limit_label"),
                        value=None,
                        precision=0,
                        minimum=1,
                        info=_t(locale, "prompt_token_limit_info"),
                    )

                generate_button = gr.Button(
                    _t(locale, "generate_report_button"), variant="primary"
                )

                with gr.Tabs():
                    with gr.Tab(_t(locale, "markdown_preview_tab")) as report_markdown_tab:
                        report_markdown_output = gr.Markdown(
                            label=_t(locale, "report_preview_markdown_label"),
                            value=_t(locale, "report_preview_default"),
                            sanitize_html=True,
                        )
                    with gr.Tab(_t(locale, "raw_text_tab")) as report_raw_tab:
                        report_output = gr.TextArea(
                            label=_t(locale, "report_preview_raw_label"),
                            lines=20,
                            interactive=False,
                        )

                with gr.Row():
                    download_md_output = gr.File(label=_t(locale, "download_md_label"))
                    download_json_output = gr.File(
                        label=_t(locale, "download_json_label")
                    )
                    download_html_output = gr.File(
                        label=_t(locale, "download_html_label")
                    )
                    download_td_output = gr.File(label=_t(locale, "download_td_label"))
                    download_dfd_output = gr.File(
                        label=_t(locale, "download_dfd_label")
                    )

                generate_button.click(
                    fn=_generate_report,
                    inputs=[
                        system_description_input,
                        context_files_input,
                        input_method,
                        diagram_input,
                        diagram_format_input,
                        drawio_page_input,
                        image_input,
                        infer_hints_input,
                        llm_api_input,
                        llm_model_input,
                        aws_profile_input,
                        aws_region_input,
                        ollama_host_input,
                        topn_input,
                        min_confidence_input,
                        require_asvs_input,
                        lang_input,
                        use_rag_input,
                        kb_selector,
                        rag_topk_input,
                        rag_strategy_input,
                        rag_reranker_input,
                        rag_candidates_input,
                        rag_min_score_input,
                        prompt_token_limit_input,
                        ui_locale_state,
                    ],
                    outputs=[
                        report_markdown_output,
                        report_output,
                        download_md_output,
                        download_json_output,
                        download_html_output,
                        download_td_output,
                        download_dfd_output,
                    ],
                    api_name=False,
                )

                def update_input_visibility(method, diagram_format):
                    if method == _INPUT_METHOD_TEXT:
                        return {
                            diagram_input: gr.update(visible=True),
                            diagram_format_input: gr.update(visible=True),
                            drawio_page_input: gr.update(
                                visible=diagram_format == INPUT_FORMAT_DRAWIO
                            ),
                            image_input: gr.update(visible=False),
                        }
                    return {
                        diagram_input: gr.update(visible=False),
                        diagram_format_input: gr.update(visible=False),
                        drawio_page_input: gr.update(visible=False),
                        image_input: gr.update(visible=True),
                    }

                input_method.change(
                    fn=update_input_visibility,
                    inputs=[input_method, diagram_format_input],
                    outputs=[
                        diagram_input,
                        diagram_format_input,
                        drawio_page_input,
                        image_input,
                    ],
                )
                diagram_format_input.change(
                    fn=update_input_visibility,
                    inputs=[input_method, diagram_format_input],
                    outputs=[
                        diagram_input,
                        diagram_format_input,
                        drawio_page_input,
                        image_input,
                    ],
                )

                def toggle_rag_controls(enabled, current_selection):
                    kb_value = current_selection if enabled else []
                    return {
                        kb_selector: gr.update(
                            interactive=enabled,
                            value=kb_value if enabled else [],
                        ),
                        rag_topk_input: gr.update(interactive=enabled),
                        rag_strategy_input: gr.update(interactive=enabled),
                        rag_reranker_input: gr.update(interactive=enabled),
                        rag_candidates_input: gr.update(interactive=enabled),
                        rag_min_score_input: gr.update(interactive=enabled),
                    }

                use_rag_input.change(
                    fn=toggle_rag_controls,
                    inputs=[use_rag_input, kb_selector],
                    outputs=[
                        kb_selector,
                        rag_topk_input,
                        rag_strategy_input,
                        rag_reranker_input,
                        rag_candidates_input,
                        rag_min_score_input,
                    ],
                )

            with gr.Tab(_t(locale, "kb_tab")) as kb_tab:
                kb_intro_md = gr.Markdown(_t(locale, "kb_intro_md"))

                kb_name_input = gr.Textbox(
                    label=_t(locale, "kb_name_label"),
                    placeholder=_t(locale, "kb_name_placeholder"),
                )
                kb_files_input = gr.File(
                    label=_t(locale, "kb_upload_label"),
                    file_types=sorted(SUPPORTED_EXTENSIONS),
                    type="filepath",
                    file_count="multiple",
                )
                with gr.Row():
                    kb_embedder_input = gr.Textbox(
                        label=_t(locale, "kb_embedder_label"),
                        value=f"openai:{DEFAULT_EMBED_MODEL}",
                        placeholder=_t(locale, "kb_embedder_placeholder"),
                    )
                    kb_clean_raw_input = gr.Checkbox(
                        label=_t(locale, "kb_replace_raw_label"),
                        value=True,
                    )
                with gr.Row():
                    kb_chunk_tokens_input = gr.Slider(
                        label=_t(locale, "chunk_tokens_label"),
                        minimum=100,
                        maximum=4000,
                        step=50,
                        value=DEFAULT_CHUNK_TOKENS,
                    )
                    kb_chunk_overlap_input = gr.Slider(
                        label=_t(locale, "chunk_overlap_label"),
                        minimum=0,
                        maximum=800,
                        step=10,
                        value=DEFAULT_CHUNK_OVERLAP,
                    )

                kb_build_button = gr.Button(_t(locale, "build_kb_button"), variant="primary")
                kb_status_md = gr.Markdown(
                    value=_t(locale, "kb_status_default"),
                    sanitize_html=True,
                )
                kb_list_md = gr.Markdown(
                    value=_kb_list_markdown(locale), sanitize_html=True
                )
                with gr.Row():
                    kb_tab_refresh_button = gr.Button(_t(locale, "refresh_kbs_button"))
                    kb_delete_selector = gr.Dropdown(
                        label=_t(locale, "kb_delete_select_label"),
                        choices=_kb_choices(),
                        multiselect=False,
                        allow_custom_value=False,
                    )
                    kb_delete_button = gr.Button(
                        _t(locale, "delete_kb_button"), variant="stop"
                    )

            with gr.Tab(_t(locale, "diff_tab")) as diff_tab:
                diff_intro_md = gr.Markdown(_t(locale, "diff_intro_md"))

                with gr.Row():
                    before_file_input = gr.File(
                        label=_t(locale, "before_report_label"),
                        file_types=[".json"],
                        type="filepath",
                    )
                    after_file_input = gr.File(
                        label=_t(locale, "after_report_label"),
                        file_types=[".json"],
                        type="filepath",
                    )

                with gr.Row():
                    diff_llm_api_input = gr.Dropdown(
                        label=_t(locale, "llm_api_label"),
                        choices=["openai", "anthropic", "bedrock", "ollama"],
                        value="openai",
                        interactive=True,
                    )
                    diff_llm_model_input = gr.Textbox(
                        label=_t(locale, "llm_model_label"),
                        value="gpt-4.1",
                        placeholder=_t(locale, "llm_model_placeholder"),
                    )
                    diff_aws_profile_input = gr.Textbox(
                        label=_t(locale, "aws_profile_label"),
                        value="",
                        placeholder=_t(locale, "aws_profile_placeholder"),
                    )
                    diff_aws_region_input = gr.Textbox(
                        label=_t(locale, "aws_region_label"),
                        value="",
                        placeholder=_t(locale, "aws_region_placeholder"),
                    )
                    diff_ollama_host_input = gr.Textbox(
                        label=_t(locale, "ollama_host_label"),
                        value=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
                        placeholder=_t(locale, "ollama_host_placeholder"),
                    )

                diff_lang_input = gr.Textbox(
                    label=_t(locale, "output_language_label"),
                    value=default_report_lang,
                    placeholder=_t(locale, "output_language_placeholder"),
                )

                diff_generate_button = gr.Button(
                    _t(locale, "generate_diff_button"), variant="primary"
                )

                with gr.Tabs():
                    with gr.Tab(_t(locale, "markdown_preview_tab")) as diff_markdown_tab:
                        diff_markdown_output = gr.Markdown(
                            label=_t(locale, "diff_report_preview_markdown_label"),
                            value=_t(locale, "diff_report_preview_default"),
                            sanitize_html=True,
                        )
                    with gr.Tab(_t(locale, "raw_text_tab")) as diff_raw_tab:
                        diff_raw_output = gr.TextArea(
                            label=_t(locale, "diff_report_preview_raw_label"),
                            lines=20,
                            interactive=False,
                        )

                with gr.Row():
                    diff_download_md_output = gr.File(
                        label=_t(locale, "download_md_diff_label"),
                    )
                    diff_download_json_output = gr.File(
                        label=_t(locale, "download_json_diff_label"),
                    )

                diff_generate_button.click(
                    fn=_generate_diff_report,
                    inputs=[
                        before_file_input,
                        after_file_input,
                        diff_llm_api_input,
                        diff_llm_model_input,
                        diff_aws_profile_input,
                        diff_aws_region_input,
                        diff_ollama_host_input,
                        diff_lang_input,
                        ui_locale_state,
                    ],
                    outputs=[
                        diff_markdown_output,
                        diff_raw_output,
                        diff_download_md_output,
                        diff_download_json_output,
                    ],
                    api_name=False,
                )

        ui_locale_selector.change(
            fn=_localize_webui,
            inputs=[
                ui_locale_selector,
                input_method,
                lang_input,
                think_lang_manual_state,
                diff_lang_input,
                diff_lang_manual_state,
                kb_selector,
                kb_delete_selector,
                report_markdown_output,
                kb_status_md,
                diff_markdown_output,
            ],
            outputs=[
                ui_locale_state,
                think_lang_manual_state,
                diff_lang_manual_state,
                intro_markdown,
                think_tab,
                kb_tab,
                diff_tab,
                system_description_input,
                context_files_input,
                advanced_diagram_accordion,
                input_method,
                diagram_input,
                diagram_format_input,
                drawio_page_input,
                image_input,
                llm_api_input,
                llm_model_input,
                aws_profile_input,
                aws_region_input,
                ollama_host_input,
                infer_hints_input,
                require_asvs_input,
                topn_input,
                min_confidence_input,
                lang_input,
                use_rag_input,
                kb_selector,
                rag_topk_input,
                rag_advanced_accordion,
                rag_strategy_input,
                rag_reranker_input,
                rag_candidates_input,
                rag_min_score_input,
                prompt_advanced_accordion,
                prompt_token_limit_input,
                generate_button,
                report_markdown_tab,
                report_raw_tab,
                report_markdown_output,
                report_output,
                download_md_output,
                download_json_output,
                download_html_output,
                download_td_output,
                download_dfd_output,
                kb_intro_md,
                kb_name_input,
                kb_files_input,
                kb_embedder_input,
                kb_clean_raw_input,
                kb_chunk_tokens_input,
                kb_chunk_overlap_input,
                kb_build_button,
                kb_status_md,
                kb_list_md,
                kb_tab_refresh_button,
                kb_delete_selector,
                kb_delete_button,
                diff_intro_md,
                before_file_input,
                after_file_input,
                diff_llm_api_input,
                diff_llm_model_input,
                diff_aws_profile_input,
                diff_aws_region_input,
                diff_ollama_host_input,
                diff_lang_input,
                diff_generate_button,
                diff_markdown_tab,
                diff_raw_tab,
                diff_markdown_output,
                diff_raw_output,
                diff_download_md_output,
                diff_download_json_output,
            ],
            api_name=False,
        )

        lang_input.change(
            fn=_output_language_is_manual,
            inputs=[lang_input, ui_locale_state],
            outputs=[think_lang_manual_state],
            api_name=False,
        )
        diff_lang_input.change(
            fn=_output_language_is_manual,
            inputs=[diff_lang_input, ui_locale_state],
            outputs=[diff_lang_manual_state],
            api_name=False,
        )

        kb_build_button.click(
            fn=_build_kb_from_uploads,
            inputs=[
                kb_name_input,
                kb_files_input,
                kb_embedder_input,
                kb_chunk_tokens_input,
                kb_chunk_overlap_input,
                kb_clean_raw_input,
                ui_locale_state,
            ],
            outputs=[kb_status_md, kb_list_md, kb_selector, kb_delete_selector],
            api_name=False,
        )

        kb_tab_refresh_button.click(
            fn=_refresh_kb_inventory,
            inputs=[kb_selector, ui_locale_state],
            outputs=[kb_list_md, kb_selector, kb_delete_selector],
            api_name=False,
        )

        kb_delete_button.click(
            fn=_delete_kb,
            inputs=[kb_delete_selector, ui_locale_state],
            outputs=[kb_status_md, kb_list_md, kb_selector, kb_delete_selector],
            api_name=False,
        )

    return demo


def launch_webui(
    *,
    server_name: str = "127.0.0.1",
    server_port: Optional[int] = None,
) -> None:
    """Launch the Gradio Web UI."""
    cleanup_temp_dir = _setup_gradio_temp_dir()
    demo = _build_webui()

    try:
        demo.launch(server_name=server_name, server_port=server_port, share=False)
    finally:
        cleanup_temp_dir()


if __name__ == "__main__":
    launch_webui()
