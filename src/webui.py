"""
Threat Thinker WebUI powered by Gradio.
"""

import atexit
import json
import os
import shutil
import tempfile
import traceback
from pathlib import Path
from typing import Callable, List, Optional, Tuple
import html

import gradio as gr

import main as cli
from parsers.image_parser import parse_image
from exporters import diff_reports, export_diff_md
from rag import (
    KnowledgeBaseError,
    DEFAULT_CHUNK_OVERLAP,
    DEFAULT_CHUNK_TOKENS,
    DEFAULT_TOPK,
    DEFAULT_EMBED_MODEL,
    build_kb,
    get_kb_root,
    list_kbs,
    remove_kb,
    retrieve_context_for_graph,
)
from rag.local import SUPPORTED_EXTENSIONS


_DOWNLOAD_PATHS: set[str] = set()


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


def _normalize_embed_model(embed_arg: str) -> str:
    value = (embed_arg or "").strip()
    if ":" in value:
        value = value.split(":", 1)[-1]
    return value or DEFAULT_EMBED_MODEL


def _validate_kb_name(kb_name: str) -> str:
    name = (kb_name or "").strip()
    if not name:
        raise gr.Error("Knowledge base name is required.")
    separators = {sep for sep in ("/", "\\", os.sep, os.altsep) if sep}
    if name in {".", ".."} or any(sep in name for sep in separators):
        raise gr.Error("Knowledge base name cannot contain path separators.")
    return name


def _kb_choices() -> list[str]:
    return sorted(entry["name"] for entry in list_kbs())


def _kb_list_markdown() -> str:
    entries = list_kbs()
    kb_root = get_kb_root()
    if not entries:
        return (
            f"No knowledge bases found under {kb_root}.\n"
            "Use the Knowledge Base tab to upload documents and build one."
        )

    lines = ["Available knowledge bases:"]
    for entry in entries:
        updated = entry.get("updated_at") or "unknown"
        chunks = entry.get("num_chunks", 0)
        docs = entry.get("num_documents", 0)
        model = entry.get("embedding_model") or DEFAULT_EMBED_MODEL
        lines.append(
            f"- `{html.escape(entry['name'])}`: {chunks} chunks from {docs} docs (model={html.escape(model)}, updated={html.escape(str(updated))})"
        )
    lines.append(f"\nStorage location: {kb_root}")
    return "\n".join(lines)


def _copy_uploaded_files_to_kb(
    kb_name: str, upload_files: List[str], clean_raw: bool
) -> list[str]:
    valid_files = [f for f in upload_files if f]
    if not valid_files:
        raise gr.Error(
            "Please upload at least one document to build the knowledge base."
        )

    raw_dir = get_kb_root() / kb_name / "raw"
    if clean_raw and raw_dir.exists():
        shutil.rmtree(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)

    supported = {ext.lower() for ext in SUPPORTED_EXTENSIONS}
    stored: list[str] = []
    for file_path in valid_files:
        src = Path(file_path)
        if not src.exists():
            raise gr.Error(f"Uploaded file not found: {src}")
        if src.suffix.lower() not in supported:
            raise gr.Error(
                f"Unsupported file type: {src.suffix}. Supported: {', '.join(sorted(supported))}"
            )
        dest = raw_dir / src.name
        shutil.copy(src, dest)
        stored.append(str(dest))
    return stored


def _refresh_kb_inventory(select_value: Optional[list[str]] = None):
    choices = _kb_choices()
    value = [kb for kb in (select_value or []) if kb in choices]
    return (
        _kb_list_markdown(),
        gr.update(choices=choices, value=value),
        gr.update(choices=choices),
    )


def _delete_kb(kb_name: str):
    name = _validate_kb_name(kb_name)
    try:
        remove_kb(name)
    except KnowledgeBaseError as exc:
        raise gr.Error(str(exc))
    except Exception as exc:
        traceback.print_exc()
        raise gr.Error(f"Failed to remove knowledge base: {exc}")

    list_md, selector_update, delete_update = _refresh_kb_inventory([])
    status = f"Removed knowledge base `{html.escape(name)}`."
    return status, list_md, selector_update, delete_update


def _build_kb_from_uploads(
    kb_name: str,
    upload_files,
    embedder: str,
    chunk_tokens: int,
    chunk_overlap: int,
    clean_raw: bool,
):
    name = _validate_kb_name(kb_name)

    if not os.getenv("OPENAI_API_KEY"):
        raise gr.Error(
            "OPENAI_API_KEY is required to build a knowledge base.\n"
            "Set the environment variable and retry."
        )

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
            raise gr.Error("Chunk tokens must be a positive integer.")
        if overlap < 0:
            raise gr.Error("Chunk overlap cannot be negative.")

        stored = _copy_uploaded_files_to_kb(name, files, clean_raw)
        meta = build_kb(
            name,
            embed_model=_normalize_embed_model(embedder),
            chunk_tokens=token_limit,
            chunk_overlap=overlap,
        )
        safe_name = html.escape(name)
        status_lines = [
            f"Stored {len(stored)} documents under `{get_kb_root() / name / 'raw'}`.",
            f"Built KB `{safe_name}` with {meta.get('num_chunks')} chunks from {meta.get('num_documents')} documents.",
            f"Embedding model: `{html.escape(meta.get('embedding_model', ''))}`",
        ]
    except gr.Error:
        raise
    except KnowledgeBaseError as exc:
        raise gr.Error(str(exc))
    except Exception as exc:
        traceback.print_exc()
        raise gr.Error(f"Failed to build knowledge base: {exc}")

    list_md, selector_update, delete_update = _refresh_kb_inventory([name])
    return "\n".join(status_lines), list_md, selector_update, delete_update


def _generate_diff_report(
    before_file: str,
    after_file: str,
    llm_api: str,
    llm_model: str,
    aws_profile: str,
    aws_region: str,
    lang: str,
) -> Tuple[str, str, Optional[str], Optional[str]]:
    """Generate diff report between two JSON files."""
    if not before_file or not after_file:
        raise gr.Error(
            "Both before and after JSON files are required for diff analysis."
        )

    # Validate file extensions
    for file_path, label in [(before_file, "Before"), (after_file, "After")]:
        if not file_path.lower().endswith(".json"):
            raise gr.Error(f"{label} file must be a JSON file.")

    llm_api = (llm_api or "openai").strip().lower()
    llm_model = (llm_model or "").strip() or "gpt-4.1"
    aws_profile = (aws_profile or "").strip() or None
    aws_region = (aws_region or "").strip() or None
    lang = (lang or "en").strip()

    try:
        # Generate diff analysis
        diff_data = diff_reports(
            after_file,
            before_file,
            llm_api,
            llm_model,
            aws_profile,
            aws_region,
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
        raise gr.Error(f"Failed to generate diff report: {exc}")


def _generate_report(
    input_method: str,
    diagram_text: str,
    diagram_format: str,
    image_file: str,
    hints_text: str,
    infer_hints: bool,
    llm_api: str,
    llm_model: str,
    aws_profile: str,
    aws_region: str,
    topn: int,
    min_confidence: float,
    require_asvs: bool,
    lang: str,
    use_rag: bool,
    kb_names,
    rag_topk: int,
) -> Tuple[str, str, Optional[str], Optional[str], Optional[str]]:
    # Validate input based on method
    if input_method == "Text":
        diagram_text = (diagram_text or "").strip()
        if not diagram_text:
            raise gr.Error("Diagram input is required.")

        diagram_format = (diagram_format or "mermaid").strip().lower()
        if diagram_format not in ["mermaid", "drawio"]:
            raise gr.Error(f"Unsupported diagram format: {diagram_format}")
    else:  # Image
        if not image_file:
            raise gr.Error("Image file is required when using image input method.")

        # Validate image file format
        from pathlib import Path

        ext = Path(image_file).suffix.lower()
        supported_formats = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}
        if ext not in supported_formats:
            raise gr.Error(
                f"Unsupported image format: {ext}. Supported formats: {', '.join(supported_formats)}"
            )

    llm_api = (llm_api or "openai").strip().lower()
    llm_model = (llm_model or "").strip() or "gpt-4.1"
    aws_profile = (aws_profile or "").strip() or None
    aws_region = (aws_region or "").strip() or None
    rag_topk_val = int(rag_topk or DEFAULT_TOPK)

    kb_list: list[str] = []
    if use_rag:
        if not os.getenv("OPENAI_API_KEY"):
            raise gr.Error(
                "OPENAI_API_KEY is required for local RAG. Set it and retry."
            )
        if kb_names is None:
            kb_list = []
        elif isinstance(kb_names, list):
            kb_list = [kb for kb in kb_names if kb]
        else:
            kb_list = [str(kb_names)]
        if not kb_list:
            raise gr.Error("Select at least one knowledge base when RAG is enabled.")
        if rag_topk_val <= 0:
            raise gr.Error("RAG top-k must be a positive integer.")

    # Prepare diagram file path
    diagram_path = None
    if input_method == "Text":
        # Determine file extension based on format
        if diagram_format == "mermaid":
            file_suffix = ".mmd"
        elif diagram_format == "drawio":
            file_suffix = ".drawio"
        else:
            file_suffix = ".txt"

        diagram_path = _write_temp_file(diagram_text, file_suffix)
    else:  # Image
        diagram_path = image_file  # Use the uploaded file directly
    hints_path = None
    if hints_text and hints_text.strip():
        hints_path = _write_temp_file(hints_text, ".yaml")

    status_lines = []
    rag_context_text = None

    try:
        # Parse diagram based on input method and format
        if input_method == "Text":
            if diagram_format == "mermaid":
                graph, metrics = cli.parse_mermaid(diagram_path)
                status_lines.append(
                    f"Parsed Mermaid diagram: {len(graph.nodes)} nodes, {len(graph.edges)} edges."
                )
            elif diagram_format == "drawio":
                graph, metrics = cli.parse_drawio(diagram_path)
                status_lines.append(
                    f"Parsed Draw.io diagram: {len(graph.nodes)} nodes, {len(graph.edges)} edges."
                )
            else:
                raise gr.Error(f"Unsupported diagram format: {diagram_format}")
        else:  # Image
            graph, metrics = parse_image(
                diagram_path,
                api=llm_api,
                model=llm_model,
                aws_profile=aws_profile,
                aws_region=aws_region,
            )
            status_lines.append(
                f"Parsed image diagram: {len(graph.nodes)} nodes, {len(graph.edges)} edges."
            )

        status_lines.append(
            f"Import success ~{metrics.import_success_rate * 100:.1f}% "
            f"(edges {metrics.edges_parsed}/{metrics.edge_candidates}, "
            f"labels {metrics.node_labels_parsed}/{metrics.node_label_candidates})"
        )

        if infer_hints:
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
                skeleton, llm_api, llm_model, aws_profile, aws_region, lang
            )
            graph = cli.merge_llm_hints(graph, inferred)
            status_lines.append("Applied LLM-inferred hints.")

        graph = cli.apply_hints(graph, hints_path)
        if hints_path:
            status_lines.append("Applied user-provided hints.")

        if use_rag:
            try:
                retrieval = retrieve_context_for_graph(
                    graph,
                    kb_list,
                    topk=rag_topk_val,
                )
                rag_context_text = retrieval.get("context_text") or ""
                num_chunks = len(retrieval.get("results", []))
                if rag_context_text and num_chunks:
                    status_lines.append(
                        f"Retrieved {num_chunks} knowledge chunks from {', '.join(kb_list)}."
                    )
                else:
                    status_lines.append(
                        "No knowledge snippets retrieved; continuing without RAG context."
                    )
            except KnowledgeBaseError as exc:
                raise gr.Error(f"Failed to retrieve local knowledge: {exc}")

        threats = cli.llm_infer_threats(
            graph,
            llm_api,
            llm_model,
            aws_profile,
            aws_region,
            lang,
            rag_context=rag_context_text,
        )
        status_lines.append(f"LLM returned {len(threats)} threats before filtering.")

        filtered = cli.denoise_threats(
            threats,
            require_asvs=require_asvs,
            min_confidence=float(min_confidence or 0.0),
            topn=int(topn or 0),
        )
        status_lines.append(f"{len(filtered)} threats after filtering.")

        # Remove any previous download files before generating a new one
        _cleanup_downloads()

        json_report = cli.export_json(filtered, None, metrics, graph)
        md_report = cli.export_md(filtered, None)
        html_report = cli.export_html(filtered, None, graph)

        download_md_path = _write_temp_file(md_report, ".md")
        download_json_path = _write_temp_file(json_report, ".json")
        download_html_path = _write_temp_file(html_report, ".html")
        _DOWNLOAD_PATHS.update(
            {download_md_path, download_json_path, download_html_path}
        )

        report_text = (
            f"JSON Report:\n{json_report}\n\n"
            f"Markdown Report:\n{md_report}\n\n"
            f"HTML Report:\n{html_report}"
        )

        status_lines.append("Report generated successfully.")

        markdown_report = md_report

        return (
            markdown_report,
            report_text,
            download_md_path,
            download_json_path,
            download_html_path,
        )
    except gr.Error:
        raise
    except Exception as exc:
        traceback.print_exc()
        raise gr.Error(f"Failed to generate report: {exc}")
    finally:
        # clean up intermediate files; keep the report download file around
        cleanup_paths = []
        if input_method == "Text" and diagram_path:
            cleanup_paths.append(diagram_path)
        if hints_path:
            cleanup_paths.append(hints_path)

        for path in cleanup_paths:
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass


def launch_webui(
    *,
    server_name: str = "127.0.0.1",
    server_port: Optional[int] = None,
) -> None:
    """Launch the Gradio Web UI."""
    cleanup_temp_dir = _setup_gradio_temp_dir()
    with gr.Blocks(title="Threat Thinker WebUI") as demo:
        gr.Markdown(
            "## Threat Thinker WebUI\nAnalyze system diagrams for security threats or compare threat reports."
        )

        with gr.Tabs():
            with gr.Tab("Think - Threat Analysis"):
                # Input method selection
                input_method = gr.Radio(
                    label="Input Method - Choose whether to input diagram as text or upload an image file",
                    choices=["Text", "Image"],
                    value="Text",
                )

                # Text input (visible by default)
                diagram_input = gr.TextArea(
                    label="Diagram Content",
                    placeholder="Paste your diagram content here (Mermaid or Draw.io XML)...",
                    lines=20,
                    autofocus=True,
                    visible=True,
                )
                diagram_format_input = gr.Radio(
                    label="Diagram Format",
                    choices=["mermaid", "drawio"],
                    value="mermaid",
                    visible=True,
                )

                # Image input (hidden by default)
                image_input = gr.File(
                    label="Upload Diagram Image (JPG, PNG, GIF, BMP, WebP)",
                    file_types=["image"],
                    type="filepath",
                    visible=False,
                )

                hints_input = gr.TextArea(
                    label="Hints YAML (optional)",
                    placeholder="Paste YAML hints here to override attributes...",
                    lines=10,
                )

                with gr.Row():
                    llm_api_input = gr.Dropdown(
                        label="LLM API",
                        choices=["openai", "anthropic", "bedrock"],
                        value="openai",
                        interactive=True,
                    )
                    llm_model_input = gr.Textbox(
                        label="LLM Model",
                        value="gpt-4.1",
                        placeholder="e.g., gpt-4.1, claude-3-haiku-20240307, anthropic.claude-3-5-sonnet-20240620-v1:0",
                    )
                    aws_profile_input = gr.Textbox(
                        label="AWS Profile (for Bedrock only)",
                        value="",
                        placeholder="e.g., my-profile (optional, leave empty to use default credentials)",
                    )
                    aws_region_input = gr.Textbox(
                        label="AWS Region (for Bedrock only)",
                        value="",
                        placeholder="e.g., us-east-1 (optional, defaults to us-east-1)",
                    )

                with gr.Row():
                    infer_hints_input = gr.Checkbox(
                        label="Infer hints with LLM",
                        value=True,
                    )
                    require_asvs_input = gr.Checkbox(
                        label="Require ASVS references",
                        value=True,
                    )

                with gr.Row():
                    topn_input = gr.Slider(
                        label="Top N threats",
                        minimum=1,
                        maximum=10,
                        step=1,
                        value=10,
                    )
                    min_confidence_input = gr.Slider(
                        label="Minimum confidence",
                        minimum=0.0,
                        maximum=1.0,
                        step=0.05,
                        value=0.5,
                    )
                lang_input = gr.Textbox(
                    label="Output language (ISO code) - Enter any ISO language code. LLM will automatically translate UI elements to that language.",
                    value="en",
                    placeholder="e.g., en, ja, fr, de, es, zh, ko, pt, it, ru, ar, hi, th, vi, nl, sv, da, no, fi, pl, cs, hu, tr, he, id, ms, tl, bn, ta, te, ml, kn, gu, ur, fa, uk, bg, hr, sr, sk, sl, et, lv, lt, mt",
                )

                use_rag_input = gr.Checkbox(
                    label="Use Knowledge Base (local RAG)",
                    value=False,
                )
                kb_selector = gr.Dropdown(
                    label="Knowledge Bases",
                    choices=_kb_choices(),
                    multiselect=True,
                    value=[],
                    interactive=False,
                    allow_custom_value=False,
                    info="Build or refresh knowledge bases in the Knowledge Base tab.",
                )
                rag_topk_input = gr.Slider(
                    label="RAG top-k (retrieved chunks)",
                    minimum=1,
                    maximum=20,
                    step=1,
                    value=DEFAULT_TOPK,
                    interactive=False,
                )

                generate_button = gr.Button("Generate Report", variant="primary")

                with gr.Tabs():
                    with gr.Tab("Markdown Preview"):
                        report_markdown_output = gr.Markdown(
                            label="Report Preview (Markdown)",
                            value="Generate a report to see the preview here...",
                            sanitize_html=True,
                        )
                    with gr.Tab("Raw Text"):
                        report_output = gr.TextArea(
                            label="Report Preview (Raw)",
                            lines=20,
                            interactive=False,
                        )

                with gr.Row():
                    download_md_output = gr.File(
                        label="Download Markdown report",
                    )
                    download_json_output = gr.File(
                        label="Download JSON report",
                    )
                    download_html_output = gr.File(
                        label="Download HTML report",
                    )

                generate_button.click(
                    fn=_generate_report,
                    inputs=[
                        input_method,
                        diagram_input,
                        diagram_format_input,
                        image_input,
                        hints_input,
                        infer_hints_input,
                        llm_api_input,
                        llm_model_input,
                        aws_profile_input,
                        aws_region_input,
                        topn_input,
                        min_confidence_input,
                        require_asvs_input,
                        lang_input,
                        use_rag_input,
                        kb_selector,
                        rag_topk_input,
                    ],
                    outputs=[
                        report_markdown_output,
                        report_output,
                        download_md_output,
                        download_json_output,
                        download_html_output,
                    ],
                    api_name=False,
                )

                # Toggle visibility based on input method selection
                def update_input_visibility(method):
                    if method == "Text":
                        return {
                            diagram_input: gr.update(visible=True),
                            diagram_format_input: gr.update(visible=True),
                            image_input: gr.update(visible=False),
                        }
                    else:  # Image
                        return {
                            diagram_input: gr.update(visible=False),
                            diagram_format_input: gr.update(visible=False),
                            image_input: gr.update(visible=True),
                        }

                input_method.change(
                    fn=update_input_visibility,
                    inputs=[input_method],
                    outputs=[diagram_input, diagram_format_input, image_input],
                )

                def toggle_rag_controls(enabled, current_selection):
                    kb_value = current_selection if enabled else []
                    return {
                        kb_selector: gr.update(
                            interactive=enabled,
                            value=kb_value if enabled else [],
                        ),
                        rag_topk_input: gr.update(interactive=enabled),
                    }

                use_rag_input.change(
                    fn=toggle_rag_controls,
                    inputs=[use_rag_input, kb_selector],
                    outputs=[kb_selector, rag_topk_input],
                )

            with gr.Tab("KB - Knowledge Base"):
                gr.Markdown(
                    "### Build Knowledge Base\nUpload documents to create a local knowledge base for retrieval in threat analysis."
                )

                kb_name_input = gr.Textbox(
                    label="Knowledge Base Name",
                    placeholder="e.g., security-standards",
                )
                kb_files_input = gr.File(
                    label="Upload documents (PDF, Markdown, Text, HTML)",
                    file_types=sorted(SUPPORTED_EXTENSIONS),
                    type="filepath",
                    file_count="multiple",
                )
                with gr.Row():
                    kb_embedder_input = gr.Textbox(
                        label="Embedding model (OpenAI)",
                        value=f"openai:{DEFAULT_EMBED_MODEL}",
                        placeholder="openai:text-embedding-3-small",
                    )
                    kb_clean_raw_input = gr.Checkbox(
                        label="Replace existing raw documents",
                        value=True,
                    )
                with gr.Row():
                    kb_chunk_tokens_input = gr.Slider(
                        label="Chunk tokens",
                        minimum=100,
                        maximum=4000,
                        step=50,
                        value=DEFAULT_CHUNK_TOKENS,
                    )
                    kb_chunk_overlap_input = gr.Slider(
                        label="Chunk overlap",
                        minimum=0,
                        maximum=800,
                        step=10,
                        value=DEFAULT_CHUNK_OVERLAP,
                    )

                kb_build_button = gr.Button("Build Knowledge Base", variant="primary")
                kb_status_md = gr.Markdown(
                    value="Upload documents and click build to create a knowledge base.",
                    sanitize_html=True,
                )
                kb_list_md = gr.Markdown(value=_kb_list_markdown(), sanitize_html=True)
                with gr.Row():
                    kb_tab_refresh_button = gr.Button("Refresh Knowledge Bases")
                    kb_delete_selector = gr.Dropdown(
                        label="Select KB to delete",
                        choices=_kb_choices(),
                        multiselect=False,
                        allow_custom_value=False,
                    )
                    kb_delete_button = gr.Button("Delete Selected KB", variant="stop")

            with gr.Tab("Diff - Report Comparison"):
                gr.Markdown(
                    "### Compare Threat Reports\nUpload two JSON threat reports to analyze differences and generate a comparison report."
                )

                with gr.Row():
                    before_file_input = gr.File(
                        label="Before Report (JSON)",
                        file_types=[".json"],
                        type="filepath",
                    )
                    after_file_input = gr.File(
                        label="After Report (JSON)",
                        file_types=[".json"],
                        type="filepath",
                    )

                with gr.Row():
                    diff_llm_api_input = gr.Dropdown(
                        label="LLM API",
                        choices=["openai", "anthropic", "bedrock"],
                        value="openai",
                        interactive=True,
                    )
                    diff_llm_model_input = gr.Textbox(
                        label="LLM Model",
                        value="gpt-4.1",
                        placeholder="e.g., gpt-4.1, claude-3-haiku-20240307, anthropic.claude-3-5-sonnet-20240620-v1:0",
                    )
                    diff_aws_profile_input = gr.Textbox(
                        label="AWS Profile (for Bedrock only)",
                        value="",
                        placeholder="e.g., my-profile (optional, leave empty to use default credentials)",
                    )
                    diff_aws_region_input = gr.Textbox(
                        label="AWS Region (for Bedrock only)",
                        value="",
                        placeholder="e.g., us-east-1 (optional, defaults to us-east-1)",
                    )

                diff_lang_input = gr.Textbox(
                    label="Output language (ISO code)",
                    value="en",
                    placeholder="e.g., en, ja, fr, de, es, zh, ko, pt, it, ru, ar, hi, th, vi, nl, sv, da, no, fi, pl, cs, hu, tr, he, id, ms, tl, bn, ta, te, ml, kn, gu, ur, fa, uk, bg, hr, sr, sk, sl, et, lv, lt, mt",
                )

                diff_generate_button = gr.Button(
                    "Generate Diff Report", variant="primary"
                )

                with gr.Tabs():
                    with gr.Tab("Markdown Preview"):
                        diff_markdown_output = gr.Markdown(
                            label="Diff Report Preview (Markdown)",
                            value="Upload two JSON reports and generate a diff to see the comparison here...",
                            sanitize_html=True,
                        )
                    with gr.Tab("Raw Text"):
                        diff_raw_output = gr.TextArea(
                            label="Diff Report Preview (Raw JSON)",
                            lines=20,
                            interactive=False,
                        )

                with gr.Row():
                    diff_download_md_output = gr.File(
                        label="Download Markdown diff report",
                    )
                    diff_download_json_output = gr.File(
                        label="Download JSON diff report",
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
                        diff_lang_input,
                    ],
                    outputs=[
                        diff_markdown_output,
                        diff_raw_output,
                        diff_download_md_output,
                        diff_download_json_output,
                    ],
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
            ],
            outputs=[kb_status_md, kb_list_md, kb_selector, kb_delete_selector],
            api_name=False,
        )

        kb_tab_refresh_button.click(
            fn=_refresh_kb_inventory,
            inputs=[kb_selector],
            outputs=[kb_list_md, kb_selector, kb_delete_selector],
            api_name=False,
        )

        kb_delete_button.click(
            fn=_delete_kb,
            inputs=[kb_delete_selector],
            outputs=[kb_status_md, kb_list_md, kb_selector, kb_delete_selector],
            api_name=False,
        )

    try:
        demo.launch(server_name=server_name, server_port=server_port, share=False)
    finally:
        cleanup_temp_dir()


if __name__ == "__main__":
    launch_webui()
