"""
Threat Thinker WebUI powered by Gradio.
"""

import atexit
import json
import os
import shutil
import tempfile
import traceback
from typing import Callable, Optional, Tuple

import gradio as gr

import main as cli


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
    tmp = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=suffix)
    try:
        tmp.write(content)
    finally:
        tmp.close()
    return tmp.name


def _generate_report(
    mermaid_text: str,
    hints_text: str,
    infer_hints: bool,
    llm_api: str,
    llm_model: str,
    topn: int,
    min_confidence: float,
    require_asvs: bool,
    output_format: str,
) -> Tuple[str, dict, str, Optional[str]]:
    mermaid_text = (mermaid_text or "").strip()
    if not mermaid_text:
        raise gr.Error("Mermaid diagram input is required.")

    llm_api = (llm_api or "openai").strip().lower()
    llm_model = (llm_model or "").strip() or "gpt-4o-mini"

    mermaid_path = _write_temp_file(mermaid_text, ".mmd")
    hints_path = None
    if hints_text and hints_text.strip():
        hints_path = _write_temp_file(hints_text, ".yaml")

    status_lines = []
    download_path: Optional[str] = None

    try:
        graph, metrics = cli.parse_mermaid(mermaid_path)
        status_lines.append(
            f"Parsed Mermaid: {len(graph.nodes)} nodes, {len(graph.edges)} edges."
        )
        status_lines.append(
            f"Import success ~{metrics.import_success_rate * 100:.1f}% "
            f"(edges {metrics.edges_parsed}/{metrics.edge_candidates}, "
            f"labels {metrics.node_labels_parsed}/{metrics.node_label_candidates})"
        )

        if infer_hints:
            skeleton = json.dumps(
                {
                    "nodes": [{"id": node.id, "label": node.label} for node in graph.nodes.values()],
                    "edges": [{"from": edge.src, "to": edge.dst, "label": edge.label} for edge in graph.edges],
                },
                ensure_ascii=False,
                indent=2,
            )
            inferred = cli.llm_infer_hints(skeleton, llm_api, llm_model)
            graph = cli.merge_llm_hints(graph, inferred)
            status_lines.append("Applied LLM-inferred hints.")

        graph = cli.apply_hints(graph, hints_path)
        if hints_path:
            status_lines.append("Applied user-provided hints.")

        threats = cli.llm_infer_threats(graph, llm_api, llm_model)
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

        if output_format == "json":
            report_text = cli.export_json(filtered, None, metrics)
            file_suffix = ".json"
        else:
            report_text = cli.export_md(filtered, None, metrics)
            file_suffix = ".md"
        status_lines.append("Report generated successfully.")

        download_path = _write_temp_file(report_text, file_suffix)
        _DOWNLOAD_PATHS.add(download_path)

        metrics_json = {
            "total_lines": metrics.total_lines,
            "edge_candidates": metrics.edge_candidates,
            "edges_parsed": metrics.edges_parsed,
            "node_label_candidates": metrics.node_label_candidates,
            "node_labels_parsed": metrics.node_labels_parsed,
            "import_success_rate": metrics.import_success_rate,
            "threats_initial": len(threats),
            "threats_final": len(filtered),
        }
        return "\n".join(status_lines), metrics_json, report_text, download_path
    except gr.Error:
        raise
    except Exception as exc:
        traceback.print_exc()
        raise gr.Error(f"Failed to generate report: {exc}")
    finally:
        # clean up intermediate files; keep the report download file around
        for path in (mermaid_path, hints_path):
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass


def launch_webui(
    *,
    server_name: str = "127.0.0.1",
    server_port: Optional[int] = None,
    share: bool = False,
) -> None:
    """Launch the Gradio Web UI."""
    cleanup_temp_dir = _setup_gradio_temp_dir()
    with gr.Blocks(title="Threat Thinker WebUI") as demo:
        gr.Markdown("## Threat Thinker WebUI\nPaste your Mermaid diagram, optionally add YAML hints, and generate threat reports.")

        mermaid_input = gr.TextArea(
            label="Mermaid Diagram",
            placeholder="Paste your Mermaid diagram here...",
            lines=20,
            autofocus=True,
        )
        hints_input = gr.TextArea(
            label="Hints YAML (optional)",
            placeholder="Paste YAML hints here to override attributes...",
            lines=10,
        )

        with gr.Row():
            llm_api_input = gr.Dropdown(
                label="LLM API",
                choices=["openai", "anthropic"],
                value="openai",
                interactive=True,
            )
            llm_model_input = gr.Textbox(
                label="LLM Model",
                value="gpt-4o-mini",
                placeholder="e.g., gpt-4o-mini, claude-3-haiku-20240307",
            )

        with gr.Row():
            infer_hints_input = gr.Checkbox(
                label="Infer hints with LLM",
                value=False,
            )
            require_asvs_input = gr.Checkbox(
                label="Require ASVS references",
                value=False,
            )

        with gr.Row():
            topn_input = gr.Slider(
                label="Top N threats",
                minimum=1,
                maximum=50,
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
            format_input = gr.Radio(
                label="Report format",
                choices=["md", "json"],
                value="md",
            )

        generate_button = gr.Button("Generate Report", variant="primary")

        status_output = gr.Textbox(
            label="Status",
            lines=6,
            interactive=False,
        )
        metrics_output = gr.JSON(
            label="Import & Filtering Metrics",
        )
        report_output = gr.TextArea(
            label="Report Preview",
            lines=20,
            interactive=False,
        )
        download_output = gr.File(
            label="Download report",
        )

        generate_button.click(
            fn=_generate_report,
            inputs=[
                mermaid_input,
                hints_input,
                infer_hints_input,
                llm_api_input,
                llm_model_input,
                topn_input,
                min_confidence_input,
                require_asvs_input,
                format_input,
            ],
            outputs=[status_output, metrics_output, report_output, download_output],
            api_name=False,
        )

    try:
        demo.launch(server_name=server_name, server_port=server_port, share=share)
    finally:
        cleanup_temp_dir()


if __name__ == "__main__":
    launch_webui()
