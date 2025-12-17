from __future__ import annotations

import base64
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from threat_thinker.exporters import export_html, export_json, export_md
from threat_thinker.hint_processor import merge_llm_hints
from threat_thinker.llm.inference import (
    llm_infer_hints,
    llm_infer_threats,
)
from threat_thinker.parsers.drawio_parser import parse_drawio
from threat_thinker.parsers.image_parser import parse_image
from threat_thinker.parsers.mermaid_parser import parse_mermaid
from threat_thinker.parsers.threat_dragon_parser import parse_threat_dragon
from threat_thinker.threat_analyzer import denoise_threats
from threat_thinker.serve.config import EngineConfig, TimeoutConfig
from threat_thinker.serve.schemas import AnalyzeOptions, AnalyzeRequest, InputPayload

logger = logging.getLogger(__name__)


class AnalysisError(Exception):
    """Raised when analysis fails."""


@dataclass
class ReportEntry:
    report_format: str
    content: str


@dataclass
class AnalysisResult:
    reports: list[ReportEntry]
    duration_ms: int
    model: str


def _write_temp_text(content: str, suffix: str) -> str:
    tmp = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=suffix)
    try:
        tmp.write(content)
    finally:
        tmp.close()
    return tmp.name


def _write_temp_bytes(data: bytes, suffix: str) -> str:
    tmp = tempfile.NamedTemporaryFile("wb", delete=False, suffix=suffix)
    try:
        tmp.write(data)
    finally:
        tmp.close()
    return tmp.name


def _decode_bytes(data_b64: Optional[str]) -> bytes:
    if not data_b64:
        return b""
    return base64.b64decode(data_b64)


def _suffix_for_input(job_input: InputPayload) -> str:
    if job_input.filename:
        return Path(job_input.filename).suffix or ""
    if job_input.type == "mermaid":
        return ".mmd"
    if job_input.type == "drawio":
        return ".xml"
    if job_input.type == "threat_dragon":
        return ".json"
    if job_input.type == "image":
        return ".png"
    return ""


def _assert_provider_ready(
    provider: str, input_type: str, aws_profile: Optional[str] = None
) -> None:
    prov = provider.lower()
    if prov == "openai" and not os.getenv("OPENAI_API_KEY"):
        raise AnalysisError("OPENAI_API_KEY is required for analysis.")
    if prov == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        raise AnalysisError("ANTHROPIC_API_KEY is required for analysis.")
    if prov == "bedrock":
        if not (
            aws_profile
            or (
                os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
            )
        ):
            logger.warning("AWS credentials are not fully configured for Bedrock usage.")
    if prov == "ollama" and input_type == "image":
        raise AnalysisError("Image inputs are not supported with the Ollama backend.")


def analyze_job(
    payload: Dict[str, Any], engine: EngineConfig, timeouts: TimeoutConfig
) -> AnalysisResult:
    request = AnalyzeRequest.model_validate(payload)
    job_input = request.input
    opts: AnalyzeOptions = request.options

    if job_input.type not in engine.allowed_inputs:
        raise AnalysisError(f"Input type '{job_input.type}' is not allowed.")

    provider = (engine.model.provider or "openai").lower()
    model_name = engine.model.name or "gpt-4.1-mini"
    ollama_host = (
        engine.model.ollama_host or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
    )
    _assert_provider_ready(provider, job_input.type, engine.model.aws_profile)

    start_time = time.time()
    temp_paths: list[str] = []

    try:
        suffix = _suffix_for_input(job_input)
        diagram_path = ""

        if job_input.type == "image":
            data = _decode_bytes(job_input.data_b64)
            if not data:
                raise AnalysisError("Image payload is empty.")
            diagram_path = _write_temp_bytes(data, suffix or ".png")
        else:
            content = (job_input.content or "").strip()
            if not content:
                raise AnalysisError("Diagram content is empty.")
            diagram_path = _write_temp_text(content, suffix or ".txt")

        temp_paths.append(diagram_path)

        if job_input.type == "mermaid":
            graph, metrics = parse_mermaid(diagram_path)
        elif job_input.type == "drawio":
            graph, metrics = parse_drawio(diagram_path)
        elif job_input.type == "threat_dragon":
            graph, metrics = parse_threat_dragon(diagram_path)
        elif job_input.type == "image":
            graph, metrics = parse_image(
                diagram_path,
                api=provider,
                model=model_name,
                aws_profile=engine.model.aws_profile,
                aws_region=engine.model.aws_region,
                ollama_host=ollama_host,
            )
        else:
            raise AnalysisError(f"Unsupported input type: {job_input.type}")

        if opts.infer_hints:
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
            try:
                inferred = llm_infer_hints(
                    skeleton,
                    provider,
                    model_name,
                    engine.model.aws_profile,
                    engine.model.aws_region,
                    ollama_host,
                    opts.language or engine.report.default_language,
                )
                graph = merge_llm_hints(graph, inferred)
            except Exception as exc:
                raise AnalysisError(f"Failed to infer hints: {exc}") from exc

        try:
            threats = llm_infer_threats(
                graph,
                provider,
                model_name,
                engine.model.aws_profile,
                engine.model.aws_region,
                ollama_host,
                opts.language or engine.report.default_language,
            )
        except Exception as exc:
            raise AnalysisError(f"Threat inference failed: {exc}") from exc

        threats = denoise_threats(
            threats,
            require_asvs=opts.require_asvs,
            min_confidence=opts.min_confidence,
            topn=opts.topn,
        )

        formats = opts.report_formats or [engine.report.default_format]
        reports: list[ReportEntry] = []
        for fmt in formats:
            if fmt == "markdown":
                content = export_md(threats)
            elif fmt == "html":
                content = export_html(threats, graph=graph)
            elif fmt == "json":
                content = export_json(threats, out_path=None, metrics=metrics, graph=graph)
            else:
                raise AnalysisError(f"Unsupported report format: {fmt}")
            reports.append(ReportEntry(report_format=fmt, content=content))

        duration_ms = int((time.time() - start_time) * 1000)
        return AnalysisResult(
            reports=reports,
            duration_ms=duration_ms,
            model=model_name,
        )
    finally:
        for path in temp_paths:
            try:
                os.unlink(path)
            except OSError:
                pass
