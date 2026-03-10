"""
Shared input loader that dispatches source formats into the Graph IR.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from threat_thinker.models import Graph, ImportMetrics
from threat_thinker.parsers.drawio_parser import parse_drawio
from threat_thinker.parsers.image_parser import parse_image
from threat_thinker.parsers.ir_parser import parse_ir
from threat_thinker.parsers.mermaid_parser import parse_mermaid
from threat_thinker.parsers.threat_dragon_parser import (
    is_threat_dragon_json,
    parse_threat_dragon,
)

INPUT_FORMAT_MERMAID = "mermaid"
INPUT_FORMAT_DRAWIO = "drawio"
INPUT_FORMAT_THREAT_DRAGON = "threat-dragon"
INPUT_FORMAT_IMAGE = "image"
INPUT_FORMAT_IR = "ir"

TEXT_INPUT_FORMATS = {
    INPUT_FORMAT_MERMAID,
    INPUT_FORMAT_DRAWIO,
    INPUT_FORMAT_THREAT_DRAGON,
    INPUT_FORMAT_IR,
}
ALL_INPUT_FORMATS = TEXT_INPUT_FORMATS | {INPUT_FORMAT_IMAGE}


def detect_input_format(filename: str) -> Optional[str]:
    name = str(filename or "").lower()
    if name.endswith((".mmd", ".mermaid")):
        return INPUT_FORMAT_MERMAID
    if name.endswith((".drawio", ".xml")):
        return INPUT_FORMAT_DRAWIO
    if name.endswith(".json") and is_threat_dragon_json(filename):
        return INPUT_FORMAT_THREAT_DRAGON
    if name.endswith((".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp")):
        return INPUT_FORMAT_IMAGE
    return None


def suffix_for_text_input(input_format: str) -> str:
    if input_format == INPUT_FORMAT_MERMAID:
        return ".mmd"
    if input_format == INPUT_FORMAT_DRAWIO:
        return ".drawio"
    if input_format in {INPUT_FORMAT_THREAT_DRAGON, INPUT_FORMAT_IR}:
        return ".json"
    return ".txt"


def load_input(
    input_format: str,
    path: str,
    *,
    drawio_page: Optional[str] = None,
    api: Optional[str] = None,
    model: Optional[str] = None,
    aws_profile: Optional[str] = None,
    aws_region: Optional[str] = None,
    ollama_host: Optional[str] = None,
) -> Tuple[Graph, ImportMetrics]:
    if input_format == INPUT_FORMAT_MERMAID:
        return parse_mermaid(path)
    if input_format == INPUT_FORMAT_DRAWIO:
        return parse_drawio(path, page=drawio_page)
    if input_format == INPUT_FORMAT_THREAT_DRAGON:
        return parse_threat_dragon(path)
    if input_format == INPUT_FORMAT_IR:
        return parse_ir(path)
    if input_format == INPUT_FORMAT_IMAGE:
        return parse_image(
            path,
            api=api,
            model=model,
            aws_profile=aws_profile,
            aws_region=aws_region,
            ollama_host=ollama_host,
        )
    raise ValueError(f"Unsupported input format: {input_format}")


def basename_for_input(path: str) -> str:
    return Path(path).stem or "threat"
