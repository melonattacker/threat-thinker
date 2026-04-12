"""
Business context document loading for prompt injection.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import tiktoken


CONTEXT_TEXT_EXTENSIONS = {".md", ".markdown", ".txt", ".text"}
SUPPORTED_CONTEXT_EXTENSIONS = {".pdf", *CONTEXT_TEXT_EXTENSIONS}


class ContextDocumentError(Exception):
    """Raised when business context documents cannot be loaded."""


@dataclass(frozen=True)
class ContextDocument:
    source: str
    text: str
    token_count: int


def get_encoding(model: Optional[str] = None):
    if model:
        try:
            return tiktoken.encoding_for_model(model)
        except KeyError:
            pass
    return tiktoken.get_encoding("cl100k_base")


def count_tokens(text: str, model: Optional[str] = None) -> int:
    return len(get_encoding(model).encode(text or ""))


def _read_pdf_text(path: Path) -> str:
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n".join(pages)
    except ContextDocumentError:
        raise
    except Exception as exc:
        raise ContextDocumentError(
            f"Failed to read PDF context file {path}: {exc}"
        ) from exc


def read_context_file(path: str | Path, model: Optional[str] = None) -> ContextDocument:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise ContextDocumentError(f"Context file not found: {file_path}")
    if not file_path.is_file():
        raise ContextDocumentError(f"Context path is not a file: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix not in SUPPORTED_CONTEXT_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_CONTEXT_EXTENSIONS))
        raise ContextDocumentError(
            f"Unsupported context file type: {suffix}. Supported: {supported}"
        )

    if suffix == ".pdf":
        text = _read_pdf_text(file_path)
    else:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            raise ContextDocumentError(
                f"Failed to read context file {file_path}: {exc}"
            ) from exc

    text = text.strip()
    if not text:
        raise ContextDocumentError(
            f"Context file is empty after text extraction: {file_path}"
        )

    return ContextDocument(
        source=file_path.name,
        text=text,
        token_count=count_tokens(text, model),
    )


def read_context_text(
    source: str,
    text: str,
    model: Optional[str] = None,
) -> ContextDocument:
    name = Path(source or "context.txt").name
    suffix = Path(name).suffix.lower()
    if suffix and suffix not in SUPPORTED_CONTEXT_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_CONTEXT_EXTENSIONS))
        raise ContextDocumentError(
            f"Unsupported context file type: {suffix}. Supported: {supported}"
        )
    clean_text = (text or "").strip()
    if not clean_text:
        raise ContextDocumentError(f"Context document is empty: {name}")
    return ContextDocument(
        source=name,
        text=clean_text,
        token_count=count_tokens(clean_text, model),
    )


def load_context_documents(
    paths: Iterable[str | Path],
    model: Optional[str] = None,
) -> list[ContextDocument]:
    docs = [read_context_file(path, model) for path in paths if path]
    return docs


def format_context_documents(documents: Iterable[ContextDocument]) -> str:
    docs = list(documents)
    if not docs:
        return ""

    blocks = ["Business context documents (full text):"]
    for idx, doc in enumerate(docs, start=1):
        blocks.append(
            f"\n[Context Document {idx}: {doc.source}]\n{doc.text}\n[/Context Document {idx}]"
        )
    return "\n".join(blocks).strip()


def context_summary(documents: Iterable[ContextDocument]) -> tuple[int, int, list[str]]:
    docs = list(documents)
    return (
        len(docs),
        sum(doc.token_count for doc in docs),
        [doc.source for doc in docs],
    )
