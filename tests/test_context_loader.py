import pytest

from threat_thinker.context_loader import (
    ContextDocumentError,
    format_context_documents,
    load_context_documents,
    read_context_file,
)


def test_load_context_text_and_markdown(tmp_path):
    text_file = tmp_path / "business.txt"
    md_file = tmp_path / "scope.md"
    text_file.write_text("Payment operations context", encoding="utf-8")
    md_file.write_text("# Scope\nCustomer refunds", encoding="utf-8")

    docs = load_context_documents([text_file, md_file], "gpt-4.1")
    prompt_block = format_context_documents(docs)

    assert [doc.source for doc in docs] == ["business.txt", "scope.md"]
    assert all(doc.token_count > 0 for doc in docs)
    assert "Business context documents" in prompt_block
    assert "Payment operations context" in prompt_block
    assert "Customer refunds" in prompt_block


def test_context_loader_rejects_unsupported_missing_and_empty(tmp_path):
    unsupported = tmp_path / "data.csv"
    unsupported.write_text("a,b", encoding="utf-8")
    empty = tmp_path / "empty.txt"
    empty.write_text("   ", encoding="utf-8")

    with pytest.raises(ContextDocumentError):
        read_context_file(unsupported)
    with pytest.raises(ContextDocumentError):
        read_context_file(tmp_path / "missing.txt")
    with pytest.raises(ContextDocumentError):
        read_context_file(empty)


def test_context_loader_extracts_pdf_text(tmp_path, monkeypatch):
    pdf_file = tmp_path / "scope.pdf"
    pdf_file.write_bytes(b"%PDF-1.4 fake")

    class _Page:
        def extract_text(self):
            return "Drone operations staff context"

    class _PdfReader:
        def __init__(self, path):
            self.pages = [_Page()]

    monkeypatch.setattr("pypdf.PdfReader", _PdfReader)

    doc = read_context_file(pdf_file, "gpt-4.1")

    assert doc.source == "scope.pdf"
    assert doc.text == "Drone operations staff context"
    assert doc.token_count > 0
