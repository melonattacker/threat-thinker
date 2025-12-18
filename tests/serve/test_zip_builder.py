import zipfile
from io import BytesIO

from threat_thinker.serve.api import _build_zip_bytes, ReportContent


def test_build_zip_bytes_includes_reports():
    reports = [
        ReportContent(report_format="markdown", content="# hello"),
        ReportContent(report_format="json", content='{"ok":true}'),
    ]
    data = _build_zip_bytes("abc123", reports)
    buf = BytesIO(data)
    with zipfile.ZipFile(buf, "r") as zf:
        names = set(zf.namelist())
        assert "threat-thinker-abc123.md" in names
        assert "threat-thinker-abc123.json" in names
        assert zf.read("threat-thinker-abc123.md").decode() == "# hello"
