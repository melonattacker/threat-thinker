"""
Tests for drawio_parser module
"""

import base64
import os
import sys
import tempfile
import urllib.parse
import zlib

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_thinker.models import Graph, ImportMetrics
from threat_thinker.parsers.drawio_parser import _clean_html_tags, parse_drawio


def _write_temp_drawio(content: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".drawio", delete=False) as f:
        f.write(content)
        return f.name


def _compress_drawio_diagram(model_xml: str) -> str:
    quoted = urllib.parse.quote(model_xml)
    compressor = zlib.compressobj(level=9, wbits=-15)
    payload = compressor.compress(quoted.encode("utf-8")) + compressor.flush()
    return base64.b64encode(payload).decode("ascii")


class TestParseDrawio:
    """Test cases for parse_drawio function"""

    def test_parse_empty_drawio_file(self):
        content = '<?xml version="1.0" encoding="UTF-8"?><mxGraphModel></mxGraphModel>'
        temp_path = _write_temp_drawio(content)
        try:
            graph, metrics = parse_drawio(temp_path)
            assert isinstance(graph, Graph)
            assert isinstance(metrics, ImportMetrics)
            assert len(graph.nodes) == 0
            assert len(graph.edges) == 0
            assert metrics.total_lines > 0
        finally:
            os.unlink(temp_path)

    def test_parse_simple_drawio_diagram(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="User" style="rounded=1;" vertex="1" parent="1"/>
    <mxCell id="node2" value="API" style="rounded=1;" vertex="1" parent="1"/>
    <mxCell id="edge1" value="HTTP Request" edge="1" source="node1" target="node2" parent="1"/>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, metrics = parse_drawio(temp_path)

            assert len(graph.nodes) == 2
            assert len(graph.edges) == 1
            assert graph.nodes["node1"].label == "User"
            assert graph.nodes["node2"].label == "API"
            assert graph.edges[0].src == "node1"
            assert graph.edges[0].dst == "node2"
            assert graph.edges[0].label == "HTTP Request"
            assert graph.edges[0].id == "edge1"
            assert metrics.edges_parsed == 1
            assert metrics.edge_candidates == 1
            assert metrics.node_labels_parsed == 2
            assert metrics.node_label_candidates == 2
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_with_html_content(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="&lt;b&gt;Web Server&lt;/b&gt;&lt;br&gt;Port 80" style="rounded=1;" vertex="1" parent="1"/>
    <mxCell id="node2" value="&lt;i&gt;Database&lt;/i&gt;" style="rounded=1;" vertex="1" parent="1"/>
    <mxCell id="edge1" value="&lt;font color=&quot;red&quot;&gt;SQL Query&lt;/font&gt;" edge="1" source="node1" target="node2" parent="1"/>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert len(graph.nodes) == 2
            assert len(graph.edges) == 1
            assert graph.nodes["node1"].label == "Web Server Port 80"
            assert graph.nodes["node2"].label == "Database"
            assert graph.edges[0].label == "SQL Query"
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_with_no_edges(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="Standalone Node" style="rounded=1;" vertex="1" parent="1"/>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, metrics = parse_drawio(temp_path)
            assert len(graph.nodes) == 1
            assert len(graph.edges) == 0
            assert graph.nodes["node1"].label == "Standalone Node"
            assert metrics.edges_parsed == 0
            assert metrics.edge_candidates == 0
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_invalid_edge(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="Node1" style="rounded=1;" vertex="1" parent="1"/>
    <mxCell id="edge1" value="Invalid Edge" edge="1" source="node1" parent="1"/>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, metrics = parse_drawio(temp_path)
            assert len(graph.nodes) == 1
            assert len(graph.edges) == 0
            assert metrics.edge_candidates == 1
            assert metrics.edges_parsed == 0
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_url_encoded_content(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="User%20Interface" style="rounded=1;" vertex="1" parent="1"/>
    <mxCell id="node2" value="API%20Gateway" style="rounded=1;" vertex="1" parent="1"/>
    <mxCell id="edge1" value="HTTPS%20Request" edge="1" source="node1" target="node2" parent="1"/>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert len(graph.nodes) == 2
            assert len(graph.edges) == 1
            assert graph.nodes["node1"].label == "User Interface"
            assert graph.nodes["node2"].label == "API Gateway"
            assert graph.edges[0].label == "HTTPS Request"
        finally:
            os.unlink(temp_path)

    def test_parse_invalid_xml_file(self):
        temp_path = _write_temp_drawio("This is not valid XML")
        try:
            graph, _ = parse_drawio(temp_path)
            assert len(graph.nodes) == 0
            assert len(graph.edges) == 0
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_nested_zones(self):
        xml_content = """
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="outer" value="Outer" style="shape=rectangle;dashed=1;" vertex="1" parent="1">
      <mxGeometry x="0" y="0" width="200" height="200" as="geometry"/>
    </mxCell>
    <mxCell id="inner" value="Inner" style="shape=rectangle;dashed=1;" vertex="1" parent="1">
      <mxGeometry x="50" y="50" width="80" height="80" as="geometry"/>
    </mxCell>
    <mxCell id="svc" value="Service" vertex="1" parent="1">
      <mxGeometry x="60" y="60" width="20" height="20" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>
""".strip()
        temp_path = _write_temp_drawio(xml_content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert graph.nodes["svc"].zone == "Inner"
            assert graph.nodes["svc"].zones == ["outer", "inner"]
            assert graph.zones["inner"].parent_id == "outer"
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_nested_relative_coordinates(self):
        xml_content = """
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="outer" value="Outer" style="shape=rectangle;dashed=1;" vertex="1" parent="1">
      <mxGeometry x="10" y="10" width="200" height="200" as="geometry"/>
    </mxCell>
    <mxCell id="inner" value="Inner" style="shape=rectangle;dashed=1;" vertex="1" parent="outer">
      <mxGeometry x="20" y="30" width="80" height="80" as="geometry"/>
    </mxCell>
    <mxCell id="svc" value="Service" vertex="1" parent="inner">
      <mxGeometry x="5" y="5" width="10" height="10" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>
""".strip()
        temp_path = _write_temp_drawio(xml_content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert graph.nodes["svc"].zone == "Inner"
            assert graph.nodes["svc"].zones == ["outer", "inner"]
            assert graph.zones["inner"].parent_id == "outer"
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_edge_labels(self):
        xml_content = """
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="a" value="Client" vertex="1" parent="1">
      <mxGeometry x="0" y="0" width="80" height="40" as="geometry"/>
    </mxCell>
    <mxCell id="b" value="Server" vertex="1" parent="1">
      <mxGeometry x="200" y="0" width="80" height="40" as="geometry"/>
    </mxCell>
    <mxCell id="e1" edge="1" source="a" target="b" parent="1">
      <mxGeometry relative="1" as="geometry"/>
    </mxCell>
    <mxCell id="label1" value="Send HTTP Request" style="edgeLabel;html=1;" vertex="1" connectable="0" parent="e1">
      <mxGeometry x="0" y="0" width="0" height="0" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>
""".strip()
        temp_path = _write_temp_drawio(xml_content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert set(graph.nodes.keys()) == {"a", "b"}
            assert len(graph.edges) == 1
            assert graph.edges[0].label == "Send HTTP Request"
            assert graph.edges[0].id == "e1"
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_mxfile_uncompressed_page(self):
        diagram_xml = """<mxGraphModel><root><mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/><mxCell id=\"node1\" value=\"User\" vertex=\"1\" parent=\"1\"/></root></mxGraphModel>"""
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="app.diagrams.net">
  <diagram id="page-1" name="Page-1">{html_escape(diagram_xml)}</diagram>
</mxfile>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert set(graph.nodes.keys()) == {"node1"}
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_mxfile_compressed_page(self):
        diagram_xml = """<mxGraphModel><root><mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/><mxCell id=\"node1\" value=\"User\" vertex=\"1\" parent=\"1\"/></root></mxGraphModel>"""
        compressed = _compress_drawio_diagram(diagram_xml)
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="app.diagrams.net">
  <diagram id="page-1" name="Page-1">{compressed}</diagram>
</mxfile>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert set(graph.nodes.keys()) == {"node1"}
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_namespace_xml(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel xmlns="http://www.diagrams.net">
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="User" vertex="1" parent="1"/>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert set(graph.nodes.keys()) == {"node1"}
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_page_selection_by_id_name_and_index(self):
        page1_xml = """<mxGraphModel><root><mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/><mxCell id=\"n1\" value=\"First\" vertex=\"1\" parent=\"1\"/></root></mxGraphModel>"""
        page2_xml = """<mxGraphModel><root><mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/><mxCell id=\"n2\" value=\"Second\" vertex=\"1\" parent=\"1\"/></root></mxGraphModel>"""
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile>
  <diagram id="p1" name="One">{html_escape(page1_xml)}</diagram>
  <diagram id="p2" name="Two">{html_escape(page2_xml)}</diagram>
</mxfile>"""
        temp_path = _write_temp_drawio(content)
        try:
            by_id, _ = parse_drawio(temp_path, page="p2")
            by_name, _ = parse_drawio(temp_path, page="Two")
            by_index, _ = parse_drawio(temp_path, page="1")
            assert set(by_id.nodes.keys()) == {"n2"}
            assert set(by_name.nodes.keys()) == {"n2"}
            assert set(by_index.nodes.keys()) == {"n2"}
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_page_selection_fallback_warns(self, capsys):
        page_xml = """<mxGraphModel><root><mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/><mxCell id=\"n1\" value=\"First\" vertex=\"1\" parent=\"1\"/></root></mxGraphModel>"""
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile>
  <diagram id="p1" name="One">{html_escape(page_xml)}</diagram>
</mxfile>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path, page="does-not-exist")
            out = capsys.readouterr().out
            assert set(graph.nodes.keys()) == {"n1"}
            assert "falling back to first page" in out
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_excludes_non_vertex_group_cells(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="group1" style="group" parent="1"/>
    <mxCell id="node1" value="User" vertex="1" parent="1"/>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert set(graph.nodes.keys()) == {"node1"}
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_rescues_unlabeled_edge_endpoints(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="source" vertex="1" parent="1"/>
    <mxCell id="target" value="Target" vertex="1" parent="1"/>
    <mxCell id="edge1" edge="1" source="source" target="target" parent="1"/>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert set(graph.nodes.keys()) == {"source", "target"}
            assert graph.nodes["source"].label == "source"
            assert len(graph.edges) == 1
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_skips_unlabeled_non_endpoint_vertices(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="lonely" vertex="1" parent="1"/>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert len(graph.nodes) == 0
        finally:
            os.unlink(temp_path)

    def test_parse_drawio_swimlane_zone_detection(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="z1" value="VPC" style="swimlane;rounded=1;" vertex="1" parent="1">
      <mxGeometry x="0" y="0" width="300" height="200" as="geometry"/>
    </mxCell>
    <mxCell id="n1" value="API" vertex="1" parent="1">
      <mxGeometry x="30" y="30" width="40" height="40" as="geometry"/>
    </mxCell>
  </root>
</mxGraphModel>"""
        temp_path = _write_temp_drawio(content)
        try:
            graph, _ = parse_drawio(temp_path)
            assert graph.nodes["n1"].zone == "VPC"
            assert graph.nodes["n1"].zones == ["z1"]
        finally:
            os.unlink(temp_path)


class TestCleanHtmlTags:
    """Test cases for _clean_html_tags function"""

    def test_clean_simple_html_tags(self):
        assert _clean_html_tags("<b>Bold</b> and <i>italic</i>") == "Bold and italic"

    def test_clean_html_entities(self):
        assert _clean_html_tags("&lt;script&gt; &amp; &quot;test&quot;") == '& "test"'

    def test_clean_complex_html(self):
        input_text = '<font color="red">Red Text</font><br><span style="font-size:12px">Small</span>'
        assert _clean_html_tags(input_text) == "Red Text Small"

    def test_clean_empty_string(self):
        assert _clean_html_tags("") == ""

    def test_clean_none_input(self):
        assert _clean_html_tags(None) is None

    def test_clean_no_html(self):
        assert _clean_html_tags("Plain text with no HTML") == "Plain text with no HTML"


def html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
