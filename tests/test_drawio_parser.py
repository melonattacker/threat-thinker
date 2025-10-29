"""
Tests for drawio_parser module
"""

import os
import sys
import tempfile
import pytest

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from parsers.drawio_parser import parse_drawio, _clean_html_tags
from models import Graph, Node, Edge, ImportMetrics


class TestParseDrawio:
    """Test cases for parse_drawio function"""
    
    def test_parse_empty_drawio_file(self):
        """Test parsing an empty drawio file"""
        content = '<?xml version="1.0" encoding="UTF-8"?><mxGraphModel></mxGraphModel>'
        with tempfile.NamedTemporaryFile(mode='w', suffix='.drawio', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
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
        """Test parsing a simple drawio diagram with nodes and edges"""
        content = '''<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="User" style="rounded=1;" parent="1"/>
    <mxCell id="node2" value="API" style="rounded=1;" parent="1"/>
    <mxCell id="edge1" value="HTTP Request" edge="1" source="node1" target="node2" parent="1"/>
  </root>
</mxGraphModel>'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.drawio', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_drawio(temp_path)
            
            assert len(graph.nodes) == 2
            assert len(graph.edges) == 1
            
            # Check nodes
            assert "node1" in graph.nodes
            assert "node2" in graph.nodes
            assert graph.nodes["node1"].label == "User"
            assert graph.nodes["node2"].label == "API"
            
            # Check edges
            assert graph.edges[0].src == "node1"
            assert graph.edges[0].dst == "node2"
            assert graph.edges[0].label == "HTTP Request"
            
            assert metrics.edges_parsed == 1
            assert metrics.edge_candidates == 1
            assert metrics.node_labels_parsed == 2
            assert metrics.node_label_candidates == 2
        finally:
            os.unlink(temp_path)
    
    def test_parse_drawio_with_html_content(self):
        """Test parsing drawio content with HTML formatting"""
        content = '''<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="&lt;b&gt;Web Server&lt;/b&gt;&lt;br&gt;Port 80" style="rounded=1;" parent="1"/>
    <mxCell id="node2" value="&lt;i&gt;Database&lt;/i&gt;" style="rounded=1;" parent="1"/>
    <mxCell id="edge1" value="&lt;font color=&quot;red&quot;&gt;SQL Query&lt;/font&gt;" edge="1" source="node1" target="node2" parent="1"/>
  </root>
</mxGraphModel>'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.drawio', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_drawio(temp_path)
            
            assert len(graph.nodes) == 2
            assert len(graph.edges) == 1
            
            # Check that HTML tags are cleaned
            assert "Web Server" in graph.nodes["node1"].label
            assert "Port 80" in graph.nodes["node1"].label
            assert "<b>" not in graph.nodes["node1"].label
            assert "<br>" not in graph.nodes["node1"].label
            
            assert graph.nodes["node2"].label == "Database"
            assert "<i>" not in graph.nodes["node2"].label
            
            assert graph.edges[0].label == "SQL Query"
            assert "font" not in graph.edges[0].label
        finally:
            os.unlink(temp_path)
    
    def test_parse_drawio_with_no_edges(self):
        """Test parsing drawio diagram with only nodes"""
        content = '''<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="Standalone Node" style="rounded=1;" parent="1"/>
  </root>
</mxGraphModel>'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.drawio', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
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
        """Test parsing drawio with edge missing source or target"""
        content = '''<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="Node1" style="rounded=1;" parent="1"/>
    <mxCell id="edge1" value="Invalid Edge" edge="1" source="node1" parent="1"/>
  </root>
</mxGraphModel>'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.drawio', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_drawio(temp_path)
            
            assert len(graph.nodes) == 1
            assert len(graph.edges) == 0  # Invalid edge should be skipped
            assert metrics.edge_candidates == 1
            assert metrics.edges_parsed == 0
        finally:
            os.unlink(temp_path)
    
    def test_parse_drawio_url_encoded_content(self):
        """Test parsing drawio with URL-encoded content"""
        content = '''<?xml version="1.0" encoding="UTF-8"?>
<mxGraphModel>
  <root>
    <mxCell id="0"/>
    <mxCell id="1" parent="0"/>
    <mxCell id="node1" value="User%20Interface" style="rounded=1;" parent="1"/>
    <mxCell id="node2" value="API%20Gateway" style="rounded=1;" parent="1"/>
    <mxCell id="edge1" value="HTTPS%20Request" edge="1" source="node1" target="node2" parent="1"/>
  </root>
</mxGraphModel>'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.drawio', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_drawio(temp_path)
            
            assert len(graph.nodes) == 2
            assert len(graph.edges) == 1
            
            # Check URL decoding
            assert graph.nodes["node1"].label == "User Interface"
            assert graph.nodes["node2"].label == "API Gateway"
            assert graph.edges[0].label == "HTTPS Request"
        finally:
            os.unlink(temp_path)

    def test_parse_invalid_xml_file(self):
        """Test parsing an invalid XML file"""
        content = "This is not valid XML"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.drawio', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_drawio(temp_path)
            
            # Should return empty graph on parse error
            assert len(graph.nodes) == 0
            assert len(graph.edges) == 0
        finally:
            os.unlink(temp_path)


class TestCleanHtmlTags:
    """Test cases for _clean_html_tags function"""
    
    def test_clean_simple_html_tags(self):
        """Test cleaning simple HTML tags"""
        input_text = "<b>Bold</b> and <i>italic</i>"
        result = _clean_html_tags(input_text)
        assert result == "Bold and italic"
    
    def test_clean_html_entities(self):
        """Test cleaning HTML entities"""
        input_text = "&lt;script&gt; &amp; &quot;test&quot;"
        result = _clean_html_tags(input_text)
        assert result == "<script> & \"test\""
    
    def test_clean_complex_html(self):
        """Test cleaning complex HTML with attributes"""
        input_text = '<font color="red">Red Text</font><br><span style="font-size:12px">Small</span>'
        result = _clean_html_tags(input_text)
        assert result == "Red TextSmall"
    
    def test_clean_empty_string(self):
        """Test cleaning empty string"""
        result = _clean_html_tags("")
        assert result == ""
    
    def test_clean_none_input(self):
        """Test cleaning None input"""
        result = _clean_html_tags(None)
        assert result is None
    
    def test_clean_no_html(self):
        """Test cleaning text with no HTML"""
        input_text = "Plain text with no HTML"
        result = _clean_html_tags(input_text)
        assert result == "Plain text with no HTML"