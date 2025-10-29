"""
Tests for mermaid_parser module
"""

import os
import sys
import tempfile
import pytest

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from parsers.mermaid_parser import parse_mermaid
from models import Graph, Node, Edge, ImportMetrics


class TestParseMermaid:
    """Test cases for parse_mermaid function"""
    
    def test_parse_empty_mermaid_file(self):
        """Test parsing an empty mermaid file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as f:
            f.write("")
            temp_path = f.name
        
        try:
            graph, metrics = parse_mermaid(temp_path)
            
            assert isinstance(graph, Graph)
            assert isinstance(metrics, ImportMetrics)
            assert len(graph.nodes) == 0
            assert len(graph.edges) == 0
            assert metrics.total_lines == 0
            assert metrics.edge_candidates == 0
            assert metrics.edges_parsed == 0
        finally:
            os.unlink(temp_path)
    
    def test_parse_simple_edge(self):
        """Test parsing a simple edge A -> B"""
        content = "A --> B"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_mermaid(temp_path)
            
            assert len(graph.edges) == 1
            assert len(graph.nodes) == 2
            assert graph.edges[0].src == "A"
            assert graph.edges[0].dst == "B"
            assert graph.edges[0].label is None
            assert "A" in graph.nodes
            assert "B" in graph.nodes
            assert metrics.edges_parsed == 1
            assert metrics.edge_candidates == 1
        finally:
            os.unlink(temp_path)
    
    def test_parse_edge_with_label(self):
        """Test parsing an edge with label A -> B |label|"""
        content = "A --> B |HTTP request|"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_mermaid(temp_path)
            
            assert len(graph.edges) == 1
            assert graph.edges[0].src == "A"
            assert graph.edges[0].dst == "B"
            assert graph.edges[0].label == "HTTP request"
        finally:
            os.unlink(temp_path)
    
    def test_parse_node_labels(self):
        """Test parsing node labels like A[User]"""
        content = """A[User]
B((API))
A --> B"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_mermaid(temp_path)
            
            assert graph.nodes["A"].label == "User"
            assert graph.nodes["B"].label == "API"
            assert metrics.node_labels_parsed == 2
            assert metrics.node_label_candidates == 2
        finally:
            os.unlink(temp_path)
    
    def test_parse_arrow_variations(self):
        """Test parsing different arrow variations"""
        content = """A -> B
C --> D
E ---> F"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_mermaid(temp_path)
            
            assert len(graph.edges) == 3
            assert metrics.edges_parsed == 3
            assert metrics.edge_candidates == 3
        finally:
            os.unlink(temp_path)
    
    def test_parse_unicode_arrow_normalization(self):
        """Test normalization of unicode arrows"""
        content = "A—→B"  # em dash and arrow
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_mermaid(temp_path)
            
            assert len(graph.edges) == 1
            assert graph.edges[0].src == "A"
            assert graph.edges[0].dst == "B"
        finally:
            os.unlink(temp_path)
    
    def test_import_success_rate_calculation(self):
        """Test import success rate calculation"""
        content = """A --> B
C[User]
invalid line that should not parse
D --> E |label|"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            graph, metrics = parse_mermaid(temp_path)
            
            # Should parse 2 edges and 1 node label
            assert metrics.edges_parsed == 2
            assert metrics.node_labels_parsed == 1
            assert metrics.import_success_rate > 0
        finally:
            os.unlink(temp_path)