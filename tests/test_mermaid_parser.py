"""
Tests for mermaid_parser module
"""

import os
import sys
import tempfile

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_thinker.parsers.mermaid_parser import parse_mermaid
from threat_thinker.models import Graph, ImportMetrics

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


class TestParseMermaid:
    """Test cases for parse_mermaid function"""

    def test_parse_empty_mermaid_file(self):
        """Test parsing an empty mermaid file"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
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

    def test_parse_edge_with_inline_label(self):
        """Test parsing an edge with inline label A -- HTTP --> B"""
        content = "A -- HTTP --> B"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            graph, metrics = parse_mermaid(temp_path)

            assert len(graph.edges) == 1
            assert graph.edges[0].src == "A"
            assert graph.edges[0].dst == "B"
            assert graph.edges[0].label == "HTTP"
            assert metrics.edges_parsed == 1
            assert metrics.edge_candidates == 1
        finally:
            os.unlink(temp_path)

    def test_parse_node_labels(self):
        """Test parsing node labels like A[User]"""
        content = """A[User]
B((API))
A --> B"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
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
E ---> F
G -- TLS --> H"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            graph, metrics = parse_mermaid(temp_path)

            assert len(graph.edges) == 4
            assert metrics.edges_parsed == 4
            assert metrics.edge_candidates == 4
        finally:
            os.unlink(temp_path)

    def test_parse_unicode_arrow_normalization(self):
        """Test normalization of unicode arrows"""
        content = "A—→B"  # em dash and arrow
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            graph, metrics = parse_mermaid(temp_path)

            assert len(graph.edges) == 1
            assert graph.edges[0].src == "A"
            assert graph.edges[0].dst == "B"
        finally:
            os.unlink(temp_path)

    def test_parse_edge_with_source_inline_label(self):
        """Test parsing edge when source has inline label like user[User] --> api"""
        content = 'user["User Browser"] -->|HTTPS| api((API Gateway))'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            graph, metrics = parse_mermaid(temp_path)

            assert len(graph.edges) == 1
            edge = graph.edges[0]
            assert edge.src == "user"
            assert edge.dst == "api"
            assert edge.label == "HTTPS"
            assert graph.nodes["user"].label == "User Browser"
            assert graph.nodes["api"].label == "API Gateway"
            assert metrics.edges_parsed == 1
            assert metrics.edge_candidates == 1
            assert "user" in graph.nodes and "api" in graph.nodes
        finally:
            os.unlink(temp_path)

    def test_parse_standard_pipe_edge_variations(self):
        """Test Mermaid-standard pipe labels and bidirectional expansion."""
        content = """A -->|HTTPS| B
A --> |TLS| C
C -.->|AMQP| D
D ==>|gRPC| E
E <--> F
G --> H |legacy|"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            graph, metrics = parse_mermaid(temp_path)
            edge_tuples = [(edge.src, edge.dst, edge.label) for edge in graph.edges]

            assert ("A", "B", "HTTPS") in edge_tuples
            assert ("A", "C", "TLS") in edge_tuples
            assert ("C", "D", "AMQP") in edge_tuples
            assert ("D", "E", "gRPC") in edge_tuples
            assert ("E", "F", None) in edge_tuples
            assert ("F", "E", None) in edge_tuples
            assert ("G", "H", "legacy") in edge_tuples
            assert metrics.edge_candidates == 6
            assert metrics.edges_parsed == 7
        finally:
            os.unlink(temp_path)

    def test_parse_mermaid_flowchart_sample_with_pipe_labels(self):
        """Test user-reported flowchart parsing with Mermaid-standard labels."""
        fixture_path = os.path.join(
            FIXTURE_DIR, "mermaid_flowchart_with_pipe_labels.mmd"
        )
        graph, metrics = parse_mermaid(fixture_path)

        assert len(graph.nodes) == 9
        assert len(graph.edges) == 9
        assert metrics.edge_candidates == 9
        assert metrics.edges_parsed == 9

        labels = {(edge.src, edge.dst): edge.label for edge in graph.edges}
        assert labels[("user", "waf")] == "HTTPS"
        assert labels[("order", "db")] == "TLS"
        assert labels[("mq", "worker")] == "AMQP"
        assert labels[("order", "pay")] == "HTTPS"

    def test_parse_invalid_edge_counts_candidate_without_parsing(self):
        """Invalid arrow line should count as edge candidate but not parsed edge."""
        content = """A -->
B --> C"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            graph, metrics = parse_mermaid(temp_path)
            assert len(graph.edges) == 1
            assert graph.edges[0].src == "B"
            assert graph.edges[0].dst == "C"
            assert metrics.edge_candidates == 2
            assert metrics.edges_parsed == 1
        finally:
            os.unlink(temp_path)

    def test_import_success_rate_calculation(self):
        """Test import success rate calculation"""
        content = """A --> B
C[User]
invalid line that should not parse
D --> E |label|"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
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

    def test_subgraph_nested_zones(self):
        """Test nested subgraphs populate zones"""
        content = """graph TD
subgraph Internet
  ext[User]
  subgraph VPC
    api(API)
  end
end
ext --> api"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mmd", delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            graph, _ = parse_mermaid(temp_path)
            zones_by_name = {z.name: zid for zid, z in graph.zones.items()}
            assert "Internet" in zones_by_name
            assert "VPC" in zones_by_name
            assert graph.nodes["api"].zone == "VPC"
            assert graph.nodes["api"].zones == [
                zones_by_name["Internet"],
                zones_by_name["VPC"],
            ]
            assert graph.nodes["ext"].zones == [zones_by_name["Internet"]]
        finally:
            os.unlink(temp_path)
