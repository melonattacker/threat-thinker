"""
Tests for hint_processor module
"""

import os
import sys
import tempfile
import yaml

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hint_processor import apply_hints, merge_llm_hints
from models import Graph, Node, Edge


class TestApplyHints:
    """Test cases for apply_hints function"""

    def test_apply_hints_none_path(self):
        """Test applying hints with None path"""
        graph = Graph()
        graph.nodes["A"] = Node(id="A", label="A")

        result = apply_hints(graph, None)

        assert result is graph
        assert len(result.nodes) == 1

    def test_apply_hints_empty_yaml(self):
        """Test applying hints from empty YAML file"""
        graph = Graph()
        graph.nodes["A"] = Node(id="A", label="A")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            temp_path = f.name

        try:
            result = apply_hints(graph, temp_path)

            assert len(result.nodes) == 1
            assert result.nodes["A"].label == "A"
        finally:
            os.unlink(temp_path)

    def test_apply_node_hints(self):
        """Test applying node hints from YAML"""
        graph = Graph()
        graph.nodes["A"] = Node(id="A", label="A")

        hints_data = {
            "nodes": {
                "A": {
                    "label": "User Interface",
                    "zone": "DMZ",
                    "type": "frontend",
                    "auth": True,
                    "notes": "Web frontend",
                    "data": ["PII", "Session"],
                },
                "B": {"label": "New Node", "type": "service"},
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(hints_data, f)
            temp_path = f.name

        try:
            result = apply_hints(graph, temp_path)

            # Test existing node update
            assert result.nodes["A"].label == "User Interface"
            assert result.nodes["A"].zone == "DMZ"
            assert result.nodes["A"].type == "frontend"
            assert result.nodes["A"].auth
            assert result.nodes["A"].notes == "Web frontend"
            assert "PII" in result.nodes["A"].data
            assert "Session" in result.nodes["A"].data

            # Test new node creation
            assert "B" in result.nodes
            assert result.nodes["B"].label == "New Node"
            assert result.nodes["B"].type == "service"
        finally:
            os.unlink(temp_path)

    def test_apply_edge_hints_existing_edge(self):
        """Test applying hints to existing edge"""
        graph = Graph()
        graph.nodes["A"] = Node(id="A", label="A")
        graph.nodes["B"] = Node(id="B", label="B")
        graph.edges.append(Edge(src="A", dst="B"))

        hints_data = {
            "edges": [
                {
                    "from": "A",
                    "to": "B",
                    "protocol": "HTTPS",
                    "label": "API Call",
                    "data": ["Credentials", "UserData"],
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(hints_data, f)
            temp_path = f.name

        try:
            result = apply_hints(graph, temp_path)

            assert len(result.edges) == 1
            edge = result.edges[0]
            assert edge.protocol == "HTTPS"
            assert edge.label == "API Call"
            assert "Credentials" in edge.data
            assert "UserData" in edge.data
        finally:
            os.unlink(temp_path)

    def test_apply_edge_hints_new_edge(self):
        """Test applying hints for new edge"""
        graph = Graph()
        graph.nodes["A"] = Node(id="A", label="A")

        hints_data = {
            "edges": [
                {
                    "from": "A",
                    "to": "C",
                    "protocol": "HTTP",
                    "label": "Request",
                    "data": ["JSON"],
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(hints_data, f)
            temp_path = f.name

        try:
            result = apply_hints(graph, temp_path)

            # Should create new edge and nodes
            assert len(result.edges) == 1
            assert len(result.nodes) == 2
            assert "C" in result.nodes

            edge = result.edges[0]
            assert edge.src == "A"
            assert edge.dst == "C"
            assert edge.protocol == "HTTP"
            assert edge.label == "Request"
            assert "JSON" in edge.data
        finally:
            os.unlink(temp_path)

    def test_apply_hints_invalid_edge_data(self):
        """Test applying hints with invalid edge data"""
        graph = Graph()

        hints_data = {
            "edges": [
                {
                    "from": "A",
                    # Missing "to" field - should be skipped
                    "protocol": "HTTP",
                },
                {
                    # Missing "from" field - should be skipped
                    "to": "B",
                    "protocol": "HTTPS",
                },
            ]
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(hints_data, f)
            temp_path = f.name

        try:
            result = apply_hints(graph, temp_path)

            # No edges should be created due to invalid data
            assert len(result.edges) == 0
        finally:
            os.unlink(temp_path)


class TestMergeLlmHints:
    """Test cases for merge_llm_hints function"""

    def test_merge_empty_hints(self):
        """Test merging empty hints"""
        graph = Graph()
        graph.nodes["A"] = Node(id="A", label="A")

        result = merge_llm_hints(graph, {})

        assert len(result.nodes) == 1
        assert result.nodes["A"].label == "A"

    def test_merge_node_hints_existing_node(self):
        """Test merging node hints for existing node"""
        graph = Graph()
        graph.nodes["A"] = Node(id="A", label="A", data=["existing"])

        hints = {
            "nodes": {
                "A": {
                    "label": "Updated Label",
                    "type": "service",
                    "zone": "internal",
                    "auth": True,
                    "notes": "Updated notes",
                    "data": ["new_data"],
                }
            }
        }

        result = merge_llm_hints(graph, hints)

        node = result.nodes["A"]
        assert node.label == "Updated Label"
        assert node.type == "service"
        assert node.zone == "internal"
        assert node.auth
        assert node.notes == "Updated notes"
        assert "existing" in node.data
        assert "new_data" in node.data

    def test_merge_node_hints_new_node(self):
        """Test merging node hints for new node"""
        graph = Graph()

        hints = {
            "nodes": {
                "B": {"label": "New Node", "type": "database", "data": ["sensitive"]}
            }
        }

        result = merge_llm_hints(graph, hints)

        assert "B" in result.nodes
        node = result.nodes["B"]
        assert node.label == "New Node"
        assert node.type == "database"
        assert "sensitive" in node.data

    def test_merge_edge_hints_existing_edge(self):
        """Test merging edge hints for existing edge"""
        graph = Graph()
        graph.nodes["A"] = Node(id="A", label="A")
        graph.nodes["B"] = Node(id="B", label="B")
        edge = Edge(src="A", dst="B", data=["existing"])
        graph.edges.append(edge)

        hints = {
            "edges": [
                {"from": "A", "to": "B", "protocol": "TLS", "data": ["encrypted"]}
            ]
        }

        result = merge_llm_hints(graph, hints)

        assert len(result.edges) == 1
        merged_edge = result.edges[0]
        assert merged_edge.protocol == "TLS"
        assert "existing" in merged_edge.data
        assert "encrypted" in merged_edge.data

    def test_merge_edge_hints_new_edge(self):
        """Test merging edge hints for new edge"""
        graph = Graph()

        hints = {
            "edges": [
                {"from": "C", "to": "D", "protocol": "gRPC", "data": ["protobuf"]}
            ]
        }

        result = merge_llm_hints(graph, hints)

        assert len(result.edges) == 1
        new_edge = result.edges[0]
        assert new_edge.src == "C"
        assert new_edge.dst == "D"
        assert new_edge.protocol == "gRPC"
        assert "protobuf" in new_edge.data

    def test_merge_hints_invalid_edge_data(self):
        """Test merging hints with invalid edge data"""
        graph = Graph()

        hints = {
            "edges": [
                {
                    "from": "A",
                    # Missing "to" field - should be skipped
                    "protocol": "HTTP",
                },
                {
                    # Missing "from" field - should be skipped
                    "to": "B",
                    "protocol": "HTTPS",
                },
            ]
        }

        result = merge_llm_hints(graph, hints)

        # No edges should be created due to invalid data
        assert len(result.edges) == 0

    def test_merge_hints_non_list_data(self):
        """Test merging hints with non-list data (should be ignored)"""
        graph = Graph()

        hints = {
            "nodes": {
                "A": {
                    "label": "Test",
                    "data": "not_a_list",  # Should be ignored
                }
            }
        }

        result = merge_llm_hints(graph, hints)

        assert "A" in result.nodes
        assert result.nodes["A"].label == "Test"
        assert result.nodes["A"].data == []  # Should remain empty
