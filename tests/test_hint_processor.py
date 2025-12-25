"""
Tests for hint_processor module
"""

import os
import sys
import tempfile
import yaml

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_thinker.hint_processor import apply_hints, merge_llm_hints
from threat_thinker.models import Edge, Graph, Node, Zone


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
            assert result.nodes["A"].zones == ["DMZ"]
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

    def test_apply_hints_with_zones_list(self):
        """Zones list should populate ordered zones."""
        graph = Graph()
        graph.nodes["A"] = Node(id="A", label="A")
        hints_data = {"nodes": {"A": {"zones": ["outer", "inner"]}}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(hints_data, f)
            temp_path = f.name

        try:
            result = apply_hints(graph, temp_path)
            assert result.nodes["A"].zones == ["outer", "inner"]
            assert result.nodes["A"].zone == "inner"
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
        assert node.zones == ["internal"]
        assert node.auth
        assert node.notes == "Updated notes"
        assert "existing" in node.data
        assert "new_data" in node.data

    def test_merge_node_hints_new_node(self):
        """Test merging node hints for new node is ignored"""
        graph = Graph()

        hints = {
            "nodes": {
                "B": {"label": "New Node", "type": "database", "data": ["sensitive"]}
            }
        }

        result = merge_llm_hints(graph, hints)

        assert "B" not in result.nodes

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
        """Test merging edge hints for new edge is ignored"""
        graph = Graph()

        hints = {
            "edges": [
                {"from": "C", "to": "D", "protocol": "gRPC", "data": ["protobuf"]}
            ]
        }

        result = merge_llm_hints(graph, hints)

        assert len(result.edges) == 0

    def test_merge_hints_preserves_zone_ids_with_existing_map(self):
        """Zone names from hints should map to existing zone ids instead of clobbering them."""
        graph = Graph()
        graph.zones = {
            "boundary-edge": Zone(id="boundary-edge", name="Edge / DMZ"),
            "boundary-internet": Zone(id="boundary-internet", name="Internet"),
        }
        graph.nodes["A"] = Node(
            id="A",
            label="API",
            zones=["boundary-edge"],
            zone="Edge / DMZ",
        )

        hints = {"nodes": {"A": {"zones": ["DMZ", "Edge / DMZ"]}}}

        result = merge_llm_hints(graph, hints)

        node = result.nodes["A"]
        assert node.zones == ["boundary-edge"]
        assert node.zone == "Edge / DMZ"

    def test_merge_hints_partial_mapping_keeps_existing_inner_zone(self):
        """When hints only partially map, retain existing zones and merge mapped ones."""
        graph = Graph()
        graph.zones = {
            "boundary-internet": Zone(id="boundary-internet", name="Internet"),
            "boundary-edge": Zone(id="boundary-edge", name="Edge / DMZ"),
        }
        graph.nodes["A"] = Node(
            id="A",
            label="API",
            zones=["boundary-edge"],
            zone="Edge / DMZ",
        )

        # Hint only knows about the outer zone name.
        hints = {"nodes": {"A": {"zones": ["Internet"]}}}

        result = merge_llm_hints(graph, hints)

        node = result.nodes["A"]
        # Since the hint targets a different root and there is no hierarchy, keep the existing inner zone only.
        assert node.zones == ["boundary-edge"]
        assert node.zone == "Edge / DMZ"

    def test_merge_hints_conflicting_root_zone_is_ignored(self):
        """Hints that map to a different root should not overwrite existing path."""
        graph = Graph()
        graph.zones = {
            "root-a": Zone(id="root-a", name="RootA"),
            "root-b": Zone(id="root-b", name="RootB"),
        }
        graph.nodes["X"] = Node(
            id="X",
            label="Node X",
            zones=["root-a"],
            zone="RootA",
        )

        hints = {"nodes": {"X": {"zones": ["RootB"]}}}

        result = merge_llm_hints(graph, hints)
        node = result.nodes["X"]
        assert node.zones == ["root-a"]
        assert node.zone == "RootA"

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

        assert "A" not in result.nodes
