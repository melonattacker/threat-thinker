"""
Tests for image parser
"""

import unittest
import tempfile
import os
import json
import base64
from unittest.mock import patch, MagicMock

from threat_thinker.parsers.image_parser import (
    parse_image,
    _encode_image_to_base64,
    _analyze_image_with_llm,
    _parse_llm_response_to_graph,
)
from threat_thinker.models import Graph, ImportMetrics
from threat_thinker.llm.response_utils import clean_json_response, safe_json_loads


class TestImageParser(unittest.TestCase):
    def setUp(self):
        """Create a temporary image file for testing."""
        # Create a minimal PNG image (1x1 pixel, red)
        self.png_data = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
        )

        # Create temporary image file
        self.temp_image = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        self.temp_image.write(self.png_data)
        self.temp_image.close()

    def tearDown(self):
        """Clean up temporary files."""
        if os.path.exists(self.temp_image.name):
            os.unlink(self.temp_image.name)

    def test_encode_image_to_base64(self):
        """Test base64 encoding of image file."""
        result = _encode_image_to_base64(self.temp_image.name)

        # Should return a base64 string
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

        # Should be decodable back to original data
        decoded = base64.b64decode(result)
        self.assertEqual(decoded, self.png_data)

    def test_unsupported_file_format(self):
        """Test error handling for unsupported file formats."""
        # Create a temporary file with unsupported extension
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        temp_file.write(b"test content")
        temp_file.close()

        try:
            graph, metrics = parse_image(temp_file.name)
            # Should not raise exception but return empty graph
            self.assertEqual(len(graph.nodes), 0)
            self.assertEqual(len(graph.edges), 0)
        finally:
            os.unlink(temp_file.name)

    def test_file_not_found(self):
        """Test error handling for non-existent files."""
        graph, metrics = parse_image("/nonexistent/file.png")

        # Should return empty graph
        self.assertEqual(len(graph.nodes), 0)
        self.assertEqual(len(graph.edges), 0)

    def test_parse_llm_response_to_graph(self):
        """Test parsing LLM response into Graph structure."""
        graph = Graph()
        metrics = ImportMetrics()

        llm_data = {
            "zones": [
                {
                    "id": "internet",
                    "name": "Internet",
                    "bounds": {"x": 0, "y": 0, "width": 400, "height": 400},
                },
                {
                    "id": "dmz",
                    "name": "DMZ",
                    "bounds": {"x": 40, "y": 40, "width": 200, "height": 200},
                },
                {
                    "id": "private",
                    "name": "Private",
                    "bounds": {"x": 80, "y": 80, "width": 120, "height": 120},
                },
            ],
            "nodes": [
                {
                    "id": "user",
                    "label": "User",
                    "type": "user",
                    "bounds": {"x": 10, "y": 10, "width": 10, "height": 10},
                },
                {
                    "id": "web_server",
                    "label": "Web Server",
                    "type": "service",
                    "bounds": {"x": 90, "y": 90, "width": 20, "height": 20},
                },
                {
                    "id": "database",
                    "label": "Database",
                    "type": "database",
                    "bounds": {"x": 120, "y": 120, "width": 20, "height": 20},
                    "zones": ["dmz", "private"],
                },
            ],
            "edges": [
                {
                    "src": "user",
                    "dst": "web_server",
                    "label": "HTTPS Request",
                    "protocol": "HTTPS",
                },
                {
                    "src": "web_server",
                    "dst": "database",
                    "label": "SQL Query",
                    "protocol": "TCP",
                },
            ],
        }

        _parse_llm_response_to_graph(llm_data, graph, metrics)

        # Check nodes
        self.assertEqual(len(graph.nodes), 3)
        self.assertIn("user", graph.nodes)
        self.assertIn("web_server", graph.nodes)
        self.assertIn("database", graph.nodes)

        user_node = graph.nodes["user"]
        self.assertEqual(user_node.label, "User")
        self.assertEqual(user_node.type, "user")
        self.assertEqual(user_node.zone, "Internet")
        self.assertEqual(user_node.zones, ["internet"])
        self.assertEqual(graph.nodes["database"].zones, ["internet", "dmz", "private"])

        # Check edges
        self.assertEqual(len(graph.edges), 2)

        first_edge = graph.edges[0]
        self.assertEqual(first_edge.src, "user")
        self.assertEqual(first_edge.dst, "web_server")
        self.assertEqual(first_edge.label, "HTTPS Request")
        self.assertEqual(first_edge.protocol, "HTTPS")

        # Check metrics
        self.assertEqual(metrics.node_label_candidates, 3)
        self.assertEqual(metrics.node_labels_parsed, 3)
        self.assertEqual(metrics.edge_candidates, 2)
        self.assertEqual(metrics.edges_parsed, 2)

    def test_parse_llm_response_with_invalid_data(self):
        """Test parsing LLM response with invalid/missing data."""
        graph = Graph()
        metrics = ImportMetrics()

        # Test with invalid node data
        llm_data = {
            "nodes": [
                {"label": "Missing ID Node"},  # No ID
                {"id": "", "label": "Empty ID Node"},  # Empty ID
                {"id": "valid_node", "label": "Valid Node"},  # Valid node
            ],
            "edges": [
                {"dst": "valid_node", "label": "Missing source"},  # No src
                {"src": "valid_node", "label": "Missing destination"},  # No dst
                {
                    "src": "valid_node",
                    "dst": "valid_node",
                    "label": "Self loop",
                },  # Valid edge
            ],
        }

        _parse_llm_response_to_graph(llm_data, graph, metrics)

        # Only valid nodes and edges should be added
        self.assertEqual(len(graph.nodes), 1)
        self.assertEqual(len(graph.edges), 1)

        # Check that valid node was parsed
        self.assertIn("valid_node", graph.nodes)
        self.assertEqual(graph.nodes["valid_node"].label, "Valid Node")

        # Check that valid edge was parsed
        edge = graph.edges[0]
        self.assertEqual(edge.src, "valid_node")
        self.assertEqual(edge.dst, "valid_node")
        self.assertEqual(edge.label, "Self loop")

    @patch("threat_thinker.parsers.image_parser.LLMClient")
    def test_analyze_image_with_llm_success(self, mock_llm_client_class):
        """Test successful image analysis with mocked LLM."""
        # Mock LLM client
        mock_client = MagicMock()
        mock_llm_client_class.return_value = mock_client

        # Mock LLM response
        mock_response = json.dumps(
            {
                "nodes": [{"id": "test_node", "label": "Test Node", "type": "service"}],
                "edges": [
                    {"src": "test_node", "dst": "test_node", "label": "Self connection"}
                ],
            }
        )
        mock_client.analyze_image_for_graph.return_value = mock_response

        # Test image analysis
        result = _analyze_image_with_llm("fake_base64_data", ".png")

        # Verify result
        self.assertIsInstance(result, dict)
        self.assertIn("nodes", result)
        self.assertIn("edges", result)
        self.assertEqual(len(result["nodes"]), 1)
        self.assertEqual(len(result["edges"]), 1)

        # Verify LLM client was called correctly
        mock_client.analyze_image_for_graph.assert_called_once()
        call_args = mock_client.analyze_image_for_graph.call_args
        self.assertEqual(call_args[1]["base64_image"], "fake_base64_data")
        self.assertEqual(call_args[1]["media_type"], "image/png")

    @patch("threat_thinker.parsers.image_parser.LLMClient")
    def test_analyze_image_with_llm_failure(self, mock_llm_client_class):
        """Test image analysis with LLM failure."""
        # Mock LLM client that raises exception
        mock_client = MagicMock()
        mock_llm_client_class.return_value = mock_client
        mock_client.analyze_image_for_graph.side_effect = Exception("LLM API Error")

        # Test image analysis
        result = _analyze_image_with_llm("fake_base64_data", ".png")

        # Should return empty dict on failure
        self.assertEqual(result, {})

    @patch("threat_thinker.parsers.image_parser._analyze_image_with_llm")
    def test_parse_image_integration(self, mock_analyze):
        """Test full parse_image function integration."""
        # Mock LLM analysis
        mock_analyze.return_value = {
            "nodes": [
                {"id": "frontend", "label": "Frontend App", "type": "service"},
                {"id": "backend", "label": "Backend API", "type": "service"},
            ],
            "edges": [
                {
                    "src": "frontend",
                    "dst": "backend",
                    "label": "API Call",
                    "protocol": "HTTPS",
                }
            ],
        }

        # Test parsing
        graph, metrics = parse_image(self.temp_image.name)

        # Verify graph structure
        self.assertEqual(len(graph.nodes), 2)
        self.assertEqual(len(graph.edges), 1)

        # Verify nodes
        self.assertIn("frontend", graph.nodes)
        self.assertIn("backend", graph.nodes)
        self.assertEqual(graph.nodes["frontend"].label, "Frontend App")
        self.assertEqual(graph.nodes["backend"].type, "service")

        # Verify edges
        edge = graph.edges[0]
        self.assertEqual(edge.src, "frontend")
        self.assertEqual(edge.dst, "backend")
        self.assertEqual(edge.protocol, "HTTPS")

        # Verify metrics
        self.assertEqual(metrics.node_label_candidates, 2)
        self.assertEqual(metrics.node_labels_parsed, 2)
        self.assertEqual(metrics.edge_candidates, 1)
        self.assertEqual(metrics.edges_parsed, 1)
        self.assertTrue(metrics.total_lines > 0)  # File size should be recorded

    def test_clean_json_response(self):
        """Test JSON response cleaning utility."""
        # Test with ```json markers
        response_with_markers = '```json\n{"test": "value"}\n```'
        cleaned = clean_json_response(response_with_markers)
        self.assertEqual(cleaned, '{"test": "value"}')

        # Test with ``` markers only
        response_with_basic_markers = '```\n{"test": "value"}\n```'
        cleaned = clean_json_response(response_with_basic_markers)
        self.assertEqual(cleaned, '{"test": "value"}')

        # Test without markers
        response_clean = '{"test": "value"}'
        cleaned = clean_json_response(response_clean)
        self.assertEqual(cleaned, '{"test": "value"}')

        # Test with whitespace
        response_with_whitespace = '  \n```json\n  {"test": "value"}  \n```  \n'
        cleaned = clean_json_response(response_with_whitespace)
        self.assertEqual(cleaned, '{"test": "value"}')

    def test_safe_json_loads(self):
        """Test safe JSON loading utility."""
        # Test with markers that need cleaning
        response_with_markers = '```json\n{"nodes": [], "edges": []}\n```'
        result = safe_json_loads(response_with_markers)
        self.assertEqual(result, {"nodes": [], "edges": []})

        # Test with clean JSON
        clean_json = '{"nodes": [], "edges": []}'
        result = safe_json_loads(clean_json)
        self.assertEqual(result, {"nodes": [], "edges": []})


if __name__ == "__main__":
    unittest.main()
