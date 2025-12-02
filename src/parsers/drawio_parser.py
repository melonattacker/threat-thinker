"""
Draw.io diagram parser
"""

import xml.etree.ElementTree as ET
import urllib.parse
from typing import Tuple, Dict

from models import Graph, Node, Edge, ImportMetrics


def parse_drawio(path: str) -> Tuple[Graph, ImportMetrics]:
    """
    Parse a Draw.io diagram file and return a Graph object and import metrics.

    Args:
        path: Path to the Draw.io file (.drawio, .xml)

    Returns:
        Tuple of (Graph, ImportMetrics)
    """
    g = Graph(source_format="drawio")
    metrics = ImportMetrics()

    try:
        # Parse XML file
        tree = ET.parse(path)
        root = tree.getroot()

        # Count total lines for metrics
        with open(path, "r", encoding="utf-8") as f:
            metrics.total_lines = len(f.readlines())

        # Find mxGraphModel element
        graph_model = root.find(".//mxGraphModel")
        if graph_model is None:
            # Try to find if root itself is mxGraphModel
            if root.tag == "mxGraphModel":
                graph_model = root
            else:
                return g, metrics

        # Get all mxCell elements
        cells = graph_model.findall(".//mxCell")

        # First pass: collect all nodes (non-edge cells)
        cell_id_map: Dict[str, str] = {}  # maps cell id -> node id for our graph

        for cell in cells:
            cell_id = cell.get("id")
            if not cell_id:
                continue

            # Skip if this is an edge
            if cell.get("edge") == "1":
                metrics.edge_candidates += 1
                continue

            # Skip the default cells (usually id="0" and id="1")
            if cell_id in ["0", "1"]:
                continue

            # Extract node information
            value = cell.get("value", "")
            if value:
                # URL decode the value in case it's encoded
                try:
                    value = urllib.parse.unquote(value)
                except Exception:
                    pass

                # Remove HTML tags if present
                value = _clean_html_tags(value)

            # Use cell ID as node ID, or value if no meaningful ID
            node_id = cell_id
            if not value:
                value = node_id

            # Create node
            node = Node(id=node_id, label=value.strip())
            g.nodes[node_id] = node
            cell_id_map[cell_id] = node_id

        # Second pass: collect edges
        for cell in cells:
            if cell.get("edge") != "1":
                continue

            source_id = cell.get("source")
            target_id = cell.get("target")

            if not source_id or not target_id:
                continue

            # Map cell IDs to our node IDs
            src_node_id = cell_id_map.get(source_id)
            dst_node_id = cell_id_map.get(target_id)

            if not src_node_id or not dst_node_id:
                continue

            # Extract edge label
            label = cell.get("value", "")
            if label:
                try:
                    label = urllib.parse.unquote(label)
                except Exception:
                    pass
                label = _clean_html_tags(label)
                label = label.strip() if label.strip() else None
            else:
                label = None

            # Create edge
            edge = Edge(src=src_node_id, dst=dst_node_id, label=label)
            g.edges.append(edge)
            metrics.edges_parsed += 1

        # Update metrics
        metrics.node_label_candidates = len(g.nodes)
        metrics.node_labels_parsed = len(g.nodes)

    except ET.ParseError as e:
        # Handle XML parsing errors
        print(f"Warning: Failed to parse XML file {path}: {e}")
    except Exception as e:
        # Handle other errors
        print(f"Warning: Error processing file {path}: {e}")

    return g, metrics


def _clean_html_tags(text: str) -> str:
    """
    Remove HTML tags from text content.
    Draw.io often stores text with HTML formatting.

    Args:
        text: Text potentially containing HTML tags

    Returns:
        Cleaned text without HTML tags
    """
    if not text:
        return text

    # Simple HTML tag removal - good enough for draw.io content
    import re

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", "", text)

    # Decode common HTML entities
    text = text.replace("&lt;", "<")
    text = text.replace("&gt;", ">")
    text = text.replace("&amp;", "&")
    text = text.replace("&quot;", '"')
    text = text.replace("&#39;", "'")
    text = text.replace("&nbsp;", " ")

    return text.strip()
