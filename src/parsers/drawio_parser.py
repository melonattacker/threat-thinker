"""
Draw.io diagram parser
"""

import urllib.parse
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from models import Edge, Graph, ImportMetrics, Node
from zone_utils import (
    compute_zone_tree_from_rectangles,
    containing_zone_ids_for_point,
    representative_zone_name,
)


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

        # First pass: collect all nodes (non-edge cells) and zone candidates
        cell_id_map: Dict[str, str] = {}  # maps cell id -> node id for our graph
        node_geometry: Dict[str, Tuple[float, float, float, float]] = {}
        zone_rects: List[Dict[str, float]] = []

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

            geometry = _extract_geometry(cell)

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

            # Identify trust boundary/zone cells
            if _is_zone_cell(cell, value, geometry):
                zone_rects.append(
                    {
                        "id": cell_id,
                        "name": value or cell_id,
                        "x": geometry[0] if geometry else 0.0,
                        "y": geometry[1] if geometry else 0.0,
                        "width": geometry[2] if geometry else 0.0,
                        "height": geometry[3] if geometry else 0.0,
                    }
                )
                continue

            # Use cell ID as node ID, or value if no meaningful ID
            node_id = cell_id
            if not value:
                value = node_id

            # Create node
            node = Node(id=node_id, label=value.strip())
            g.nodes[node_id] = node
            cell_id_map[cell_id] = node_id
            if geometry:
                node_geometry[node_id] = geometry

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

        if zone_rects:
            g.zones = compute_zone_tree_from_rectangles(zone_rects)
            for node_id, geom in node_geometry.items():
                cx = geom[0] + geom[2] / 2
                cy = geom[1] + geom[3] / 2
                zone_ids = containing_zone_ids_for_point(cx, cy, zone_rects, g.zones)
                g.nodes[node_id].zones = zone_ids
                g.nodes[node_id].zone = representative_zone_name(zone_ids, g.zones)

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


def _extract_geometry(cell: ET.Element) -> Optional[Tuple[float, float, float, float]]:
    """Extract geometry tuple (x, y, width, height) from an mxCell."""
    geom = cell.find("mxGeometry")
    if geom is None:
        return None
    try:
        x = float(geom.get("x") or 0)
        y = float(geom.get("y") or 0)
        width = float(geom.get("width") or 0)
        height = float(geom.get("height") or 0)
        return x, y, width, height
    except Exception:
        return None


def _is_zone_cell(
    cell: ET.Element, label: str, geometry: Optional[Tuple[float, float, float, float]]
) -> bool:
    """
    Heuristic to detect trust boundaries in draw.io: dashed/dotted rectangles with a label.
    """
    if geometry is None:
        return False
    style = (cell.get("style") or "").lower()
    if not label:
        return False
    is_rectangle_like = "rectangle" in style or "shape=rect" in style or "rounded=1" in style
    has_boundary_hint = (
        "dashed=1" in style
        or "dashpattern" in style
        or "boundary" in style
        or "zone" in style
        or "trust" in style
    )
    return is_rectangle_like and has_boundary_hint
