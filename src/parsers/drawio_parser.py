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
        cells_by_id: Dict[str, ET.Element] = {
            cell.get("id"): cell for cell in cells if cell.get("id")
        }

        # First pass: collect all nodes (non-edge cells) and zone candidates
        cell_id_map: Dict[str, str] = {}  # maps cell id -> node id for our graph
        node_geometry: Dict[str, Tuple[float, float, float, float]] = {}
        zone_rects: List[Dict[str, float]] = []
        edge_labels: Dict[str, str] = {}

        for cell in cells:
            cell_id = cell.get("id")
            if not cell_id:
                continue

            style = (cell.get("style") or "").lower()

            # edgeLabel cells attach labels to edges; do not treat as nodes
            if "edgelabel" in style:
                parent_edge_id = cell.get("parent")
                if parent_edge_id:
                    label_value = _decode_and_clean(cell.get("value", ""))
                    if label_value:
                        edge_labels[parent_edge_id] = label_value
                continue

            # Skip if this is an edge
            if cell.get("edge") == "1":
                metrics.edge_candidates += 1
                continue

            # Skip the default cells (usually id="0" and id="1")
            if cell_id in ["0", "1"]:
                continue

            geometry = _extract_absolute_geometry(cell, cells_by_id)

            # Extract node information
            value = _decode_and_clean(cell.get("value", ""))

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
            label = _decode_and_clean(cell.get("value", ""))
            if not label:
                label = edge_labels.get(cell.get("id") or "") or None

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


def _decode_and_clean(value: Optional[str]) -> str:
    """URL-decode a value and strip simple HTML markup."""
    if value is None:
        return ""
    text = value
    try:
        text = urllib.parse.unquote(text)
    except Exception:
        pass
    cleaned = _clean_html_tags(text)
    return cleaned if cleaned is not None else ""


def _clean_html_tags(text: str) -> Optional[str]:
    """
    Remove HTML tags from text content.
    Draw.io often stores text with HTML formatting.

    Args:
        text: Text potentially containing HTML tags

    Returns:
        Cleaned text without HTML tags
    """
    if text is None:
        return None
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


def _extract_absolute_geometry(
    cell: ET.Element, cells_by_id: Dict[str, ET.Element]
) -> Optional[Tuple[float, float, float, float]]:
    """
    Extract absolute geometry (x, y, width, height) from an mxCell by summing parent offsets.
    """
    geom = cell.find("mxGeometry")
    if geom is None:
        return None
    try:
        x = float(geom.get("x") or 0)
        y = float(geom.get("y") or 0)
        width = float(geom.get("width") or 0)
        height = float(geom.get("height") or 0)

        parent_id = cell.get("parent")
        while parent_id:
            parent_cell = cells_by_id.get(parent_id)
            if parent_cell is None:
                break
            parent_geom = parent_cell.find("mxGeometry")
            if parent_geom is not None:
                x += float(parent_geom.get("x") or 0)
                y += float(parent_geom.get("y") or 0)
            parent_id = parent_cell.get("parent")

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
