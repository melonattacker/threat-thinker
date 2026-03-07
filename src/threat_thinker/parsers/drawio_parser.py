"""
Draw.io diagram parser
"""

import base64
import html
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from threat_thinker.models import Edge, Graph, ImportMetrics, Node
from threat_thinker.zone_utils import (
    compute_zone_tree_from_rectangles,
    containing_zone_ids_for_point,
    representative_zone_name,
)


def parse_drawio(path: str, page: Optional[str] = None) -> Tuple[Graph, ImportMetrics]:
    """
    Parse a Draw.io diagram file and return a Graph object and import metrics.

    Args:
        path: Path to the Draw.io file (.drawio, .xml)
        page: Optional page selector (page id, page name, or 0-based index)

    Returns:
        Tuple of (Graph, ImportMetrics)
    """
    g = Graph(source_format="drawio")
    metrics = ImportMetrics()

    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        metrics.total_lines = len(text.splitlines())

        root = ET.fromstring(text)
        pages = _extract_graph_models(root)
        if not pages:
            return g, metrics

        page_id, page_name, graph_model = _select_page(pages, page)
        if page is not None and page_id != page and page_name != page:
            if not _is_selected_by_index(page, pages, page_id):
                print(
                    f"Warning: Draw.io page '{page}' not found in {path}; falling back to first page."
                )

        cells = _find_descendants_by_local_name(graph_model, "mxCell")
        cells_by_id: Dict[str, ET.Element] = {
            cell.get("id"): cell for cell in cells if cell.get("id")
        }

        cell_id_map: Dict[str, str] = {}
        node_geometry: Dict[str, Tuple[float, float, float, float]] = {}
        zone_rects: List[Dict[str, float]] = []
        edge_labels: Dict[str, str] = {}

        edge_endpoint_ids: Set[str] = set()
        for cell in cells:
            cell_id = cell.get("id")
            if not cell_id:
                continue

            style = (cell.get("style") or "").lower()
            if _is_edge_label_cell(cell, style):
                parent_edge_id = cell.get("parent")
                label_value = _decode_and_clean(cell.get("value"))
                if parent_edge_id and label_value:
                    edge_labels[parent_edge_id] = label_value
                continue

            if cell.get("edge") == "1":
                metrics.edge_candidates += 1
                source_id = cell.get("source")
                target_id = cell.get("target")
                if source_id:
                    edge_endpoint_ids.add(source_id)
                if target_id:
                    edge_endpoint_ids.add(target_id)

        vertex_cells: List[Dict[str, object]] = []
        for cell in cells:
            cell_id = cell.get("id")
            if not cell_id or cell_id in {"0", "1"}:
                continue
            if cell.get("edge") == "1":
                continue

            style = (cell.get("style") or "").lower()
            if _is_edge_label_cell(cell, style):
                continue

            if cell.get("vertex") != "1":
                continue

            geometry = _extract_absolute_geometry(cell, cells_by_id)
            value = _decode_and_clean(cell.get("value"))
            vertex_cells.append(
                {
                    "id": cell_id,
                    "label": value,
                    "style": style,
                    "geometry": geometry,
                    "cell": cell,
                    "is_edge_endpoint": cell_id in edge_endpoint_ids,
                }
            )

        zone_ids: Set[str] = set()
        for item in vertex_cells:
            cell = item["cell"]
            label = str(item["label"] or "")
            geometry = item["geometry"]
            if _is_zone_cell(cell, label, geometry, vertex_cells):
                cell_id = str(item["id"])
                zone_ids.add(cell_id)
                zone_rects.append(
                    {
                        "id": cell_id,
                        "name": label or cell_id,
                        "x": geometry[0] if geometry else 0.0,
                        "y": geometry[1] if geometry else 0.0,
                        "width": geometry[2] if geometry else 0.0,
                        "height": geometry[3] if geometry else 0.0,
                    }
                )

        for item in vertex_cells:
            node_id = str(item["id"])
            if node_id in zone_ids:
                continue

            label = str(item["label"] or "")
            if not label and not bool(item["is_edge_endpoint"]):
                continue
            if not label:
                label = node_id

            node = Node(id=node_id, label=label)
            g.nodes[node_id] = node
            cell_id_map[node_id] = node_id
            geometry = item["geometry"]
            if geometry is not None:
                node_geometry[node_id] = geometry

        for cell in cells:
            if cell.get("edge") != "1":
                continue

            source_id = cell.get("source")
            target_id = cell.get("target")
            if not source_id or not target_id:
                continue

            src_node_id = cell_id_map.get(source_id)
            dst_node_id = cell_id_map.get(target_id)
            if not src_node_id or not dst_node_id:
                continue

            edge_id = cell.get("id")
            label = _decode_and_clean(cell.get("value"))
            if not label and edge_id:
                label = edge_labels.get(edge_id) or None

            g.edges.append(
                Edge(src=src_node_id, dst=dst_node_id, label=label, id=edge_id)
            )
            metrics.edges_parsed += 1

        metrics.node_label_candidates = len(g.nodes)
        metrics.node_labels_parsed = len(g.nodes)

        if zone_rects:
            g.zones = compute_zone_tree_from_rectangles(zone_rects)
            for node_id, geom in node_geometry.items():
                cx = geom[0] + geom[2] / 2
                cy = geom[1] + geom[3] / 2
                zone_ids_for_node = containing_zone_ids_for_point(
                    cx, cy, zone_rects, g.zones
                )
                g.nodes[node_id].zones = zone_ids_for_node
                g.nodes[node_id].zone = representative_zone_name(
                    zone_ids_for_node, g.zones
                )

    except ET.ParseError as e:
        print(f"Warning: Failed to parse XML file {path}: {e}")
    except Exception as e:
        print(f"Warning: Error processing file {path}: {e}")

    return g, metrics


def _extract_graph_models(
    root: ET.Element,
) -> List[Tuple[Optional[str], Optional[str], ET.Element]]:
    """Return available pages as (id, name, mxGraphModel)."""
    if _local_name(root.tag) == "mxGraphModel":
        return [(None, None, root)]

    pages: List[Tuple[Optional[str], Optional[str], ET.Element]] = []

    if _local_name(root.tag) == "mxfile":
        diagrams = [
            elem for elem in list(root) if isinstance(elem.tag, str) and _local_name(elem.tag) == "diagram"
        ]
        for diagram in diagrams:
            model = _graph_model_from_diagram(diagram)
            if model is None:
                continue
            pages.append((diagram.get("id"), diagram.get("name"), model))
        return pages

    graph_model = _first_descendant_by_local_name(root, "mxGraphModel")
    if graph_model is not None:
        return [(None, None, graph_model)]

    return pages


def _select_page(
    pages: Sequence[Tuple[Optional[str], Optional[str], ET.Element]],
    page: Optional[str],
) -> Tuple[Optional[str], Optional[str], ET.Element]:
    """Pick target page by id, name, or 0-based numeric index."""
    if not pages:
        raise ValueError("No pages found")

    if page is None:
        return pages[0]

    needle = page.strip()
    if not needle:
        return pages[0]

    for page_id, page_name, model in pages:
        if page_id == needle:
            return page_id, page_name, model

    for page_id, page_name, model in pages:
        if page_name == needle:
            return page_id, page_name, model

    if needle.isdigit():
        index = int(needle)
        if 0 <= index < len(pages):
            return pages[index]

    return pages[0]


def _is_selected_by_index(
    page: Optional[str],
    pages: Sequence[Tuple[Optional[str], Optional[str], ET.Element]],
    selected_page_id: Optional[str],
) -> bool:
    if page is None:
        return False
    needle = page.strip()
    if not needle.isdigit():
        return False
    index = int(needle)
    if index < 0 or index >= len(pages):
        return False
    return pages[index][0] == selected_page_id


def _graph_model_from_diagram(diagram: ET.Element) -> Optional[ET.Element]:
    """Decode a <diagram> page and return its mxGraphModel."""
    existing = _first_descendant_by_local_name(diagram, "mxGraphModel")
    if existing is not None:
        return existing

    raw = "".join(diagram.itertext() or []).strip()
    if not raw:
        return None

    decoded = _decode_diagram_text(raw)
    if not decoded:
        return None

    try:
        decoded_root = ET.fromstring(decoded)
    except ET.ParseError:
        return None

    if _local_name(decoded_root.tag) == "mxGraphModel":
        return decoded_root
    return _first_descendant_by_local_name(decoded_root, "mxGraphModel")


def _decode_diagram_text(raw: str) -> Optional[str]:
    """
    Decode draw.io diagram payload.

    Order:
    1) raw XML
    2) URL-encoded XML
    3) base64 -> raw inflate (wbits=-15) -> URL decode
    """
    text = (raw or "").strip()
    if not text:
        return None

    if text.lstrip().startswith("<"):
        return text

    url_decoded = urllib.parse.unquote(text)
    if url_decoded.lstrip().startswith("<"):
        return url_decoded

    try:
        raw_bytes = base64.b64decode(_pad_base64(text), validate=False)
    except Exception:
        return None

    try:
        xml_data = raw_bytes.decode("utf-8")
        if xml_data.lstrip().startswith("<"):
            return xml_data
    except UnicodeDecodeError:
        pass

    try:
        inflated = zlib.decompress(raw_bytes, -15).decode("utf-8")
    except Exception:
        return None

    inflated_decoded = urllib.parse.unquote(inflated)
    if inflated_decoded.lstrip().startswith("<"):
        return inflated_decoded
    return None


def _pad_base64(value: str) -> str:
    remainder = len(value) % 4
    if remainder == 0:
        return value
    return value + ("=" * (4 - remainder))


def _local_name(tag: str) -> str:
    if not isinstance(tag, str):
        return ""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    if ":" in tag:
        return tag.split(":", 1)[1]
    return tag


def _find_descendants_by_local_name(element: ET.Element, name: str) -> List[ET.Element]:
    return [
        node
        for node in element.iter()
        if isinstance(node.tag, str) and _local_name(node.tag) == name
    ]


def _first_descendant_by_local_name(
    element: ET.Element, name: str
) -> Optional[ET.Element]:
    for node in element.iter():
        if isinstance(node.tag, str) and _local_name(node.tag) == name:
            return node
    return None


def _decode_and_clean(value: Optional[str]) -> str:
    """URL-decode a value and strip HTML markup."""
    if value is None:
        return ""
    text = value
    try:
        text = urllib.parse.unquote(text)
    except Exception:
        pass
    cleaned = _clean_html_tags(text)
    return cleaned if cleaned is not None else ""


def _clean_html_tags(text: Optional[str]) -> Optional[str]:
    """
    Remove HTML tags from text content.
    Draw.io often stores text with HTML formatting.
    """
    if text is None:
        return None
    if not text:
        return text

    cleaned = html.unescape(text)
    cleaned = re.sub(r"(?i)<br\s*/?>", " ", cleaned)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _extract_absolute_geometry(
    cell: ET.Element, cells_by_id: Dict[str, ET.Element]
) -> Optional[Tuple[float, float, float, float]]:
    """
    Extract absolute geometry (x, y, width, height) from an mxCell by summing parent offsets.
    """
    geom = _first_descendant_by_local_name(cell, "mxGeometry")
    if geom is None:
        return None

    try:
        x = float(geom.get("x") or 0)
        y = float(geom.get("y") or 0)
        width = float(geom.get("width") or 0)
        height = float(geom.get("height") or 0)

        parent_id = cell.get("parent")
        seen: Set[str] = set()
        while parent_id and parent_id not in seen:
            seen.add(parent_id)
            parent_cell = cells_by_id.get(parent_id)
            if parent_cell is None:
                break

            parent_geom = _first_descendant_by_local_name(parent_cell, "mxGeometry")
            if parent_geom is not None:
                x += float(parent_geom.get("x") or 0)
                y += float(parent_geom.get("y") or 0)

            parent_id = parent_cell.get("parent")

        return x, y, width, height
    except Exception:
        return None


def _is_edge_label_cell(cell: ET.Element, style: str) -> bool:
    return "edgelabel" in style or (
        cell.get("vertex") == "1"
        and cell.get("connectable") == "0"
        and bool(cell.get("parent"))
        and "label" in style
    )


def _rect_contains(outer: Tuple[float, float, float, float], inner: Tuple[float, float, float, float]) -> bool:
    ox, oy, ow, oh = outer
    ix, iy, iw, ih = inner
    return ox <= ix and oy <= iy and ox + ow >= ix + iw and oy + oh >= iy + ih


def _contains_other_vertices(
    geometry: Tuple[float, float, float, float],
    cell_id: str,
    vertex_cells: Iterable[Dict[str, object]],
) -> bool:
    if geometry[2] <= 0 or geometry[3] <= 0:
        return False

    for item in vertex_cells:
        other_id = str(item["id"])
        if other_id == cell_id:
            continue
        other_geometry = item.get("geometry")
        if other_geometry is None:
            continue
        og = other_geometry
        if og[2] <= 0 or og[3] <= 0:
            continue
        if _rect_contains(geometry, og):
            return True
    return False


def _is_zone_cell(
    cell: ET.Element,
    label: str,
    geometry: Optional[Tuple[float, float, float, float]],
    vertex_cells: Sequence[Dict[str, object]],
) -> bool:
    """
    Heuristic to detect trust boundaries in draw.io.
    """
    if cell.get("vertex") != "1":
        return False
    if geometry is None:
        return False
    if geometry[2] <= 0 or geometry[3] <= 0:
        return False
    if not label:
        return False

    style = (cell.get("style") or "").lower()
    is_container_like = (
        "rectangle" in style
        or "shape=rect" in style
        or "rounded=1" in style
        or "swimlane" in style
        or "group" in style
    )

    has_boundary_hint = (
        "dashed=1" in style
        or "dashpattern" in style
        or "boundary" in style
        or "zone" in style
        or "trust" in style
        or "swimlane" in style
        or "group" in style
        or "container=1" in style
    )

    contains_others = _contains_other_vertices(geometry, str(cell.get("id") or ""), vertex_cells)
    return is_container_like and (has_boundary_hint or contains_others)
