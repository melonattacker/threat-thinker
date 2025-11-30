"""
Threat Dragon v2 JSON parser.
"""

import json
from pathlib import Path
from typing import Any, Dict, Tuple

from models import Edge, Graph, ImportMetrics, Node

# Mapping from Threat Dragon data.type to internal node.type values
NODE_TYPE_MAP = {
    "tm.Actor": "actor",
    "tm.Process": "process",
    "tm.Store": "store",
}


def is_threat_dragon_json(path: str) -> bool:
    """
    Quick detection helper to check whether a JSON file looks like
    a Threat Dragon v2 model.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False

    version = str(data.get("version", ""))
    if version and not version.startswith("2."):
        return False

    detail = data.get("detail") or {}
    diagrams = detail.get("diagrams") or []
    if not isinstance(diagrams, list) or not diagrams:
        return False

    first_diagram = diagrams[0]
    return isinstance(first_diagram, dict) and bool(first_diagram.get("cells"))


def parse_threat_dragon(path: str) -> Tuple[Graph, ImportMetrics]:
    """
    Parse a Threat Dragon v2 JSON file into the internal Graph structure.

    Args:
        path: Path to the Threat Dragon JSON file.

    Returns:
        Tuple of (Graph, ImportMetrics)
    """
    g = Graph()
    metrics = ImportMetrics()

    try:
        text = Path(path).read_text(encoding="utf-8")
        metrics.total_lines = len(text.splitlines())
        model = json.loads(text)
    except FileNotFoundError:
        print(f"Warning: Threat Dragon file not found: {path}")
        return g, metrics
    except json.JSONDecodeError as exc:
        print(f"Warning: Failed to parse Threat Dragon JSON {path}: {exc}")
        return g, metrics
    except Exception as exc:
        print(f"Warning: Error reading Threat Dragon file {path}: {exc}")
        return g, metrics

    version = str(model.get("version", ""))
    if version and not version.startswith("2."):
        print(
            f"Warning: Threat Dragon version {version} is not in the 2.x range; attempting to parse anyway."
        )

    detail = model.get("detail") or {}
    diagrams = detail.get("diagrams") or []
    if not diagrams:
        return g, metrics

    diagram = diagrams[0] or {}
    cells = diagram.get("cells") or []
    node_ids = set()

    # First pass: collect nodes
    for cell in cells:
        data_block: Dict[str, Any] = cell.get("data") or {}
        cell_type = data_block.get("type")
        cell_id = cell.get("id")

        if not cell_id or cell_type not in NODE_TYPE_MAP:
            continue

        label = _extract_label(cell, data_block)
        node = Node(id=cell_id, label=label, type=NODE_TYPE_MAP[cell_type])
        g.nodes[cell_id] = node
        node_ids.add(cell_id)

    metrics.node_label_candidates = len(g.nodes)
    metrics.node_labels_parsed = len(g.nodes)

    # Second pass: collect flows
    for cell in cells:
        data_block: Dict[str, Any] = cell.get("data") or {}
        if data_block.get("type") != "tm.Flow" or cell.get("shape") != "flow":
            continue

        metrics.edge_candidates += 1

        source = (cell.get("source") or {}).get("cell")
        target = (cell.get("target") or {}).get("cell")
        if not source or not target:
            continue
        if source not in node_ids or target not in node_ids:
            continue

        label = _extract_flow_label(cell, data_block)
        protocol = data_block.get("protocol") or None
        edge = Edge(src=source, dst=target, label=label, protocol=protocol)

        edge_flags = []
        if data_block.get("isEncrypted"):
            edge_flags.append("encrypted")
        if data_block.get("isPublicNetwork"):
            edge_flags.append("public-network")
        if data_block.get("isBidirectional"):
            edge_flags.append("bidirectional")
        if edge_flags:
            edge.data = edge_flags

        g.edges.append(edge)
        metrics.edges_parsed += 1

    return g, metrics


def _extract_label(cell: Dict[str, Any], data_block: Dict[str, Any]) -> str:
    """Pick the best available label for a node cell."""
    if data_block.get("name"):
        return str(data_block["name"]).strip()

    attrs = cell.get("attrs") or {}
    text_attr = (attrs.get("text") or {}).get("text")
    if text_attr:
        return str(text_attr).strip()

    label_attr = (attrs.get("label") or {}).get("text")
    if label_attr:
        return str(label_attr).strip()

    cell_id = cell.get("id") or ""
    return str(cell_id).strip()


def _extract_flow_label(cell: Dict[str, Any], data_block: Dict[str, Any]) -> str | None:
    """Pick the best available label for a flow edge."""
    if data_block.get("name"):
        return str(data_block["name"]).strip() or None

    labels = cell.get("labels") or []
    if labels:
        first = labels[0]
        if isinstance(first, str):
            text = first
        elif isinstance(first, dict):
            text = first.get("text", "")
        else:
            text = ""
        if text and str(text).strip():
            return str(text).strip()
    return None
