"""
Image diagram parser for system architecture diagrams
"""

import base64
import os
from typing import Dict, Tuple
from pathlib import Path

from models import Edge, Graph, ImportMetrics, Node
from llm.client import LLMClient
from llm.response_utils import safe_json_loads
from zone_utils import (
    compute_zone_tree_from_rectangles,
    containing_zone_ids_for_point,
    representative_zone_name,
    sort_zone_ids_by_hierarchy,
)

# Headroom for dense diagrams so we can return many nodes/edges with metadata.
IMAGE_GRAPH_EXTRACTION_MAX_TOKENS = 2800


def parse_image(
    path: str,
    api: str = None,
    model: str = None,
    aws_profile: str = None,
    aws_region: str = None,
    ollama_host: str = None,
) -> Tuple[Graph, ImportMetrics]:
    """
    Parse an image file containing a system architecture diagram and return a Graph object and import metrics.

    Args:
        path: Path to the image file (jpg, jpeg, png, gif, bmp, webp)
        api: LLM API provider (openai, anthropic, bedrock)
        model: LLM model name
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)

    Returns:
        Tuple of (Graph, ImportMetrics)
    """
    g = Graph(source_format="image")
    metrics = ImportMetrics()

    try:
        if api and api.lower() == "ollama":
            raise NotImplementedError(
                "Image parsing is not supported with the Ollama backend."
            )
        # Check if file exists and is an image
        if not os.path.exists(path):
            raise FileNotFoundError(f"Image file not found: {path}")

        # Get file extension to validate image type
        ext = Path(path).suffix.lower()
        supported_formats = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}
        if ext not in supported_formats:
            raise ValueError(
                f"Unsupported image format: {ext}. Supported formats: {', '.join(supported_formats)}"
            )

        # Read and encode image to base64
        base64_image = _encode_image_to_base64(path)

        # Get file size for metrics
        file_size = os.path.getsize(path)
        metrics.total_lines = (
            file_size  # Use file size as a metric since images don't have lines
        )

        # Analyze image using LLM
        graph_data = _analyze_image_with_llm(
            base64_image,
            ext,
            api=api,
            model=model,
            aws_profile=aws_profile,
            aws_region=aws_region,
            ollama_host=ollama_host,
        )

        # Parse LLM response into Graph structure
        if graph_data:
            _parse_llm_response_to_graph(graph_data, g, metrics)

    except Exception as e:
        print(f"Warning: Error processing image file {path}: {e}")

    return g, metrics


def _encode_image_to_base64(image_path: str) -> str:
    """
    Encode an image file to base64 string.

    Args:
        image_path: Path to the image file

    Returns:
        Base64 encoded string of the image
    """
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode("utf-8")


def _analyze_image_with_llm(
    base64_image: str,
    file_ext: str,
    api: str = None,
    model: str = None,
    aws_profile: str = None,
    aws_region: str = None,
    ollama_host: str = None,
) -> Dict:
    """
    Analyze image using LLM to extract system architecture information.

    Args:
        base64_image: Base64 encoded image string
        file_ext: File extension (used to determine media type)
        api: LLM API provider (openai, anthropic, bedrock)
        model: LLM model name
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)

    Returns:
        Dictionary containing extracted graph information
    """
    # Map file extensions to media types
    media_type_map = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".webp": "image/webp",
    }

    media_type = media_type_map.get(file_ext, "image/jpeg")

    # System prompt for analyzing system architecture diagrams
    system_prompt = """You are an expert system architect. Analyze the provided system architecture diagram image and extract all components and their relationships.

Your task is to identify:
1. All system components (services, databases, users, external systems, etc.)
2. All connections/relationships between components
3. Any labels or descriptions on the connections
4. Security boundaries or zones if visible (including nested trust boundaries)

Return ONLY a valid JSON object (no markdown formatting, no code blocks, no ```json markers) with this exact structure:
{
  "zones": [
    {"id": "zone_id", "name": "Zone Name", "bounds": {"x": 0, "y": 0, "width": 100, "height": 80}}
  ],
  "nodes": [
    {
      "id": "unique_id",
      "label": "Component Name",
      "type": "service|database|user|external|queue|cache|storage",
      "zones": ["outer_zone_id", "inner_zone_id"],
      "bounds": {"x": 10, "y": 12, "width": 32, "height": 20}
    }
  ],
  "edges": [
    {"src": "source_node_id", "dst": "destination_node_id", "label": "connection_description", "protocol": "HTTP|HTTPS|TCP|gRPC|etc"}
  ]
}

Guidelines:
- Use descriptive but concise labels
- Create unique IDs for each component (use lowercase with underscores)
- Identify the type of each component if possible
- Include protocol information if visible in the diagram
- If arrows show direction, respect that in src/dst
- If no clear direction, order alphabetically by component name
- If zones are present, include nested rectangles with bounds; when unsure about bounds, still provide the best-effort placement.
- Return ONLY the JSON object, no other text or formatting"""

    user_prompt = """Please analyze this system architecture diagram and extract all components, zones (trust boundaries), and their relationships. Return ONLY a valid JSON object with the specified format, no markdown code blocks or extra formatting."""

    try:
        # Get LLM client and analyze the image
        llm_client = LLMClient(
            api=api,
            model=model,
            aws_profile=aws_profile,
            aws_region=aws_region,
            ollama_host=ollama_host,
        )

        # Call LLM with image analysis
        response = llm_client.analyze_image_for_graph(
            base64_image=base64_image,
            media_type=media_type,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=IMAGE_GRAPH_EXTRACTION_MAX_TOKENS,
        )

        # Parse JSON response
        graph_data = safe_json_loads(response)
        return graph_data

    except Exception as e:
        print(f"Warning: Failed to analyze image with LLM: {e}")
        return {}


def _parse_llm_response_to_graph(
    graph_data: Dict, graph: Graph, metrics: ImportMetrics
) -> None:
    """
    Parse LLM response data into Graph object and update metrics.

    Args:
        graph_data: Dictionary containing nodes and edges data from LLM
        graph: Graph object to populate
        metrics: ImportMetrics object to update
    """
    # Zones (trust boundaries)
    rect_zones = []
    for zone in graph_data.get("zones", []) or []:
        bounds = zone.get("bounds") or {}
        rect_zones.append(
            {
                "id": str(zone.get("id") or zone.get("name")),
                "name": zone.get("name") or zone.get("id") or "",
                "x": float(bounds.get("x") or 0),
                "y": float(bounds.get("y") or 0),
                "width": float(bounds.get("width") or 0),
                "height": float(bounds.get("height") or 0),
            }
        )
    if rect_zones:
        graph.zones = compute_zone_tree_from_rectangles(rect_zones)

    # Process nodes
    nodes_data = graph_data.get("nodes", [])
    metrics.node_label_candidates = len(nodes_data)

    for node_data in nodes_data:
        try:
            node_id = node_data.get("id", "")
            label = node_data.get("label", node_id)
            node_type = node_data.get("type")
            zones_hint = node_data.get("zones") or []
            zone_name = node_data.get("zone")
            bounds = node_data.get("bounds") or {}

            zone_ids = [str(z) for z in zones_hint if z]
            if bounds and graph.zones:
                cx = float(bounds.get("x") or 0) + float(bounds.get("width") or 0) / 2
                cy = float(bounds.get("y") or 0) + float(bounds.get("height") or 0) / 2
                inferred = containing_zone_ids_for_point(
                    cx, cy, rect_zones, graph.zones
                )
                zone_ids.extend(inferred)
            if zone_name and zone_name not in zone_ids:
                zone_ids.append(str(zone_name))
            if graph.zones:
                zone_ids = sort_zone_ids_by_hierarchy(zone_ids, graph.zones)
            else:
                deduped = []
                seen = set()
                for zid in zone_ids:
                    if zid in seen:
                        continue
                    seen.add(zid)
                    deduped.append(zid)
                zone_ids = deduped

            if node_id:
                node = Node(id=node_id, label=label, type=node_type)
                node.zones = zone_ids
                if graph.zones:
                    node.zone = representative_zone_name(zone_ids, graph.zones)
                else:
                    node.zone = zone_ids[-1] if zone_ids else zone_name
                graph.nodes[node_id] = node
                metrics.node_labels_parsed += 1
        except Exception as e:
            print(f"Warning: Failed to parse node data {node_data}: {e}")

    # Process edges
    edges_data = graph_data.get("edges", [])
    metrics.edge_candidates = len(edges_data)

    for edge_data in edges_data:
        try:
            src = edge_data.get("src", "")
            dst = edge_data.get("dst", "")
            label = edge_data.get("label")
            protocol = edge_data.get("protocol")

            if src and dst:
                edge = Edge(src=src, dst=dst, label=label, protocol=protocol)
                graph.edges.append(edge)
                metrics.edges_parsed += 1
        except Exception as e:
            print(f"Warning: Failed to parse edge data {edge_data}: {e}")
