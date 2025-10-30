"""
Image diagram parser for system architecture diagrams
"""

import base64
import os
import json
from typing import Tuple, Dict, List
from pathlib import Path

from models import Graph, Node, Edge, ImportMetrics
from llm.client import LLMClient
from llm.response_utils import safe_json_loads


def parse_image(path: str, 
                api: str = None, 
                model: str = None,
                aws_profile: str = None,
                aws_region: str = None) -> Tuple[Graph, ImportMetrics]:
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
    g = Graph()
    metrics = ImportMetrics()
    
    try:
        # Check if file exists and is an image
        if not os.path.exists(path):
            raise FileNotFoundError(f"Image file not found: {path}")
        
        # Get file extension to validate image type
        ext = Path(path).suffix.lower()
        supported_formats = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
        if ext not in supported_formats:
            raise ValueError(f"Unsupported image format: {ext}. Supported formats: {', '.join(supported_formats)}")
        
        # Read and encode image to base64
        base64_image = _encode_image_to_base64(path)
        
        # Get file size for metrics
        file_size = os.path.getsize(path)
        metrics.total_lines = file_size  # Use file size as a metric since images don't have lines
        
        # Analyze image using LLM
        graph_data = _analyze_image_with_llm(base64_image, ext, api=api, model=model, 
                                            aws_profile=aws_profile, aws_region=aws_region)
        
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
        return base64.b64encode(image_file.read()).decode('utf-8')


def _analyze_image_with_llm(base64_image: str, file_ext: str,
                           api: str = None, model: str = None,
                           aws_profile: str = None, aws_region: str = None) -> Dict:
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
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg', 
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.bmp': 'image/bmp',
        '.webp': 'image/webp'
    }
    
    media_type = media_type_map.get(file_ext, 'image/jpeg')
    
    # System prompt for analyzing system architecture diagrams
    system_prompt = """You are an expert system architect. Analyze the provided system architecture diagram image and extract all components and their relationships.

Your task is to identify:
1. All system components (services, databases, users, external systems, etc.)
2. All connections/relationships between components
3. Any labels or descriptions on the connections
4. Security boundaries or zones if visible

Return ONLY a valid JSON object (no markdown formatting, no code blocks, no ```json markers) with this exact structure:
{
  "nodes": [
    {"id": "unique_id", "label": "Component Name", "type": "service|database|user|external|queue|cache|storage", "zone": "zone_name_if_applicable"}
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
- Return ONLY the JSON object, no other text or formatting"""

    user_prompt = """Please analyze this system architecture diagram and extract all components and their relationships. Return ONLY a valid JSON object with the specified format, no markdown code blocks or extra formatting."""
    
    try:
        # Get LLM client and analyze the image
        llm_client = LLMClient(api=api, model=model, aws_profile=aws_profile, aws_region=aws_region)
        
        # Call LLM with image analysis
        response = llm_client.analyze_image_for_graph(
            base64_image=base64_image,
            media_type=media_type,
            system_prompt=system_prompt,
            user_prompt=user_prompt
        )
        
        # Parse JSON response
        graph_data = safe_json_loads(response)
        return graph_data
        
    except Exception as e:
        print(f"Warning: Failed to analyze image with LLM: {e}")
        return {}


def _parse_llm_response_to_graph(graph_data: Dict, graph: Graph, metrics: ImportMetrics) -> None:
    """
    Parse LLM response data into Graph object and update metrics.
    
    Args:
        graph_data: Dictionary containing nodes and edges data from LLM
        graph: Graph object to populate
        metrics: ImportMetrics object to update
    """
    # Process nodes
    nodes_data = graph_data.get('nodes', [])
    metrics.node_label_candidates = len(nodes_data)
    
    for node_data in nodes_data:
        try:
            node_id = node_data.get('id', '')
            label = node_data.get('label', node_id)
            node_type = node_data.get('type')
            zone = node_data.get('zone')
            
            if node_id:
                node = Node(
                    id=node_id,
                    label=label,
                    type=node_type,
                    zone=zone
                )
                graph.nodes[node_id] = node
                metrics.node_labels_parsed += 1
        except Exception as e:
            print(f"Warning: Failed to parse node data {node_data}: {e}")
    
    # Process edges
    edges_data = graph_data.get('edges', [])
    metrics.edge_candidates = len(edges_data)
    
    for edge_data in edges_data:
        try:
            src = edge_data.get('src', '')
            dst = edge_data.get('dst', '')
            label = edge_data.get('label')
            protocol = edge_data.get('protocol')
            
            if src and dst:
                edge = Edge(
                    src=src,
                    dst=dst,
                    label=label,
                    protocol=protocol
                )
                graph.edges.append(edge)
                metrics.edges_parsed += 1
        except Exception as e:
            print(f"Warning: Failed to parse edge data {edge_data}: {e}")