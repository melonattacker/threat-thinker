"""
Mermaid diagram parser
"""

import re
from typing import Tuple

from models import Graph, Node, Edge, ImportMetrics


# tolerate variations: A->B, A-->B, A--->B |label|
MERMAID_EDGE_RE = re.compile(
    r'^\s*([A-Za-z0-9_]+)\s*-\s*-*\s*>+\s*([A-Za-z0-9_]+)\s*(?:\|\s*([^|]+?)\s*\|)?'
)

NODE_LABEL_RE = re.compile(
    r'^\s*([A-Za-z0-9_]+)\s*[\[\(\{]{1,2}\s*([^]\)\}]+?)\s*[\]\)\}]{1,2}'
)


def parse_mermaid(path: str) -> Tuple[Graph, ImportMetrics]:
    """
    Parse a Mermaid diagram file and return a Graph object and import metrics.
    
    Args:
        path: Path to the Mermaid file
        
    Returns:
        Tuple of (Graph, ImportMetrics)
    """
    g = Graph()
    metrics = ImportMetrics()
    
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    metrics.total_lines = len(lines)

    # edges + create nodes
    for line in lines:
        # normalize common arrow typos
        norm = line.replace('—', '-').replace('→', '>')  # emdash/arrow variants
        m = MERMAID_EDGE_RE.search(norm)
        if m:
            metrics.edge_candidates += 1
            src, dst, label = m.group(1), m.group(2), m.group(3)
            g.edges.append(Edge(src=src, dst=dst, label=label.strip() if label else None))
            metrics.edges_parsed += 1
            if src not in g.nodes:
                g.nodes[src] = Node(id=src, label=src)
            if dst not in g.nodes:
                g.nodes[dst] = Node(id=dst, label=dst)

    # node labels like A[User], B((API))
    for line in lines:
        m = NODE_LABEL_RE.search(line)
        if m:
            metrics.node_label_candidates += 1
            nid, nlabel = m.group(1), m.group(2)
            n = g.nodes.get(nid)
            if n:
                n.label = nlabel.strip()
            else:
                g.nodes[nid] = Node(id=nid, label=nlabel.strip())
            metrics.node_labels_parsed += 1

    return g, metrics