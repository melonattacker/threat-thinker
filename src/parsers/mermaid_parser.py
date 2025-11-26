"""
Mermaid diagram parser
"""

import re
from typing import Tuple

from models import Graph, Node, Edge, ImportMetrics


# tolerate variations:
#   - Plain: A -> B, A --> B, A ---> B
#   - Pipe label: A --> B |label|
#   - Inline label: A -- label --> B
#   - Source with inline node label: A[User] --> B
# IDs allow letters, numbers, underscore, dash, dot
# Optional inline node label after source is captured and ignored
SOURCE_WITH_LABEL = r"([A-Za-z0-9_.-]+)(?:\s*[\[\(\{]{1,2}[^\]\)\}]+?[\]\)\}]{1,2})?"
MERMAID_EDGE_INLINE_RE = re.compile(
    rf"^\s*{SOURCE_WITH_LABEL}\s*--+\s*([^->\n]+?)\s*-+>\s*([A-Za-z0-9_.-]+)"
)
MERMAID_EDGE_PIPE_RE = re.compile(
    rf"^\s*{SOURCE_WITH_LABEL}\s*-\s*-*\s*>+\s*([A-Za-z0-9_.-]+)\s*\|\s*([^|]+?)\s*\|"
)
MERMAID_EDGE_PLAIN_RE = re.compile(
    rf"^\s*{SOURCE_WITH_LABEL}\s*-\s*-*\s*>+\s*([A-Za-z0-9_.-]+)"
)

NODE_LABEL_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*[\[\(\{]{1,2}\s*([^]\)\}]+?)\s*[\]\)\}]{1,2}"
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
        norm = line.replace("—", "-").replace("→", ">")  # emdash/arrow variants
        match = None
        label = None
        m_inline = MERMAID_EDGE_INLINE_RE.search(norm)
        if m_inline:
            match = m_inline
            src, label, dst = m_inline.group(1), m_inline.group(2), m_inline.group(3)
        else:
            m_pipe = MERMAID_EDGE_PIPE_RE.search(norm)
            if m_pipe:
                match = m_pipe
                src, dst, label = m_pipe.group(1), m_pipe.group(2), m_pipe.group(3)
            else:
                m_plain = MERMAID_EDGE_PLAIN_RE.search(norm)
                if m_plain:
                    match = m_plain
                    src, dst = m_plain.group(1), m_plain.group(2)
        if match:
            metrics.edge_candidates += 1
            g.edges.append(
                Edge(src=src, dst=dst, label=label.strip() if label else None)
            )
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
