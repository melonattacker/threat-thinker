"""
Data models for Threat Thinker
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Node:
    id: str
    label: str
    zone: Optional[str] = None
    type: Optional[str] = None  # actor/service/database/queue/etc.
    data: List[str] = field(default_factory=list)  # PII/Secrets/etc.
    auth: Optional[bool] = None
    notes: Optional[str] = None


@dataclass
class Edge:
    src: str
    dst: str
    label: Optional[str] = None
    protocol: Optional[str] = None  # HTTP/HTTPS/gRPC/etc.
    data: List[str] = field(default_factory=list)


@dataclass
class Graph:
    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)


@dataclass
class ImportMetrics:
    total_lines: int = 0
    edge_candidates: int = 0
    edges_parsed: int = 0
    node_label_candidates: int = 0
    node_labels_parsed: int = 0

    @property
    def import_success_rate(self) -> float:
        denom = max(1, self.edge_candidates + self.node_label_candidates)
        return round((self.edges_parsed + self.node_labels_parsed) / denom, 3)


@dataclass
class Threat:
    id: str
    title: str
    stride: List[str]
    severity: str  # High/Medium/Low
    score: float  # integer 1..9 expected
    affected: List[str]
    why: str
    references: List[str]  # e.g., ["ASVS V5 ...", "CWE-319 ..."]
    recommended_action: str  # developer-friendly actionable guidance
    evidence_nodes: List[str] = field(default_factory=list)  # node IDs
    evidence_edges: List[str] = field(default_factory=list)  # edge IDs (src->dst)
    confidence: Optional[float] = None
