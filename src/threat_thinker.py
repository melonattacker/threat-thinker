#!/usr/bin/env python3
"""
Threat Thinker - CLI (LLM required)
"Throw in an architecture diagram, get a prioritized threat list."

Inputs:
- Mermaid file (.mmd/.mermaid)
- Optional YAML hints for node/edge attributes

Outputs:
- Markdown table or JSON with threats (LLM-driven), each with 1-line "why" and ASVS refs.
- Optional diff vs baseline JSON.

Examples:
  export OPENAI_API_KEY=***
  # 属性推定あり（hintなしでもOK）
  python threat_thinker.py think --mermaid examples.mmd --infer-hints --llm --openai-model gpt-4o-mini --format md --out report.md
  # 既存のヒントで上書きも可能（推定→ヒントの順でマージ）
  python threat_thinker.py think --mermaid examples.mmd --infer-hints --hints hints.yaml --llm --openai-model gpt-4o-mini --format json --out report.json
  # 差分
  python threat_thinker.py diff --current report.json --baseline old.json
"""

import argparse
import json
import os
import re
import sys
import yaml
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# ---------------- Data model ----------------

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
class Threat:
    id: str
    title: str
    stride: List[str]
    severity: str         # High/Medium/Low
    score: float          # integer 1..9 expected
    affected: List[str]
    why: str
    references: List[str] # e.g., ["ASVS V5 ...", "ASVS V13 ..."]

# ---------------- Parsers ----------------

MERMAID_EDGE_RE = re.compile(
    r'^\s*([A-Za-z0-9_]+)\s*-{1,2}>\s*([A-Za-z0-9_]+)\s*(?:\|\s*([^|]+?)\s*\|)?'
)  # A-->B |label|

def parse_mermaid(path: str) -> Graph:
    g = Graph()
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    # edges + create nodes
    for line in lines:
        m = MERMAID_EDGE_RE.search(line)
        if m:
            src, dst, label = m.group(1), m.group(2), m.group(3)
            g.edges.append(Edge(src=src, dst=dst, label=label.strip() if label else None))
            if src not in g.nodes:
                g.nodes[src] = Node(id=src, label=src)
            if dst not in g.nodes:
                g.nodes[dst] = Node(id=dst, label=dst)
    # node labels like A[User], B((API))
    NODE_LABEL_RE = re.compile(r'^\s*([A-Za-z0-9_]+)\s*[\[\(\{]{1,2}\s*([^]\)\}]+?)\s*[\]\)\}]{1,2}')
    for line in lines:
        m = NODE_LABEL_RE.search(line)
        if m:
            nid, nlabel = m.group(1), m.group(2)
            n = g.nodes.get(nid)
            if n:
                n.label = nlabel.strip()
            else:
                g.nodes[nid] = Node(id=nid, label=nlabel.strip())
    return g

def apply_hints(g: Graph, hints_path: Optional[str]) -> Graph:
    if not hints_path:
        return g
    with open(hints_path, "r", encoding="utf-8") as f:
        hints = yaml.safe_load(f) or {}
    # nodes
    for nid, attrs in (hints.get("nodes") or {}).items():
        if nid not in g.nodes:
            g.nodes[nid] = Node(id=nid, label=attrs.get("label", nid))
        node = g.nodes[nid]
        node.zone = attrs.get("zone", node.zone)
        node.type = attrs.get("type", node.type)
        node.auth = attrs.get("auth", node.auth)
        node.notes = attrs.get("notes", node.notes)
        if isinstance(attrs.get("data"), list):
            node.data = list({*node.data, *attrs["data"]})
        if "label" in attrs:
            node.label = attrs["label"]
    # edges
    for e in (hints.get("edges") or []):
        src, dst = e.get("from"), e.get("to")
        if not src or not dst:
            continue
        found = False
        for edge in g.edges:
            if edge.src == src and edge.dst == dst:
                found = True
                edge.protocol = e.get("protocol", edge.protocol)
                if isinstance(e.get("data"), list):
                    edge.data = list({*edge.data, *e["data"]})
                if e.get("label"):
                    edge.label = e["label"]
        if not found:
            new_edge = Edge(src=src, dst=dst, label=e.get("label"))
            new_edge.protocol = e.get("protocol")
            if isinstance(e.get("data"), list):
                new_edge.data = e["data"]
            g.edges.append(new_edge)
            if src not in g.nodes:
                g.nodes[src] = Node(id=src, label=src)
            if dst not in g.nodes:
                g.nodes[dst] = Node(id=dst, label=dst)
    return g

# ---------------- LLM-based attribute inference (optional) ----------------

HINT_SYSTEM = (
    "You are Threat Thinker. Infer practical attributes for threat modeling from a graph skeleton. "
    "Labels/IDs may be in any language. Be conservative and avoid inventing nodes or edges."
)

HINT_INSTRUCTIONS = (
    "Return a JSON object with EXACT shape:\n"
    "{\n"
    '  \"nodes\": {\n'
    '    \"<nodeId>\": {\n'
    '      \"label\": \"string\",\n'
    '      \"type\": \"actor|service|pod|database|s3|elb|ingress|queue|cache|lambda|unknown\",\n'
    '      \"zone\": \"Internet|DMZ|Private|K8s-Namespace|VPC-Public|VPC-Private|AWS-Managed|unknown\",\n'
    '      \"data\": [\"PII\",\"Credentials\",\"Internal\",\"Secrets\"],\n'
    '      \"auth\": true|false|null,\n'
    '      \"notes\": \"string optional\"\n'
    "    }, ...\n"
    "  },\n"
    '  \"edges\": [\n'
    '    {\"from\":\"<nodeId>\",\"to\":\"<nodeId>\",\"protocol\":\"HTTP|HTTPS|TCP|gRPC|AMQP|unknown\",\"data\":[\"PII\",\"Credentials\",\"Internal\",\"Secrets\"]}\n'
    "  ],\n"
    '  \"policies\": {}\n'
    "}\n"
    "Rules:\n"
    "- Use null/unknown if unsure. Do not add or remove graph elements.\n"
    "- Keep arrays short and high-signal.\n"
)

def llm_infer_hints(graph_skeleton_json: str, model: str) -> dict:
    from openai import OpenAI
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")
    client = OpenAI()
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role":"system", "content": HINT_SYSTEM},
            {"role":"user", "content": (
                "Graph skeleton (nodes with id/label; edges with from/to/label):\n"
                f"{graph_skeleton_json}\n\n"
                "Infer attributes strictly following the output schema.\n"
                f"{HINT_INSTRUCTIONS}"
            )},
        ],
        response_format={"type":"json_object"},
        temperature=0.2,
        max_tokens=1400,
    )
    return json.loads(resp.choices[0].message.content)

def merge_llm_hints(g: Graph, hints: dict) -> Graph:
    # nodes
    for nid, attrs in (hints.get("nodes") or {}).items():
        if nid not in g.nodes:
            g.nodes[nid] = Node(id=nid, label=attrs.get("label", nid))
        n = g.nodes[nid]
        n.label = attrs.get("label", n.label)
        n.type = attrs.get("type", n.type)
        n.zone = attrs.get("zone", n.zone)
        if isinstance(attrs.get("data"), list):
            n.data = list({*n.data, *[str(x) for x in attrs["data"]]})
        if "auth" in attrs:
            n.auth = attrs["auth"]
        if "notes" in attrs:
            n.notes = attrs["notes"]
    # edges
    for e in (hints.get("edges") or []):
        src, dst = e.get("from"), e.get("to")
        if not src or not dst:
            continue
        # match existing
        matched = None
        for edge in g.edges:
            if edge.src == src and edge.dst == dst:
                matched = edge
                break
        if matched:
            if e.get("protocol"):
                matched.protocol = e["protocol"]
            if isinstance(e.get("data"), list):
                matched.data = list({*matched.data, *[str(x) for x in e["data"]]})
        else:
            # normally not expected, but keep safe
            ne = Edge(src=src, dst=dst, protocol=e.get("protocol"))
            if isinstance(e.get("data"), list):
                ne.data = [str(x) for x in e["data"]]
            g.edges.append(ne)
    return g

# ---------------- LLM-driven threat inference (required) ----------------

LLM_SYSTEM = (
    "You are Threat Thinker, an expert security analyst. "
    "Given a system graph (nodes/edges with attributes), output a concise, prioritized threat list. "
    "Use STRIDE. Provide a 1-line 'why' per threat (developer-friendly), and include OWASP ASVS references."
)

LLM_INSTRUCTIONS = (
    "Return a JSON object with this exact shape:\n"
    "{\n"
    '  "threats": [\n'
    "    {\n"
    '      "id": "short-stable-id",\n'
    '      "title": "string",\n'
    '      "stride": ["Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"],\n'
    '      "severity": "High|Medium|Low",\n'
    '      "score": 1,\n'
    '      "affected": ["Component A","Component B"],\n'
    '      "why": "one-line developer-friendly reason",\n'
    '      "references": ["ASVS V5 ...","ASVS V13 ..."]\n'
    "    }\n"
    "  ]\n"
    "}\n"
    "Rules:\n"
    "- Severity should be consistent with score (1..9 ~= impact*likelihood). Use integers for score.\n"
    "- Create stable, readable ids (e.g., TLS-app-db-01). Avoid randomness.\n"
    "- Prefer 5–15 high-signal threats; de-duplicate similar findings.\n"
    "- If information is missing, make conservative assumptions and mention them in 'why'.\n"
)

def graph_to_prompt(g: Graph) -> str:
    nodes = [asdict(n) for n in g.nodes.values()]
    edges = [asdict(e) for e in g.edges]
    return json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False, indent=2)

def llm_infer_threats(g: Graph, model: str) -> List[Threat]:
    from openai import OpenAI
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")
    client = OpenAI()
    payload = graph_to_prompt(g)
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role":"system", "content": LLM_SYSTEM},
            {"role":"user", "content": (
                "System graph (JSON):\n"
                f"{payload}\n\n"
                f"{LLM_INSTRUCTIONS}"
            )},
        ],
        response_format={"type":"json_object"},
        temperature=0.2,
        max_tokens=1200,
    )
    content = resp.choices[0].message.content
    data = json.loads(content)

    threats_out: List[Threat] = []
    for t in data.get("threats", []):
        tid = str(t.get("id") or "").strip()
        if not tid:
            import hashlib
            tid = hashlib.sha1(str(t.get("title","")).encode("utf-8")).hexdigest()[:8]
        severity = str(t.get("severity","Medium"))
        score = float(t.get("score", 4))
        threats_out.append(Threat(
            id=tid[:64],
            title=str(t.get("title") or "Untitled"),
            stride=[str(s) for s in (t.get("stride") or [])],
            severity=severity,
            score=score,
            affected=[str(a) for a in (t.get("affected") or [])],
            why=str(t.get("why") or ""),
            references=[str(r) for r in (t.get("references") or [])],
        ))
    if not threats_out:
        raise RuntimeError("LLM returned no threats")
    uniq = {t.id: t for t in threats_out}
    return list(uniq.values())

# ---------------- Export ----------------

def export_json(threats: List[Threat], out_path: Optional[str]) -> str:
    data = []
    for t in sorted(threats, key=lambda x: (-x.score, x.title)):
        data.append({
            "id": t.id,
            "title": t.title,
            "stride": t.stride,
            "severity": t.severity,
            "score": t.score,
            "affected": t.affected,
            "why": t.why,
            "references": t.references
        })
    s = json.dumps({
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "count": len(data),
        "threats": data
    }, ensure_ascii=False, indent=2)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(s)
    return s

def export_md(threats: List[Threat], out_path: Optional[str]) -> str:
    lines = []
    lines.append("# Threat Thinker Report")
    lines.append("")
    lines.append(f"Generated: {__import__('datetime').datetime.utcnow().isoformat()}Z")
    lines.append("")
    lines.append("| Severity | Title | Why | Affected | STRIDE | References |")
    lines.append("|---|---|---|---|---|---|")
    for t in sorted(threats, key=lambda x: (-x.score, x.title)):
        lines.append("| {sev} | {title} | {why} | {aff} | {stride} | {refs} |".format(
            sev=t.severity,
            title=t.title.replace("|","/"),
            why=t.why.replace("|","/"),
            aff=", ".join(t.affected).replace("|","/"),
            stride=", ".join(t.stride),
            refs=", ".join(t.references).replace("|","/"),
        ))
    s = "\n".join(lines)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(s)
    return s

# ---------------- Diff ----------------

def diff_reports(current_path: str, baseline_path: str) -> Dict:
    with open(current_path, "r", encoding="utf-8") as f:
        cur = json.load(f)
    with open(baseline_path, "r", encoding="utf-8") as f:
        base = json.load(f)
    cur_ids = {t["id"] for t in cur.get("threats", [])}
    base_ids = {t["id"] for t in base.get("threats", [])}
    added = cur_ids - base_ids
    removed = base_ids - cur_ids
    return {
        "added": [t for t in cur.get("threats", []) if t["id"] in added],
        "removed": [t for t in base.get("threats", []) if t["id"] in removed],
        "count_added": len(added),
        "count_removed": len(removed)
    }

# ---------------- CLI ----------------

def main():
    p = argparse.ArgumentParser(prog="threat_thinker", description="Threat Thinker CLI (LLM required)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_think = sub.add_parser("think", help="Parse diagram + hints, generate threats (LLM required)")
    p_think.add_argument("--mermaid", type=str, required=True, help="Path to Mermaid (.mmd/.mermaid)")
    p_think.add_argument("--hints", type=str, help="Optional YAML hints file")
    p_think.add_argument("--infer-hints", action="store_true",
                         help="Infer node/edge attributes from Mermaid via LLM (multilingual)")
    p_think.add_argument("--format", choices=["json", "md"], default="md")
    p_think.add_argument("--out", type=str, help="Write output to file")
    p_think.add_argument("--llm", action="store_true", help="Must be provided to enable LLM threat inference")
    p_think.add_argument("--openai-model", type=str, default="gpt-4o-mini", help="OpenAI model name")

    p_diff = sub.add_parser("diff", help="Diff two JSON reports")
    p_diff.add_argument("--current", type=str, required=True)
    p_diff.add_argument("--baseline", type=str, required=True)
    p_diff.add_argument("--out", type=str, help="Write diff JSON to file")

    args = p.parse_args()

    if args.cmd == "think":
        if not args.llm:
            print("ERROR: --llm is required and no fallback is available.", file=sys.stderr)
            sys.exit(2)
        if not os.getenv("OPENAI_API_KEY"):
            print("ERROR: OPENAI_API_KEY is not set.", file=sys.stderr)
            sys.exit(2)

        # 1) Parse Mermaid to skeleton graph
        g = parse_mermaid(args.mermaid)

        # 2) (Optional) LLM-based attribute inference from skeleton
        if args.infer_hints:
            skeleton = json.dumps({
                "nodes": [{"id": n.id, "label": n.label} for n in g.nodes.values()],
                "edges": [{"from": e.src, "to": e.dst, "label": e.label} for e in g.edges],
            }, ensure_ascii=False, indent=2)
            inferred = llm_infer_hints(skeleton, args.openai_model)
            g = merge_llm_hints(g, inferred)

        # 3) Apply user hints to override inferred ones (if provided)
        g = apply_hints(g, args.hints)

        # 4) LLM-driven threat inference
        threats = llm_infer_threats(g, args.openai_model)

        # 5) Export
        if args.format == "json":
            s = export_json(threats, args.out)
        else:
            s = export_md(threats, args.out)
        print(s)

    elif args.cmd == "diff":
        d = diff_reports(args.current, args.baseline)
        s = json.dumps(d, ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(s)
        print(s)

if __name__ == "__main__":
    main()
