#!/usr/bin/env python3
"""
Threat Thinker - CLI
"Throw in an architecture diagram, get a prioritized threat list."

Inputs:
- Mermaid file (.mmd/.mermaid)
- Optional YAML hints for node/edge attributes

Outputs:
- Markdown table or JSON with threats (LLM-driven), each with 1-line "why" and ASVS refs (+ evidence IDs).
- Optional diff vs baseline JSON.

Examples:
  export OPENAI_API_KEY=***
    python main.py think --mermaid examples.mmd --infer-hints --llm-api openai --llm-model gpt-4o-mini --format md --out report.md
    python main.py think --mermaid examples.mmd --infer-hints --hints hints.yaml --llm-model gpt-4o-mini --format json --out report.json
  python main.py diff --current report.json --baseline old.json
"""

import argparse
import json
import os
import re
import sys
import yaml
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from openai import OpenAI

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
    severity: str         # High/Medium/Low
    score: float          # integer 1..9 expected
    affected: List[str]
    why: str
    references: List[str] # e.g., ["ASVS V5 ...", "CWE-319 ..."]
    evidence_nodes: List[str] = field(default_factory=list)  # node IDs
    evidence_edges: List[str] = field(default_factory=list)  # edge IDs (src->dst)
    confidence: Optional[float] = None

# ---------------- Parsers ----------------

# tolerate variations: A->B, A-->B, A--->B |label|
MERMAID_EDGE_RE = re.compile(
    r'^\s*([A-Za-z0-9_]+)\s*-\s*-\s*>+\s*([A-Za-z0-9_]+)\s*(?:\|\s*([^|]+?)\s*\|)?'
)

NODE_LABEL_RE = re.compile(
    r'^\s*([A-Za-z0-9_]+)\s*[\[\(\{]{1,2}\s*([^]\)\}]+?)\s*[\]\)\}]{1,2}'
)

def parse_mermaid(path: str) -> Tuple[Graph, ImportMetrics]:
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
            node.data = list({*node.data, *[str(x) for x in attrs["data"]]})
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
                    edge.data = list({*edge.data, *[str(x) for x in e["data"]]})
                if e.get("label"):
                    edge.label = e["label"]
        if not found:
            new_edge = Edge(src=src, dst=dst, label=e.get("label"))
            new_edge.protocol = e.get("protocol")
            if isinstance(e.get("data"), list):
                new_edge.data = [str(x) for x in e["data"]]
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

def call_llm(api: str,
             model: str,
             system_prompt: str,
             user_prompt: str,
             *,
             response_format: Optional[Dict[str, str]] = None,
             temperature: float = 0.2,
             max_tokens: int = 1600) -> str:
    api_normalized = api.lower()
    if api_normalized != "openai":
        raise NotImplementedError(f"LLM api '{api}' is not supported yet.")

    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")

    client = OpenAI()
    kwargs = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if response_format is not None:
        kwargs["response_format"] = response_format

    resp = client.chat.completions.create(**kwargs)
    content = resp.choices[0].message.content
    if not content:
        raise RuntimeError("LLM returned empty content")
    return content


def llm_infer_hints(graph_skeleton_json: str, api: str, model: str) -> dict:
    user_prompt = (
        "Graph skeleton (nodes with id/label; edges with from/to/label):\n"
        f"{graph_skeleton_json}\n\n"
        "Infer attributes strictly following the output schema.\n"
        f"{HINT_INSTRUCTIONS}"
    )
    content = call_llm(
        api=api,
        model=model,
        system_prompt=HINT_SYSTEM,
        user_prompt=user_prompt,
        response_format={"type": "json_object"},
        temperature=0.2,
        max_tokens=1400,
    )
    return json.loads(content)

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
            ne = Edge(src=src, dst=dst, protocol=e.get("protocol"))
            if isinstance(e.get("data"), list):
                ne.data = [str(x) for x in e["data"]]
            g.edges.append(ne)
    return g

# ---------------- LLM-driven threat inference (required) ----------------

LLM_SYSTEM = (
    "You are Threat Thinker, an expert security analyst. "
    "Given a system graph (nodes/edges with attributes), output a concise, prioritized threat list. "
    "Use STRIDE. Provide a 1-line 'why' per threat (developer-friendly), and include OWASP ASVS references. "
    "CWE refs are optional but helpful. Each threat must link to graph evidence (node/edge IDs)."
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
    '      "references": ["ASVS V5 ...","CWE-319 (optional)"],\n'
    '      "evidence": {"nodes":["n1","n2"], "edges":["n1->n2"]},\n'
    '      "confidence": 0.0\n'
    "    }\n"
    "  ]\n"
    "}\n"
    "Rules:\n"
    "- Severity should be consistent with score (1..9 ~= impact*likelihood). Use integers for score.\n"
    "- Create stable, readable ids (e.g., TLS-app-db-01). Avoid randomness.\n"
    "- Prefer 5–15 high-signal threats; de-duplicate similar findings.\n"
    "- If information is missing, make conservative assumptions and mention them in 'why'.\n"
    "- Each threat MUST include evidence (node/edge IDs) and at least one ASVS reference.\n"
)

def graph_to_prompt(g: Graph) -> str:
    nodes = [asdict(n) for n in g.nodes.values()]
    edges = [asdict(e) for e in g.edges]
    # help LLM with available IDs for evidence
    return json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False, indent=2)

def llm_infer_threats(g: Graph, api: str, model: str) -> List[Threat]:
    payload = graph_to_prompt(g)
    user_prompt = (
        "System graph (JSON):\n"
        f"{payload}\n\n"
        f"{LLM_INSTRUCTIONS}"
    )
    content = call_llm(
        api=api,
        model=model,
        system_prompt=LLM_SYSTEM,
        user_prompt=user_prompt,
        response_format={"type": "json_object"},
        temperature=0.2,
        max_tokens=1600,
    )
    data = json.loads(content)

    threats_out: List[Threat] = []
    for t in data.get("threats", []):
        tid = (str(t.get("id") or "").strip())[:64]
        if not tid:
            import hashlib
            tid = hashlib.sha1(str(t.get("title","")).encode("utf-8")).hexdigest()[:8]
        severity = str(t.get("severity","Medium"))
        score = float(t.get("score", 4))
        ev = t.get("evidence") or {}
        ev_nodes = [str(x) for x in (ev.get("nodes") or [])]
        ev_edges = [str(x) for x in (ev.get("edges") or [])]
        conf = t.get("confidence", None)
        if isinstance(conf, (int, float)):
            conf = float(conf)
        else:
            conf = None
        threats_out.append(Threat(
            id=tid,
            title=str(t.get("title") or "Untitled"),
            stride=[str(s) for s in (t.get("stride") or [])],
            severity=severity,
            score=score,
            affected=[str(a) for a in (t.get("affected") or [])],
            why=str(t.get("why") or ""),
            references=[str(r) for r in (t.get("references") or [])],
            evidence_nodes=ev_nodes,
            evidence_edges=ev_edges,
            confidence=conf
        ))
    if not threats_out:
        raise RuntimeError("LLM returned no threats")
    # de-dup by stable id first
    uniq = {t.id: t for t in threats_out}
    return list(uniq.values())

# de-noise / policy filters ------------------------------------------------

def denoise_threats(threats: List[Threat],
                    require_asvs: bool = True,
                    min_confidence: float = 0.0,
                    topn: Optional[int] = None) -> List[Threat]:
    filtered: List[Threat] = []
    for t in threats:
        if require_asvs and not any("ASVS" in r.upper() for r in t.references):
            continue
        if (t.confidence is not None) and (t.confidence < min_confidence):
            continue
        # require evidence for explainability
        if not t.evidence_nodes and not t.evidence_edges:
            continue
        # drop too generic “why”
        if len(t.why.strip()) < 6:
            continue
        filtered.append(t)
    # stable sort: score desc, then severity, then title
    filtered.sort(key=lambda x: (-x.score, x.severity, x.title))
    if topn:
        filtered = filtered[:topn]
    # merge near-duplicates by (title, evidence) signature
    sig_seen = set()
    uniq: List[Threat] = []
    for t in filtered:
        sig = (t.title.lower(), tuple(sorted(t.evidence_nodes)), tuple(sorted(t.evidence_edges)))
        if sig in sig_seen:
            continue
        sig_seen.add(sig)
        uniq.append(t)
    return uniq

# ---------------- Export ----------------

def export_json(threats: List[Threat], out_path: Optional[str], metrics: Optional[ImportMetrics]=None) -> str:
    data = []
    for t in threats:
        data.append({
            "id": t.id,
            "title": t.title,
            "stride": t.stride,
            "severity": t.severity,
            "score": t.score,
            "affected": t.affected,
            "why": t.why,
            "references": t.references,
            "evidence": {"nodes": t.evidence_nodes, "edges": t.evidence_edges},
            "confidence": t.confidence
        })
    obj = {
        "generated_at": __import__("datetime").datetime.datetime.now(__import__("datetime").timezone.utc).isoformat() + "Z",
        "count": len(data),
        "threats": data
    }
    if metrics:
        obj["import_metrics"] = {
            "total_lines": metrics.total_lines,
            "edge_candidates": metrics.edge_candidates,
            "edges_parsed": metrics.edges_parsed,
            "node_label_candidates": metrics.node_label_candidates,
            "node_labels_parsed": metrics.node_labels_parsed,
            "import_success_rate": metrics.import_success_rate
        }
    s = json.dumps(obj, ensure_ascii=False, indent=2)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(s)
    return s

def export_md(threats: List[Threat], out_path: Optional[str], metrics: Optional[ImportMetrics]=None) -> str:
    lines = []
    lines.append("# Threat Thinker Report")
    lines.append("")
    lines.append(f"Generated: {__import__('datetime').datetime.utcnow().isoformat()}Z")
    if metrics:
        lines.append("")
        lines.append(f"Import Success: {metrics.import_success_rate*100:.1f}% "
                     f"(edges {metrics.edges_parsed}/{metrics.edge_candidates}, "
                     f"labels {metrics.node_labels_parsed}/{metrics.node_label_candidates})")
    lines.append("")
    lines.append("| Severity | Title | Why | Affected | STRIDE | References | Evidence | Score |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for t in threats:
        ev = ", ".join([*t.evidence_nodes, *t.evidence_edges]).replace("|","/")
        lines.append("| {sev} | {title} | {why} | {aff} | {stride} | {refs} | {ev} | {score} |".format(
            sev=t.severity,
            title=t.title.replace("|","/"),
            why=t.why.replace("|","/"),
            aff=", ".join(t.affected).replace("|","/"),
            stride=", ".join(t.stride),
            refs=", ".join(t.references).replace("|","/"),
            ev=ev,
            score=int(t.score),
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
    p = argparse.ArgumentParser(prog="threat_thinker", description="Threat Thinker CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_think = sub.add_parser("think", help="Parse diagram + hints, generate threats (LLM required)")
    p_think.add_argument("--mermaid", type=str, required=True, help="Path to Mermaid (.mmd/.mermaid)")
    p_think.add_argument("--hints", type=str, help="Optional YAML hints file")
    p_think.add_argument("--infer-hints", action="store_true",
                         help="Infer node/edge attributes from Mermaid via LLM (multilingual)")
    p_think.add_argument("--format", choices=["json", "md"], default="md")
    p_think.add_argument("--out", type=str, help="Write output to file")
    p_think.add_argument("--llm-api", type=str, default="openai", help="LLM provider to use (currently only 'openai')")
    p_think.add_argument("--llm-model", type=str, default="gpt-4o-mini", help="LLM model identifier")

    p_think.add_argument("--topn", type=int, default=15, help="Keep top-N threats after de-noise")
    p_think.add_argument("--min-confidence", type=float, default=0.0, help="Drop threats below this confidence")
    p_think.add_argument("--require-asvs", action="store_true", help="Require at least one ASVS reference")

    p_diff = sub.add_parser("diff", help="Diff two JSON reports")
    p_diff.add_argument("--current", type=str, required=True)
    p_diff.add_argument("--baseline", type=str, required=True)
    p_diff.add_argument("--out", type=str, help="Write diff JSON to file")

    p_webui = sub.add_parser("webui", help="Launch the Gradio Web UI")
    p_webui.add_argument("--host", type=str, default="127.0.0.1", help="Interface to bind (default: 127.0.0.1)")
    p_webui.add_argument("--port", type=int, help="Port to bind")
    p_webui.add_argument("--share", action="store_true", help="Enable public Gradio share URL")

    args = p.parse_args()

    if args.cmd == "think":
        if args.llm_api.lower() != "openai":
            print("ERROR: only --llm-api openai is supported right now.", file=sys.stderr)
            sys.exit(2)
        if not os.getenv("OPENAI_API_KEY"):
            print("ERROR: OPENAI_API_KEY is not set.", file=sys.stderr)
            sys.exit(2)

        # 1) Parse Mermaid to skeleton graph (+ metrics)
        g, metrics = parse_mermaid(args.mermaid)
        print("Parsed graph:")
        print(g)
        print("\n")
        print("Parsed metrics:")
        print(metrics)
        print("\n")

        # 2) (Optional) LLM-based attribute inference from skeleton
        if args.infer_hints:
            skeleton = json.dumps({
                "nodes": [{"id": n.id, "label": n.label} for n in g.nodes.values()],
                "edges": [{"from": e.src, "to": e.dst, "label": e.label} for e in g.edges],
            }, ensure_ascii=False, indent=2)
            inferred = llm_infer_hints(skeleton, args.llm_api, args.llm_model)
            g = merge_llm_hints(g, inferred)
        print("Graph after LLM-inferred hints:")
        print(g)
        print("\n")

        # 3) Apply user hints to override inferred ones (if provided)
        g = apply_hints(g, args.hints)
        print("Graph after applying user hints:")
        print(g)
        print("\n")

        # 4) LLM-driven threat inference
        threats = llm_infer_threats(g, args.llm_api, args.llm_model)
        print(f"LLM inferred {len(threats)} threats.")
        for t in threats:
            print(t)
        print("\n")

        # 5) De-noise & trim
        threats = denoise_threats(
            threats,
            require_asvs=args.require_asvs,
            min_confidence=args.min_confidence,
            topn=args.topn
        )
        print(f"{len(threats)} threats after de-noising/filtering.")
        for t in threats:
            print(t)
        print("\n")

        # 6) Export
        if args.format == "json":
            s = export_json(threats, args.out, metrics)
        else:
            s = export_md(threats, args.out, metrics)
        print(s)

    elif args.cmd == "diff":
        d = diff_reports(args.current, args.baseline)
        s = json.dumps(d, ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(s)
        print(s)
    elif args.cmd == "webui":
        import webui
        webui.launch_webui(
            server_name=args.host,
            server_port=args.port,
            share=args.share,
        )

if __name__ == "__main__":
    main()
