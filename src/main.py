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
  export ANTHROPIC_API_KEY=***
    python main.py think --mermaid examples.mmd --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --format md --out report.md
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

from parsers.mermaid_parser import parse_mermaid
from hint_processor import apply_hints, merge_llm_hints
from llm.inference import llm_infer_hints, llm_infer_threats
from threat_analyzer import denoise_threats
from exporters import export_json, export_md, diff_reports

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
    p_think.add_argument("--llm-api", type=str, default="openai", help="LLM provider to use ('openai' or 'anthropic')")
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
        supported_apis = ["openai", "anthropic"]
        if args.llm_api.lower() not in supported_apis:
            print(f"ERROR: --llm-api must be one of {supported_apis}.", file=sys.stderr)
            sys.exit(2)
        
        # Check for required API keys
        if args.llm_api.lower() == "openai" and not os.getenv("OPENAI_API_KEY"):
            print("ERROR: OPENAI_API_KEY is not set.", file=sys.stderr)
            sys.exit(2)
        elif args.llm_api.lower() == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
            print("ERROR: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
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
