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
    python main.py think --drawio examples.drawio --infer-hints --llm-api openai --llm-model gpt-4o-mini --format md --lang ja --out report_ja.md
    python main.py think --image examples/architecture.png --infer-hints --llm-api openai --llm-model gpt-4o --format md --out report.md
    python main.py think --diagram examples/system.xml --infer-hints --llm-api openai --llm-model gpt-4o-mini --format md --lang ko --out report_ko.md
    python main.py think --mermaid examples.mmd --infer-hints --llm-api openai --llm-model gpt-4o-mini --format md --lang zh --out report_zh.md
  export ANTHROPIC_API_KEY=***
    python main.py think --mermaid examples.mmd --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --format md --out report.md
    python main.py think --image examples/system_diagram.jpg --infer-hints --llm-api anthropic --llm-model claude-3-5-sonnet-20241022 --format md --out report.md
    python main.py think --diagram examples/system.xml --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --format md --lang pt --out report_pt.md
    python main.py think --drawio examples.drawio --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --format md --lang ru --out report_ru.md
  For AWS Bedrock:
    # Option 1: Use AWS Profile
    aws configure --profile my-profile
    python main.py think --mermaid examples.mmd --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --aws-profile my-profile --aws-region us-east-1 --format md --out report.md
    python main.py think --image examples/architecture.png --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20241022-v1:0 --aws-profile my-profile --aws-region us-east-1 --format md --out report.md
    python main.py think --drawio examples.drawio --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --aws-profile my-profile --aws-region us-east-1 --format md --lang ar --out report_ar.md
    python main.py think --diagram examples/system.xml --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --aws-profile my-profile --aws-region us-east-1 --format md --lang hi --out report_hi.md
    # Option 2: Use environment variables
    export AWS_ACCESS_KEY_ID=***
    export AWS_SECRET_ACCESS_KEY=***
    export AWS_SESSION_TOKEN=***  # if using temporary credentials
    export AWS_DEFAULT_REGION=us-east-1
    python main.py think --mermaid examples.mmd --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --format md --lang th --out report_th.md
  python main.py diff --current report.json --baseline old.json
"""

import argparse
import json
import os
import sys

from parsers.mermaid_parser import parse_mermaid
from parsers.drawio_parser import parse_drawio
from parsers.image_parser import parse_image
from hint_processor import apply_hints, merge_llm_hints
from llm.inference import llm_infer_hints, llm_infer_threats
from threat_analyzer import denoise_threats
from exporters import export_json, export_md, diff_reports


def main():
    p = argparse.ArgumentParser(prog="threat_thinker", description="Threat Thinker CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_think = sub.add_parser(
        "think", help="Parse diagram + hints, generate threats (LLM required)"
    )
    p_think.add_argument("--mermaid", type=str, help="Path to Mermaid (.mmd/.mermaid)")
    p_think.add_argument("--drawio", type=str, help="Path to Draw.io (.drawio/.xml)")
    p_think.add_argument(
        "--image", type=str, help="Path to image file (.jpg/.jpeg/.png/.gif/.bmp/.webp)"
    )
    p_think.add_argument(
        "--diagram",
        type=str,
        help="Path to diagram file (auto-detects format from extension)",
    )
    p_think.add_argument("--hints", type=str, help="Optional YAML hints file")
    p_think.add_argument(
        "--infer-hints",
        action="store_true",
        help="Infer node/edge attributes from Mermaid via LLM (multilingual)",
    )
    p_think.add_argument("--format", choices=["json", "md"], default="md")
    p_think.add_argument("--out", type=str, help="Write output to file")
    p_think.add_argument(
        "--llm-api",
        type=str,
        default="openai",
        help="LLM provider to use ('openai', 'anthropic', or 'bedrock')",
    )
    p_think.add_argument(
        "--llm-model", type=str, default="gpt-4o-mini", help="LLM model identifier"
    )
    p_think.add_argument(
        "--aws-profile", type=str, help="AWS profile name (for bedrock provider only)"
    )
    p_think.add_argument(
        "--aws-region",
        type=str,
        help="AWS region (for bedrock provider only, defaults to us-east-1)",
    )

    p_think.add_argument(
        "--topn", type=int, default=10, help="Keep top-N threats after de-noise"
    )
    p_think.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="Drop threats below this confidence",
    )
    p_think.add_argument(
        "--require-asvs",
        action="store_true",
        help="Require at least one ASVS reference",
    )
    p_think.add_argument(
        "--lang",
        type=str,
        default="en",
        help="Output language code (ISO 639-1, e.g., en, ja, fr, de, es, zh, ko, pt, it, ru, ar, hi, th, vi, etc.) - LLM will automatically translate UI elements",
    )

    p_diff = sub.add_parser("diff", help="Diff two JSON reports")
    p_diff.add_argument("--current", type=str, required=True)
    p_diff.add_argument("--baseline", type=str, required=True)
    p_diff.add_argument("--out", type=str, help="Write diff JSON to file")

    p_webui = sub.add_parser("webui", help="Launch the Gradio Web UI")
    p_webui.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Interface to bind (default: 127.0.0.1)",
    )
    p_webui.add_argument("--port", type=int, help="Port to bind")

    args = p.parse_args()

    if args.cmd == "think":
        # Determine diagram file and format
        diagram_file = None
        diagram_format = None

        if args.diagram:
            diagram_file = args.diagram
            # Auto-detect format from extension
            if diagram_file.lower().endswith((".mmd", ".mermaid")):
                diagram_format = "mermaid"
            elif diagram_file.lower().endswith((".drawio", ".xml")):
                diagram_format = "drawio"
            elif diagram_file.lower().endswith(
                (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp")
            ):
                diagram_format = "image"
            else:
                print(
                    f"ERROR: Unsupported diagram file format for {diagram_file}. Supported: .mmd, .mermaid, .drawio, .xml, .jpg, .jpeg, .png, .gif, .bmp, .webp",
                    file=sys.stderr,
                )
                sys.exit(2)
        elif args.mermaid:
            diagram_file = args.mermaid
            diagram_format = "mermaid"
        elif args.drawio:
            diagram_file = args.drawio
            diagram_format = "drawio"
        elif args.image:
            diagram_file = args.image
            diagram_format = "image"
        else:
            print(
                "ERROR: Please specify a diagram file using --diagram, --mermaid, --drawio, or --image",
                file=sys.stderr,
            )
            sys.exit(2)
        supported_apis = ["openai", "anthropic", "bedrock"]
        if args.llm_api.lower() not in supported_apis:
            print(f"ERROR: --llm-api must be one of {supported_apis}.", file=sys.stderr)
            sys.exit(2)

        # Check for required API keys/credentials
        if args.llm_api.lower() == "openai" and not os.getenv("OPENAI_API_KEY"):
            print("ERROR: OPENAI_API_KEY is not set.", file=sys.stderr)
            sys.exit(2)
        elif args.llm_api.lower() == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
            print("ERROR: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
            sys.exit(2)
        elif args.llm_api.lower() == "bedrock":
            # For bedrock, we check credentials later in the provider initialization
            # Here we just validate that if aws-profile is provided, it's for bedrock
            if not args.aws_profile and not (
                os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
            ):
                print(
                    "WARNING: For bedrock API, either set --aws-profile or AWS environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)",
                    file=sys.stderr,
                )

        # 1) Parse diagram to skeleton graph (+ metrics)
        if diagram_format == "mermaid":
            g, metrics = parse_mermaid(diagram_file)
        elif diagram_format == "drawio":
            g, metrics = parse_drawio(diagram_file)
        elif diagram_format == "image":
            g, metrics = parse_image(
                diagram_file,
                api=args.llm_api,
                model=args.llm_model,
                aws_profile=args.aws_profile,
                aws_region=args.aws_region,
            )
        else:
            print(
                f"ERROR: Unsupported diagram format: {diagram_format}", file=sys.stderr
            )
            sys.exit(2)
        print("Parsed graph:")
        print(g)
        print("\n")
        print("Parsed metrics:")
        print(metrics)
        print("\n")

        # 2) (Optional) LLM-based attribute inference from skeleton
        if args.infer_hints:
            skeleton = json.dumps(
                {
                    "nodes": [{"id": n.id, "label": n.label} for n in g.nodes.values()],
                    "edges": [
                        {"from": e.src, "to": e.dst, "label": e.label} for e in g.edges
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
            inferred = llm_infer_hints(
                skeleton,
                args.llm_api,
                args.llm_model,
                args.aws_profile,
                args.aws_region,
                args.lang,
            )
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
        threats = llm_infer_threats(
            g,
            args.llm_api,
            args.llm_model,
            args.aws_profile,
            args.aws_region,
            args.lang,
        )
        print(f"LLM inferred {len(threats)} threats.")
        for t in threats:
            print(t)
        print("\n")

        # 5) De-noise & trim
        threats = denoise_threats(
            threats,
            require_asvs=args.require_asvs,
            min_confidence=args.min_confidence,
            topn=args.topn,
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
        )


if __name__ == "__main__":
    main()
