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
    python main.py think --mermaid examples.mmd --infer-hints --llm-api openai --llm-model gpt-4o-mini --format md --out-md report.md
    python main.py think --mermaid examples.mmd --infer-hints --hints hints.yaml --llm-model gpt-4o-mini --format json --out-json report.json
    python main.py think --mermaid examples.mmd --infer-hints --llm-api openai --llm-model gpt-4o-mini --format both --out-md report.md --out-json report.json
    python main.py think --drawio examples.drawio --infer-hints --llm-api openai --llm-model gpt-4o-mini --format md --lang ja --out-md report_ja.md
    python main.py think --image examples/architecture.png --infer-hints --llm-api openai --llm-model gpt-4o --format md --out-md report.md
    python main.py think --diagram examples/system.xml --infer-hints --llm-api openai --llm-model gpt-4o-mini --format md --lang ko --out-md report_ko.md
    python main.py think --mermaid examples.mmd --infer-hints --llm-api openai --llm-model gpt-4o-mini --format md --lang zh --out-md report_zh.md
  export ANTHROPIC_API_KEY=***
    python main.py think --mermaid examples.mmd --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --format md --out-md report.md
    python main.py think --image examples/system_diagram.jpg --infer-hints --llm-api anthropic --llm-model claude-3-5-sonnet-20241022 --format md --out-md report.md
    python main.py think --diagram examples/system.xml --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --format md --lang pt --out-md report_pt.md
    python main.py think --drawio examples.drawio --infer-hints --llm-api anthropic --llm-model claude-3-haiku-20240307 --format md --lang ru --out-md report_ru.md
  For AWS Bedrock:
    # Option 1: Use AWS Profile
    aws configure --profile my-profile
    python main.py think --mermaid examples.mmd --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --aws-profile my-profile --aws-region us-east-1 --format md --out-md report.md
    python main.py think --image examples/architecture.png --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20241022-v1:0 --aws-profile my-profile --aws-region us-east-1 --format md --out-md report.md
    python main.py think --drawio examples.drawio --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --aws-profile my-profile --aws-region us-east-1 --format md --lang ar --out-md report_ar.md
    python main.py think --diagram examples/system.xml --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --aws-profile my-profile --aws-region us-east-1 --format md --lang hi --out-md report_hi.md
    # Option 2: Use environment variables
    export AWS_ACCESS_KEY_ID=***
    export AWS_SECRET_ACCESS_KEY=***
    export AWS_SESSION_TOKEN=***  # if using temporary credentials
    export AWS_DEFAULT_REGION=us-east-1
    python main.py think --mermaid examples.mmd --infer-hints --llm-api bedrock --llm-model anthropic.claude-3-5-sonnet-20240620-v1:0 --format md --lang th --out-md report_th.md
  python main.py diff --after report.json --before old.json
"""

import argparse
import json
import os
import sys
import time

from parsers.mermaid_parser import parse_mermaid
from parsers.drawio_parser import parse_drawio
from parsers.image_parser import parse_image
from hint_processor import apply_hints, merge_llm_hints
from llm.inference import llm_infer_hints, llm_infer_threats
from threat_analyzer import denoise_threats
from exporters import export_json, export_md, diff_reports, export_diff_md, export_html
from cliui import ui, set_verbose
from rag import (
    KnowledgeBaseError,
    DEFAULT_CHUNK_OVERLAP,
    DEFAULT_CHUNK_TOKENS,
    DEFAULT_EMBED_MODEL,
    DEFAULT_TOPK,
    build_kb,
    list_kbs,
    search_kb,
    remove_kb,
    retrieve_context_for_graph,
    get_kb_root,
)


def _normalize_embed_model(embed_arg: str) -> str:
    value = (embed_arg or "").strip()
    if ":" in value:
        value = value.split(":", 1)[-1]
    return value or DEFAULT_EMBED_MODEL


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
    p_think.add_argument(
        "--format",
        choices=["json", "md", "html", "both", "all"],
        default="both",
    )
    p_think.add_argument("--out-md", type=str, help="Write Markdown output to file")
    p_think.add_argument("--out-json", type=str, help="Write JSON output to file")
    p_think.add_argument("--out-html", type=str, help="Write HTML output to file")
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
    p_think.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output with detailed logs",
    )
    p_think.add_argument(
        "--rag",
        action="store_true",
        help="Enable local RAG enrichment using knowledge bases built with `kb build`",
    )
    p_think.add_argument(
        "--kb",
        type=str,
        help="Comma-separated knowledge base names to use when --rag is enabled",
    )
    p_think.add_argument(
        "--rag-topk",
        type=int,
        default=DEFAULT_TOPK,
        help=f"Number of retrieved knowledge chunks to inject (default: {DEFAULT_TOPK})",
    )

    p_kb = sub.add_parser("kb", help="Manage local knowledge bases for RAG")
    p_kb.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output with detailed logs",
    )
    kb_sub = p_kb.add_subparsers(dest="kb_cmd", required=True)

    kb_build = kb_sub.add_parser(
        "build", help="Chunk documents in raw/ and create embeddings"
    )
    kb_build.add_argument("kb_name", type=str, help="Knowledge base name")
    kb_build.add_argument(
        "--embedder",
        type=str,
        default=f"openai:{DEFAULT_EMBED_MODEL}",
        help="Embedding backend (OpenAI only). Format: openai:<model>",
    )
    kb_build.add_argument(
        "--chunk-tokens",
        type=int,
        default=DEFAULT_CHUNK_TOKENS,
        help=f"Max tokens per chunk (default: {DEFAULT_CHUNK_TOKENS})",
    )
    kb_build.add_argument(
        "--chunk-overlap",
        type=int,
        default=DEFAULT_CHUNK_OVERLAP,
        help=f"Token overlap between chunks (default: {DEFAULT_CHUNK_OVERLAP})",
    )

    kb_sub.add_parser("list", help="List available knowledge bases")

    kb_search = kb_sub.add_parser(
        "search", help="Query a knowledge base with semantic similarity"
    )
    kb_search.add_argument("kb_name", type=str, help="Knowledge base name")
    kb_search.add_argument("query", type=str, help="Search query")
    kb_search.add_argument(
        "--topk",
        type=int,
        default=DEFAULT_TOPK,
        help=f"Number of chunks to return (default: {DEFAULT_TOPK})",
    )
    kb_search.add_argument(
        "--show",
        action="store_true",
        help="Print retrieved chunk text to stdout",
    )

    kb_remove = kb_sub.add_parser("remove", help="Delete a knowledge base directory")
    kb_remove.add_argument("kb_name", type=str, help="Knowledge base name")
    kb_remove.add_argument(
        "--force", action="store_true", help="Remove without confirmation"
    )

    p_diff = sub.add_parser("diff", help="Diff two JSON reports")
    p_diff.add_argument(
        "--after", type=str, required=True, help="Path to after report JSON"
    )
    p_diff.add_argument(
        "--before", type=str, required=True, help="Path to before report JSON"
    )
    p_diff.add_argument("--out-json", type=str, help="Write diff JSON to file")
    p_diff.add_argument("--out-md", type=str, help="Write diff Markdown to file")
    p_diff.add_argument(
        "--llm-api",
        type=str,
        default="openai",
        help="LLM provider to use ('openai', 'anthropic', or 'bedrock')",
    )
    p_diff.add_argument(
        "--llm-model", type=str, default="gpt-4o-mini", help="LLM model identifier"
    )
    p_diff.add_argument(
        "--aws-profile", type=str, help="AWS profile name (for bedrock provider only)"
    )
    p_diff.add_argument(
        "--aws-region",
        type=str,
        help="AWS region (for bedrock provider only, defaults to us-east-1)",
    )
    p_diff.add_argument(
        "--lang",
        type=str,
        default="en",
        help="Output language code (ISO 639-1, e.g., en, ja, fr, de, es, zh, ko, pt, it, ru, ar, hi, th, vi, etc.) - LLM will automatically translate UI elements",
    )
    p_diff.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output with detailed logs",
    )

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
        start_time = time.time()

        # Set verbose mode
        set_verbose(args.verbose)

        # Set up progress tracking
        total_steps = 6 + (1 if args.rag else 0)
        ui.set_total_steps(
            total_steps
        )  # Parse, Infer hints, Apply hints, (Retrieve), Analyze threats, Denoise, Export

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
                ui.error(
                    f"Unsupported diagram file format for {diagram_file}",
                    "Supported: .mmd, .mermaid, .drawio, .xml, .jpg, .jpeg, .png, .gif, .bmp, .webp",
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
            ui.error(
                "No diagram file specified",
                "Please specify a diagram file using --diagram, --mermaid, --drawio, or --image",
            )
            sys.exit(2)

        supported_apis = ["openai", "anthropic", "bedrock"]
        if args.llm_api.lower() not in supported_apis:
            ui.error(
                f"Invalid LLM API: {args.llm_api}", f"Must be one of {supported_apis}"
            )
            sys.exit(2)

        # Check for required API keys/credentials
        if args.llm_api.lower() == "openai" and not os.getenv("OPENAI_API_KEY"):
            ui.error(
                "OPENAI_API_KEY is not set",
                "Please set your OpenAI API key in environment variables",
            )
            sys.exit(2)
        elif args.llm_api.lower() == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
            ui.error(
                "ANTHROPIC_API_KEY is not set",
                "Please set your Anthropic API key in environment variables",
            )
            sys.exit(2)
        elif args.llm_api.lower() == "bedrock":
            # For bedrock, we check credentials later in the provider initialization
            # Here we just validate that if aws-profile is provided, it's for bedrock
            if not args.aws_profile and not (
                os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
            ):
                ui.warning(
                    "AWS credentials not fully configured",
                    "For bedrock API, either set --aws-profile or AWS environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)",
                )

        rag_kbs: list[str] = []
        if args.rag:
            if not os.getenv("OPENAI_API_KEY"):
                ui.error(
                    "OPENAI_API_KEY is required for --rag",
                    "Local RAG relies on OpenAI embeddings for semantic search.",
                )
                sys.exit(2)
            if not args.kb:
                ui.error(
                    "--kb is required when --rag is enabled",
                    "Provide a comma-separated list of knowledge base names.",
                )
                sys.exit(2)
            rag_kbs = [kb.strip() for kb in args.kb.split(",") if kb.strip()]
            if not rag_kbs:
                ui.error(
                    "No valid knowledge base names provided",
                    "Example: --kb owasp,internal-standards",
                )
                sys.exit(2)

        # 1) Parse diagram to skeleton graph (+ metrics)
        ui.step("Parsing architecture diagram")
        ui.info(f"Loading {diagram_format} diagram: {diagram_file}")

        thinking = ui.create_thinking_indicator("Parsing diagram structure")
        thinking.start()

        try:
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
                ui.error(f"Unsupported diagram format: {diagram_format}")
                sys.exit(2)

            thinking.stop()
            ui.success("Successfully parsed diagram")
            ui.show_metrics_summary(metrics)
            ui.debug("Parsed graph details", str(g))

        except Exception as e:
            thinking.stop()
            ui.error("Failed to parse diagram", str(e))
            sys.exit(2)

        # 2) (Optional) LLM-based attribute inference from skeleton
        if args.infer_hints:
            ui.step("Inferring node and edge attributes")
            ui.thinking(
                "AI is analyzing diagram components to infer security-relevant attributes"
            )

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

            thinking = ui.create_thinking_indicator(
                "AI is inferring component attributes"
            )
            thinking.start()

            try:
                inferred = llm_infer_hints(
                    skeleton,
                    args.llm_api,
                    args.llm_model,
                    args.aws_profile,
                    args.aws_region,
                    args.lang,
                )
                g = merge_llm_hints(g, inferred)
                thinking.stop()
                ui.success("Successfully inferred component attributes")
                ui.debug("Graph after LLM-inferred hints", str(g))

            except Exception as e:
                thinking.stop()
                ui.error("Failed to infer hints", str(e))
                sys.exit(2)
        else:
            ui.step("Skipping attribute inference")
            ui.info("Using basic component attributes from diagram")

        # 3) Apply user hints to override inferred ones (if provided)
        ui.step("Applying configuration")
        if args.hints:
            ui.info(f"Loading custom hints from: {args.hints}")
            try:
                g = apply_hints(g, args.hints)
                ui.success("Applied custom hints successfully")
            except Exception as e:
                ui.warning("Failed to apply some hints", str(e))
        else:
            ui.info("No custom hints provided, using inferred attributes")

        ui.debug("Graph after applying user hints", str(g))

        rag_context_text = None
        if args.rag:
            ui.step("Retrieving local knowledge")
            try:
                retrieval = retrieve_context_for_graph(
                    g,
                    rag_kbs,
                    topk=args.rag_topk or DEFAULT_TOPK,
                )
                rag_context_text = retrieval.get("context_text") or ""
                num_chunks = len(retrieval.get("results", []))
                if rag_context_text and num_chunks:
                    ui.success(
                        f"Retrieved {num_chunks} knowledge chunks from {', '.join(rag_kbs)}"
                    )
                    ui.debug("RAG query", retrieval.get("query", ""))
                else:
                    ui.warning(
                        "No knowledge snippets retrieved",
                        "Proceeding without additional context.",
                    )
            except KnowledgeBaseError as e:
                ui.error("Failed to retrieve local knowledge", str(e))
                sys.exit(2)

        # 4) LLM-driven threat inference
        ui.step("Analyzing potential security threats")
        ui.thinking("AI is performing comprehensive security threat analysis")

        thinking = ui.create_thinking_indicator("AI is identifying security threats")
        thinking.start()

        try:
            threats = llm_infer_threats(
                g,
                args.llm_api,
                args.llm_model,
                args.aws_profile,
                args.aws_region,
                args.lang,
                rag_context=rag_context_text,
            )
            thinking.stop()
            ui.success(f"Identified {len(threats)} potential threats")
            ui.debug("LLM inferred threats", "\n".join(str(t) for t in threats))

        except Exception as e:
            thinking.stop()
            ui.error("Failed to analyze threats", str(e))
            sys.exit(2)

        # 5) De-noise & trim
        ui.step("Filtering and prioritizing threats")
        ui.info("Applying threat filtering criteria")

        try:
            original_count = len(threats)
            threats = denoise_threats(
                threats,
                require_asvs=args.require_asvs,
                min_confidence=args.min_confidence,
                topn=args.topn,
            )

            filtered_count = original_count - len(threats)
            if filtered_count > 0:
                ui.info(f"Filtered out {filtered_count} low-confidence threats")

            ui.success(f"Finalized {len(threats)} high-priority threats")
            ui.show_threats_preview(threats)
            ui.debug(
                "Threats after de-noising/filtering", "\n".join(str(t) for t in threats)
            )

        except Exception as e:
            ui.error("Failed to filter threats", str(e))
            sys.exit(2)

        # 6) Export
        ui.step("Generating reports")
        ui.info(f"Exporting in {args.format} format")

        try:
            if args.format == "json":
                s = export_json(threats, args.out_json, metrics, g)
                if args.out_json:
                    ui.success(f"JSON report saved to: {args.out_json}")
                if not args.verbose:
                    ui.debug("JSON output", s)
                else:
                    print("\n" + s)

            elif args.format == "md":
                s = export_md(threats, args.out_md)
                if args.out_md:
                    ui.success(f"Markdown report saved to: {args.out_md}")
                if not args.verbose:
                    ui.debug("Markdown output", s)
                else:
                    print("\n" + s)

            elif args.format == "html":
                s = export_html(threats, args.out_html, g)
                if args.out_html:
                    ui.success(f"HTML report saved to: {args.out_html}")
                if not args.verbose:
                    ui.debug("HTML output", s)
                else:
                    print("\n" + s)

            elif args.format == "both":
                # Export JSON and Markdown
                json_output = export_json(threats, args.out_json, metrics, g)
                md_output = export_md(threats, args.out_md)

                if args.out_json:
                    ui.success(f"JSON report saved to: {args.out_json}")
                if args.out_md:
                    ui.success(f"Markdown report saved to: {args.out_md}")

                if args.verbose:
                    print("\nJSON Output:")
                    print(json_output)
                    print("\nMarkdown Output:")
                    print(md_output)
                else:
                    ui.debug("JSON output", json_output)
                    ui.debug("Markdown output", md_output)

            elif args.format == "all":
                json_output = export_json(threats, args.out_json, metrics, g)
                md_output = export_md(threats, args.out_md)
                html_output = export_html(threats, args.out_html, g)

                if args.out_json:
                    ui.success(f"JSON report saved to: {args.out_json}")
                if args.out_md:
                    ui.success(f"Markdown report saved to: {args.out_md}")
                if args.out_html:
                    ui.success(f"HTML report saved to: {args.out_html}")

                if args.verbose:
                    print("\nJSON Output:")
                    print(json_output)
                    print("\nMarkdown Output:")
                    print(md_output)
                    print("\nHTML Output:")
                    print(html_output)
                else:
                    ui.debug("JSON output", json_output)
                    ui.debug("Markdown output", md_output)
                    ui.debug("HTML output", html_output)

        except Exception as e:
            ui.error("Failed to export reports", str(e))
            sys.exit(2)

        # Show final summary
        end_time = time.time()
        processing_time = end_time - start_time
        ui.show_summary(len(threats), processing_time)

    elif args.cmd == "kb":
        set_verbose(args.verbose)

        if args.kb_cmd == "list":
            entries = list_kbs()
            root = get_kb_root()
            if not entries:
                ui.info(
                    f"No knowledge bases found under {root}.",
                    "Use `threat-thinker kb build <name>` after adding documents to raw/.",
                )
            else:
                ui.info(f"Knowledge bases stored in {root}:")
                for entry in entries:
                    updated = entry.get("updated_at") or "unknown"
                    num_chunks = entry.get("num_chunks", 0)
                    num_docs = entry.get("num_documents", 0)
                    model = entry.get("embedding_model") or DEFAULT_EMBED_MODEL
                    print(
                        f"  • {entry['name']}: {num_chunks} chunks from {num_docs} docs (model={model}, updated={updated})"
                    )
        elif args.kb_cmd == "build":
            if not os.getenv("OPENAI_API_KEY"):
                ui.error(
                    "OPENAI_API_KEY is required to build a knowledge base.",
                    "Set your OpenAI key before invoking embeddings.",
                )
                sys.exit(2)
            embed_model = _normalize_embed_model(args.embedder)
            try:
                meta = build_kb(
                    args.kb_name,
                    embed_model=embed_model,
                    chunk_tokens=args.chunk_tokens,
                    chunk_overlap=args.chunk_overlap,
                )
                ui.success(
                    f"KB '{args.kb_name}' built with {meta['num_chunks']} chunks using {meta['embedding_model']}"
                )
            except KnowledgeBaseError as e:
                ui.error("Failed to build knowledge base", str(e))
                sys.exit(2)
        elif args.kb_cmd == "search":
            if not os.getenv("OPENAI_API_KEY"):
                ui.error(
                    "OPENAI_API_KEY is required for semantic search.",
                    "Set your OpenAI key before executing `kb search`.",
                )
                sys.exit(2)
            try:
                results = search_kb(
                    args.kb_name,
                    args.query,
                    topk=args.topk,
                )
            except KnowledgeBaseError as e:
                ui.error("KB search failed", str(e))
                sys.exit(2)

            if not results:
                ui.info("No chunks matched the query.")
            else:
                ui.info(f"Top {len(results)} chunks:")
                for idx, item in enumerate(results, 1):
                    print(
                        f"  {idx}. KB={item['kb']} chunk={item['chunk_id']} "
                        f"score={item['score']:.3f} source={item.get('source')}"
                    )
                    if args.show:
                        snippet = (item["text"] or "").strip()
                        if len(snippet) > 400:
                            snippet = snippet[:400] + "..."
                        print(f"     {snippet}")
        elif args.kb_cmd == "remove":
            kb_name = args.kb_name
            if not args.force:
                confirmation = input(
                    f"Delete knowledge base '{kb_name}'? This cannot be undone. [y/N]: "
                ).strip()
                if confirmation.lower() not in {"y", "yes"}:
                    ui.info("Aborted knowledge base removal.")
                    return
            try:
                remove_kb(kb_name)
                ui.success(f"Removed knowledge base '{kb_name}'.")
            except KnowledgeBaseError as e:
                ui.error("KB removal failed", str(e))
                sys.exit(2)

    elif args.cmd == "diff":
        start_time = time.time()

        # Set verbose mode
        set_verbose(args.verbose)

        # Check for required API keys/credentials
        if args.llm_api.lower() == "openai" and not os.getenv("OPENAI_API_KEY"):
            ui.error(
                "OPENAI_API_KEY is not set",
                "Please set your OpenAI API key in environment variables",
            )
            sys.exit(2)
        elif args.llm_api.lower() == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
            ui.error(
                "ANTHROPIC_API_KEY is not set",
                "Please set your Anthropic API key in environment variables",
            )
            sys.exit(2)
        elif args.llm_api.lower() == "bedrock":
            if not args.aws_profile and not (
                os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
            ):
                ui.warning(
                    "AWS credentials not fully configured",
                    "For bedrock API, either set --aws-profile or AWS environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)",
                )

        ui.info(f"Comparing reports: {args.before} → {args.after}")

        thinking = ui.create_thinking_indicator("AI is analyzing report differences")
        thinking.start()

        try:
            d = diff_reports(
                args.after,
                args.before,
                args.llm_api,
                args.llm_model,
                args.aws_profile,
                args.aws_region,
                args.lang,
            )
            thinking.stop()

            # Show summary of changes
            graph_changes = d.get("graph_changes", {})
            threat_changes = d.get("threat_changes", {})

            ui.success("Diff analysis completed")
            ui.info("Changes summary:")
            print(
                f"  • Nodes: +{graph_changes.get('count_nodes_added', 0)} -{graph_changes.get('count_nodes_removed', 0)}"
            )
            print(
                f"  • Edges: +{graph_changes.get('count_edges_added', 0)} -{graph_changes.get('count_edges_removed', 0)}"
            )
            print(
                f"  • Threats: +{threat_changes.get('count_added', 0)} -{threat_changes.get('count_removed', 0)}"
            )

            s = json.dumps(d, ensure_ascii=False, indent=2)
            if args.out_json:
                with open(args.out_json, "w", encoding="utf-8") as f:
                    f.write(s)
                ui.success(f"Diff JSON saved to: {args.out_json}")

            if args.out_md:
                md_output = export_diff_md(d, args.out_md)
                ui.success(f"Diff Markdown saved to: {args.out_md}")
                if args.verbose:
                    print("\nMarkdown diff output:")
                    print(md_output)

            if args.verbose:
                print("\nJSON diff output:")
                print(s)

        except Exception as e:
            thinking.stop()
            ui.error("Failed to generate diff", str(e))
            sys.exit(2)

        end_time = time.time()
        processing_time = end_time - start_time
        ui.info(f"Diff completed in {processing_time:.1f}s")
    elif args.cmd == "webui":
        ui.info("Starting Threat Thinker Web UI")
        import webui

        webui.launch_webui(
            server_name=args.host,
            server_port=args.port,
        )


if __name__ == "__main__":
    main()
