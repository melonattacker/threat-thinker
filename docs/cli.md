# CLI Quick Reference

Common flags used in `threat-thinker` commands.

| Flag | Purpose | Notes |
| --- | --- | --- |
| `--mermaid / --drawio / --image / --diagram` | Choose input format | Mermaid `.mmd/.mermaid`, Draw.io `.xml`, image files, or generic `--diagram` autodetect. |
| `--infer-hints` | Ask LLM to infer node/edge attributes | Combine with `--hints` to override specific fields. |
| `--hints <path>` | Apply custom `hint.yaml` | Used after inference; can add missing nodes/edges. |
| `--rag --kb <name>` | Enable local KB retrieval | Requires a built KB; pairs with `--rag-topk`. |
| `--rag-topk <n>` | Set number of KB chunks to retrieve | Typical 5–10. |
| `--require-asvs` | Ensure each threat has ASVS references | Helpful for compliance-driven runs. |
| `--lang <code>` | Set output language | ISO language code (e.g., `en`, `ja`). |
| `--topn <n>` | Limit number of threats | Default top critical findings; keep ≤12 for clarity. |
| `--llm-api / --llm-model` | Pick provider/model | E.g., `openai gpt-4.1` or Anthropic/Bedrock variants. |
| `--out-dir <path>` | Where to write reports | Defaults to current directory. |
| `--out-name <basename>` | Override base filename | Affects `*_report.{json,md,html}` and diff outputs. |

Diff command specifics:
- `--before <report.json>` and `--after <report.json>` are required.
- Outputs are written as `<after_basename>_diff.{json,md}` unless `--out-name` is set.
- Use the same provider/model flags as `think` if LLM explanation is desired.

For full usage: run `threat-thinker --help` or `threat-thinker <subcommand> --help`.
