# CLI Quick Reference

Common flags used in `threat-thinker` commands.

| Flag | Purpose | Notes |
| --- | --- | --- |
| `--mermaid / --drawio / --threat-dragon / --image / --diagram` | Choose input format | Mermaid `.mmd/.mermaid`, Draw.io `.xml`, Threat Dragon v2 `.json`, image files, or generic `--diagram` autodetect (recognizes Threat Dragon JSON when version is 2.x). |
| `--infer-hints` | Ask LLM to infer node/edge attributes | Combine with `--hints` to override specific fields. |
| `--hints <path>` | Apply custom `hint.yaml` | Used after inference; can add missing nodes/edges. |
| `--rag --kb <name>` | Enable local KB retrieval | Requires a built KB; pairs with `--rag-topk`. |
| `--rag-topk <n>` | Set number of KB chunks to retrieve | Typical 5–10. |
| `--require-asvs` | Ensure each threat has ASVS references | Helpful for compliance-driven runs. |
| `--lang <code>` | Set output language | ISO language code (e.g., `en`, `ja`). |
| `--topn <n>` | Limit number of threats | Default top critical findings; keep ≤12 for clarity. |
| `--llm-api / --llm-model` | Pick provider/model | `openai`, `anthropic`, `bedrock`, or `ollama` (text-only). Example: `--llm-api ollama --llm-model llama3.1`. |
| `--ollama-host <url>` | Set Ollama host | Defaults to `http://localhost:11434` or env `OLLAMA_HOST`; ignored for other providers. |
| `--out-dir <path>` | Where to write reports | Defaults to current directory. |
| `--out-name <basename>` | Override base filename | Affects `*_report.{json,md,html}` and diff outputs. |

Notes:
- Ollama backend does not support image inputs; use Mermaid/Draw.io/Threat Dragon files with `--llm-api ollama`.
- RAG requires OpenAI embeddings; set `OPENAI_API_KEY` when using `--rag`.

Diff command specifics:
- `--before <report.json>` and `--after <report.json>` are required.
- Outputs are written as `<after_basename>_diff.{json,md}` unless `--out-name` is set.
- Use the same provider/model flags as `think` if LLM explanation is desired.

For full usage: run `threat-thinker --help` or `threat-thinker <subcommand> --help`.
