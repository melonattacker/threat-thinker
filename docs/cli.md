# CLI Quick Reference

Common flags used in `threat-thinker` commands.

| Flag | Purpose | Notes |
| --- | --- | --- |
| `--mermaid / --drawio / --threat-dragon / --ir / --image / --diagram` | Choose input format | Mermaid `.mmd/.mermaid`, Draw.io `.xml`, Threat Dragon v2 `.json`, native Graph IR `.json`, image files, or generic `--diagram` autodetect (recognizes Threat Dragon JSON when version is 2.x). |
| `--drawio-page <id|name|index>` | Select Draw.io page to parse | Optional; supports page id, page name, or 0-based index for multi-page `.drawio` files. |
| `--infer-hints` | Ask LLM to infer node/edge attributes | Combine with `--hints` to override specific fields. |
| `--hints <path>` | Apply custom `hint.yaml` | Used after inference; can add missing nodes/edges. |
| `--context <path>` | Inject business context into the threat prompt | Repeat for multiple PDF, Markdown, or text files. Unlike RAG, each file's extracted full text is included directly. |
| `--prompt-token-limit <n>` | Fail before analysis if the assembled prompt is too large | Applies to graph, context documents, RAG snippets, and instructions. No truncation is performed. |
| `--rag --kb <name>` | Enable local KB retrieval | Requires a built KB; pairs with `--rag-topk`. |
| `--rag-topk <n>` | Set number of KB chunks to inject | Typical 5–10. |
| `--rag-strategy <hybrid|dense>` | Select retrieval strategy | Default `hybrid` (dense+sparse+rerank+MMR). |
| `--rag-reranker <auto|local|llm|off>` | Select reranker backend | Default `auto` (local cross-encoder, fallback LLM). |
| `--rag-candidates <n>` | Candidate pool before rerank/MMR | Default 40. |
| `--rag-min-score <0..1>` | Drop weak retrieval results | Applied after reranking normalization. |
| `--require-asvs` | Ensure each threat has ASVS references | Helpful for compliance-driven runs. |
| `--lang <code>` | Set output language | ISO language code (e.g., `en`, `ja`). |
| `--topn <n>` | Limit number of threats | Default top critical findings; keep ≤12 for clarity. |
| `--llm-api / --llm-model` | Pick provider/model | `openai`, `anthropic`, `bedrock`, or `ollama` (text-only). Example: `--llm-api ollama --llm-model llama3.1`. |
| `--ollama-host <url>` | Set Ollama host | Defaults to `http://localhost:11434` or env `OLLAMA_HOST`; ignored for other providers. |
| `--out-dir <path>` | Where to write reports | Defaults to current directory. |
| `--out-name <basename>` | Override base filename | Affects `*_report.{json,md,html}` and diff outputs. |

Notes:
- Ollama backend does not support image inputs; use Mermaid/Draw.io/Threat Dragon files with `--llm-api ollama`.
- Native IR JSON is explicit-only in v1; use `--ir` or API/UI `type=ir`, not `--diagram`.
- RAG requires OpenAI embeddings; set `OPENAI_API_KEY` when using `--rag`.
- Use `--context` for scope, actors, assets, and business assumptions that should always be visible to the LLM. Use `--rag` for optional supporting references retrieved from larger KBs. They can be combined:

```bash
threat-thinker think \
    --mermaid examples/web/system.mmd \
    --context docs/business-scope.md \
    --context docs/safety-assumptions.pdf \
    --rag --kb secure-web --rag-topk 8 \
    --llm-api openai --llm-model gpt-4.1 \
    --out-dir reports/
```

Diff command specifics:
- `--before <report.json>` and `--after <report.json>` are required.
- Outputs are written as `<after_basename>_diff.{json,md}` unless `--out-name` is set.
- Use the same provider/model flags as `think` if LLM explanation is desired.

For full usage: run `threat-thinker --help` or `threat-thinker <subcommand> --help`.
