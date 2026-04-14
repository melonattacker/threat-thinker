# Knowledge Base (RAG) Guide

Threat Thinker can enrich LLM reasoning with a local knowledge base (KB) so findings reflect your standards (OWASP, MITRE, internal controls). KBs live under `~/.threat-thinker/kb/<kb_name>/`.

RAG is different from `think --context`. Use `--context` for required business context such as scope, actors, assets, assumptions, and safety or operational constraints; Threat Thinker injects the full extracted text of those PDF, Markdown, or text files directly into the threat prompt. Use `--rag` for larger reference collections where only the most relevant chunks should be retrieved. Both can be enabled in the same run.

> Note: Source documents stay local, but inference still calls your configured remote LLM provider. This is not a fully offline flow.

## When to Use RAG
- You need threat inference to consider external standards such as OWASP, MITRE, or NIST in addition to the diagram.
- You want to reinforce analysis with internal threat modeling guidelines or system-specific docs (designs, runbooks) so outputs match your environment.
- You want consistent ASVS/CWE/contextual recommendations across teams without pasting long guidance into each prompt.

## Directory Layout
```
~/.threat-thinker/kb/<kb_name>/
  raw/            # source docs you place (PDF/MD/HTML/TXT)
  chunks.jsonl    # chunk records + sparse stats (auto-generated)
  embeddings.npy  # dense vectors (auto-generated)
  meta.json       # build metadata (auto-generated)
```

## Build a KB
```bash
# Place source docs under raw/
mkdir -p ~/.threat-thinker/kb/secure-web/raw
cp docs/*.md ~/.threat-thinker/kb/secure-web/raw/

# Build embeddings (OpenAI example)
threat-thinker kb build secure-web \
    --embedder openai:text-embedding-3-small \
    --chunk-tokens 800 --chunk-overlap 80
```
Notes:
- Supported embedders: OpenAI (text-embedding-3-small, text-embedding-3-large). Add others as implemented.
- Re-run `kb build` whenever you change files in `raw/`.
- If build fails, check API credentials and that files are readable.

## Inspect or Search
```bash
# List KBs
threat-thinker kb list

# Search
threat-thinker kb search secure-web "api" --topk 5 --show
```

## Use RAG During Analysis
CLI:
```bash
threat-thinker think \
    --mermaid diagram.mmd \
    --rag --kb secure-web --rag-topk 8 \
    --rag-strategy hybrid --rag-reranker auto \
    --rag-candidates 40 --rag-min-score 0.25 \
    --llm-api openai --llm-model gpt-4.1 \
    --out-dir reports/
```
Web UI:
- Upload docs in the **Knowledge Base** tab, click **Build KB**, then select the KB on the Think tab.
- Enable **Use Knowledge Base (local RAG)** and set Top-k to control how many chunks are retrieved.

## Tips
- Keep KBs focused (per domain/product) for more relevant retrieval.
- Chunk sizes: 600–900 tokens with 10–15% overlap works well; adjust if you see truncated sentences.
- Avoid placing secrets or proprietary keys in KB content.
- Version KBs alongside architecture diagrams to reproduce results.
- If a KB is corrupted, rebuild by re-running `kb build` (or delete `chunks.jsonl`, `embeddings.npy`, and `meta.json` first).

## Troubleshooting
- "KB not found": confirm the name matches directory under `~/.threat-thinker/kb/`.
- "No chunks indexed": ensure files exist in `raw/` before building.
- Retrieval seems irrelevant: tune `--rag-topk`, `--rag-candidates`, `--rag-min-score`, or switch strategy/reranker.
