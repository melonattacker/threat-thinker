# Benchmarking Harness

This folder bundles small, reproducible diagrams plus evaluation helpers for measuring
`threat-thinker think` precision/recall.

## Layout

- `aws/`, `rag/`, `web/` &mdash; individual benchmark scenarios.  
  Each folder contains a Mermaid diagram (`system.mmd`) and an `expected_threats.json`
  descriptor with the threats the model should raise.
- `scripts/bench_metrics.py` &mdash; driver that runs the CLI, applies detection rules,
  and prints metrics.

## `expected_threats.json`

Every scenario describes the diagram to use and a list of expectations:

```json
{
  "scenario": "aws",
  "diagram": "benchmarking/aws/system.mmd",
  "expected": [
    {
      "id": "G1",
      "title": "Public S3 Bucket Exposure",
      "components": ["s3"],
      "why": "Misconfigured S3 bucket permissions may allow public access…",
      "detection": {
        "threshold": 0.6
      }
    }
  ]
}
```

During evaluation the expectation `title` and `why` strings are embedded with OpenAI's
embedding API and compared against every threat's `title`/`why` text using cosine similarity.
Matching fields are fixed to those two columns for both expectations and outputs. Use the
`detection.threshold`/`detection.similarity_threshold` overrides (or omit the `detection`
block entirely) to tweak how strict a given expectation should be. Semantic similarity alone
controls whether a match is counted; make sure `OPENAI_API_KEY` is configured before running
the benchmark mode.

## Running Metrics

```bash
python benchmarking/scripts/bench_metrics.py \
  --llm-api openai \
  --llm-model gpt-4.1 \
  --scenarios web \
  --topn 5 \
  --report-dir reports/benchmarks \
  --json \
  --out-file reports/benchmarks/metrics.json
```

- Use `--scenarios aws web` to focus on a subset.
- Pass `--diagram-file system.png` (relative to each scenario directory) to benchmark
  alternative diagram exports such as PNG or XML files.
- Reports from `threat-thinker think` land in `reports/benchmarks/<scenario>.json`.
- Pass `--json` to capture machine-readable output.
- Add `--out-file reports/benchmarks/metrics.txt` to mirror the CLI output into a file.
- Use `--similarity-threshold 0.55` (default `0.6`) to tune how strict the cosine-similarity
  filter is, and `--embedding-model` to point at a different OpenAI embedding model
  (default `text-embedding-3-large`). Provide an `OPENAI_API_KEY` in the environment so
  embeddings can be computed.

Set `--manual` to fall back to the legacy "enter counts" mode if you just want the
metric formulas.
