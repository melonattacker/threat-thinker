# Threat Thinker Agent Guide

This document describes how human contributors and AI assistants should operate inside this repository. Follow it whenever crafting code, tests, docs, or analyses so that new work is aligned with the architecture, workflows, and security expectations of Threat Thinker.

## 1. Mission & Scope
- Automate threat modeling from system diagrams (Mermaid, draw.io, raster images) and produce concise reports referencing OWASP ASVS/CWE items.
- Provide both CLI and Web UI entry points plus a local RAG layer for augmenting LLM reasoning with curated documents.
- Favor small, reviewable pull requests that include documentation and automated tests relevant to the change.

## 2. Architecture & File Layout
- `src/`
  - `main.py`: CLI parser/subcommands (`think`, `diff`, `kb`), orchestrates parsers → hint processors → LLM adapters → analyzers → exporters.
  - `cliui.py`: lightweight UI helpers and verbose logging toggles used by CLI and tests.
  - `webui.py`: Gradio-based UI wiring.
  - `parsers/`: diagram ingestion (`mermaid_parser.py`, `drawio_parser.py`, `image_parser.py`) plus helpers (e.g., OCR/extraction) — keep deterministic and side-effect free.
  - `hint_processor.py`: merges user hints with LLM-generated attributes.
  - `llm/`: provider-specific adapters, prompt builders, throttling/retry logic.
  - `threat_analyzer.py`: deduplicates/denoises threats, filters via thresholds, ensures ASVS references as requested.
  - `exporters.py`: Markdown/JSON exporters and diff helpers (`diff_reports`, `export_diff_md`).
  - `rag/`: local KB management (chunking, embedding, semantic retrieval).
  - `models.py`, `constants.py`: shared dataclasses and enums (always update type hints when data contracts change).
- `tests/`: mirrors `src/` package structure with pytest suites, fixtures, and golden files.
- `docs/`: architecture notes, tutorials, design specs (keep high-level rationale here, not operational findings).
- `examples/`: canonical diagrams (`.mmd`, `.xml`, `.png`) used by docs/tests.
- `reports/`: generated analysis artifacts in Markdown/JSON; never hand-edit these.
- `benchmarking/`: notebooks/scripts for perf or accuracy comparisons.
- Root configuration: `pyproject.toml`, `pytest.ini`, `requirements.txt`, `.ruff.toml` (via `[tool.ruff]` inside pyproject).

## 3. Development Workflow
1. **Environment**
   ```bash
   uv venv                         # create .venv if absent
   source .venv/bin/activate
   uv pip install -e . -r requirements.txt
   ```
   Use `pip install -e .` as a fallback if `uv` is unavailable.
2. **Credentials**: export one or more of `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or configure AWS credentials (`aws configure --profile ...` or `AWS_ACCESS_KEY_ID/...`) before running CLI/web UI features that contact LLMs.
3. **Iterate**
   - Run `ruff check src tests` and `ruff format` before committing.
   - Execute targeted pytest nodes during development (`pytest tests/parsers/test_mermaid_parser.py -k trust_boundary`) but always run `pytest` at the end.
   - When editing CLI flows, add fixtures to `tests/fixtures/` (e.g., diagrams, YAML hints) so regressions are reproducible offline.
4. **Artifacts**
   - CLI run:
     ```bash
     threat-thinker think \
         --mermaid examples/web/system.mmd \
         --infer-hints --topn 5 \
         --llm-api openai --llm-model gpt-4.1 \
         --format both \
         --out-md reports/web-report.md \
         --out-json reports/web-report.json
     ```
   - Diffing two reports:
     ```bash
     threat-thinker diff \
         --after reports/new-report.json \
         --before reports/old-report.json \
         --llm-api openai --llm-model gpt-4.1 \
         --out-md reports/diff.md --out-json reports/diff.json
     ```
   - RAG KB maintenance:
     ```bash
     threat-thinker kb build <kb_name> \
         --embedder openai:text-embedding-3-small \
         --chunk-tokens 800 --chunk-overlap 80
     threat-thinker kb search <kb_name> "lateral movement" --topk 5 --show
     threat-thinker think ... --rag --kb <kb_name> --rag-topk 8
     ```
   - Web UI launches via `threat-thinker webui` (Gradio on `http://localhost:7860`).
5. **Documentation & PRs**
   - Update `docs/` when interfaces, prompts, or architecture flows change.
   - Include CLI output screenshots or Markdown excerpts when UX is affected.
   - Commit messages stay short & imperative (`add kb search tests`, `fix drawio parser bounds`).

## 4. Coding Standards & Patterns
- Python 3.8+ with four-space indentation and full typing; prefer dataclasses for request/response payloads.
- Use descriptive `snake_case` for functions/variables and `PascalCase` for classes. Module docstrings summarize intent and key interactions.
- Keep prompt-building helpers pure – no file I/O or network calls in `llm/` prompt modules.
- Minimal but meaningful inline comments (e.g., explain unusual filtering logic or boundary conditions).
- Imports are auto-sorted by Ruff. Avoid wildcard imports.
- When adding new CLI options, update both `main.py` and README/tutorials for discoverability.
- Keep threat ranking logic deterministic: use sorted operations and explicit random seeds if randomness is unavoidable.

## 5. Testing Expectations
- Align new tests under `tests/<package>/test_<module>.py`. Mirror class/function names to ease tracing.
- Favor small deterministic fixtures under `tests/fixtures/` or `examples/`. Store diagram snippets, hints YAML, and stub LLM responses there.
- Mock network/LLM calls; integration tests should rely on recorded outputs instead of live providers.
- When modifying exporters/analyzers, verify Markdown/JSON snapshots (e.g., load fixture report and assert on sections/keys rather than entire files).
- Always run `pytest` before opening a PR; document any intentionally skipped tests with reasons.

## 6. Agent Behavior Guidelines
- **Understand before editing**: inspect relevant modules/tests prior to modification; summarize findings in PRs or assistant messages before proposing code.
- **Respect existing work**: never revert unrelated local changes. When encountering dirty files, coordinate with the author.
- **Safe command usage**: avoid destructive shell commands (`git reset --hard`, `rm -rf`, etc.) unless explicitly requested. Prefer `rg`, `pytest -k`, and targeted scripts.
- **Explain reasoning**: when proposing non-trivial code, provide rationale, risk assessment, and verification steps.
- **Validation first**: run local lint/tests whenever feasible; describe any gaps (e.g., network limits) so reviewers know what remains unverified.
- **Security & privacy**: never log or commit API keys, secrets, or sensitive diagram content. Generated threat reports belong in `reports/`, not `docs/`, unless sanitized for sharing.

## 7. Tooling & Integrations
- **LLM Providers**: support `openai`, `anthropic`, and `bedrock`. Ensure CLI defaults to `gpt-4o-mini` unless the user specifies `--llm-model`. When adding providers/models, document credential requirements and update inference adapters.
- **Knowledge Base (RAG)**: data lives under `~/.threat-thinker/kb/<name>/{raw,chunks,index}` (see `rag/`). Guard against corrupt KBs by raising `KnowledgeBaseError`.
- **Export Surfaces**: Markdown output is consumed by reviewers, JSON output feeds automation. Maintain schema stability: version keys in JSON and reflect changes in tests.
- **CLI/Web UI**: keep parameter naming consistent between CLI flags and Web UI components. Whenever CLI adds a flag, determine whether Web UI needs parity.
- **Benchmarks**: store notebooks/scripts in `benchmarking/` and keep dependencies optional; document reproduction steps if numbers appear in README/docs.

## 8. Examples & Playbooks
- **Add parser support for a new diagram property**
  1. Extend parser module (`src/parsers/...`) with deterministic extraction logic.
  2. Update relevant dataclasses in `models.py`.
  3. Adapt hint merging logic (`hint_processor.py`) to respect the new property.
  4. Write parser + analyzer tests plus an exporter snapshot if output changes.
  5. Document the property in README/tutorials.
- **Create a new RAG knowledge base**
  1. Place PDFs/Markdown in `~/.threat-thinker/kb/<kb_name>/raw/`.
  2. Run `threat-thinker kb build <kb_name> --embedder openai:text-embedding-3-small`.
  3. Validate with `threat-thinker kb search`.
  4. Reference it via `--rag --kb <kb_name> --rag-topk <n>` in CLI commands.
- **Compare two threat runs**
  1. Collect JSON outputs for both versions.
  2. Run `threat-thinker diff --after ... --before ... --out-md ... --out-json ...`.
  3. Review Markdown diff for narrative, JSON for automation/regression detection.

## 9. Anti-Patterns & Failure Modes
- Skipping lint/tests before submitting (CI will fail and wastes reviewer time).
- Bypassing hint merging/denoising layers and sending raw diagram data directly to LLM adapters.
- Adding prompts or export templates with hidden coupling (e.g., referencing non-existent fields) without corresponding tests.
- Hardcoding provider credentials or embedding sample API keys anywhere in the repo.
- Generating reports or fixtures outside repo boundaries; tests need deterministic, versioned assets inside `tests/fixtures/` or `examples/`.
- Overloading AGENTS.md with project history or marketing copy; keep this document operational and concise.

Refer back to this guide whenever onboarding new contributors, updating automation, or coordinating AI assistance. Consistency here ensures Threat Thinker remains predictable, testable, and secure.
