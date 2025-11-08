# Repository Guidelines

## Project Structure & Module Organization
`src/` contains the application packages (CLI entry point, UI layers, parsers, LLM adapters, analyzers, exporters). `tests/` mirrors those packages with pytest suites and fixtures. `docs/` stores design docs, architecture notes, and tutorials; `examples/` holds reference diagrams in Mermaid, draw.io, and image formats; `reports/` is reserved for generated findings in Markdown/JSON. Root-level files such as `pyproject.toml`, `requirements.txt`, and `pytest.ini` define packaging, dependencies, and test configuration.

## Build, Test, and Development Commands
```bash
pip install -e . -r requirements.txt   # editable install plus tooling deps
ruff check src tests                   # static checks + formatting hints
pytest                                 # run the full automated test suite
threat-thinker think --mermaid examples/web/system.mmd --infer-hints --topn 5 \
  --llm-api openai --llm-model gpt-4.1 --format both --out-md reports/report.md
threat-thinker webui                   # launch Gradio UI on http://localhost:7860
```

## Coding Style & Naming Conventions
Code is Python 3.8+ with 4-space indentation, type hints, and dataclass-backed models (`models.py`). Favor descriptive `snake_case` for functions and variables, `PascalCase` for classes, and module-level docstrings that explain intent. Keep prompt strings, filters, and serializer helpers pure and side-effect free. Use Ruff both as linter and formatter (`ruff format`) before submitting; keep imports ordered automatically. Embed short comments only where control flow is non-obvious (e.g., threat deduping).

## Testing Guidelines
Write new tests under `tests/` using pytest naming (`test_<module>.py` and `test_<behavior>_...`). Target logical units such as parsers, LLM adapters, and exporters; when patching CLI flows, add integration-style tests that exercise command functions with fixtures. Maintain coverage of new data paths and include representative diagrams or JSON snippets under `tests/fixtures/` or `examples/` when needed. Always run `pytest` locally; use `-k` filters for focused debugging but rerun the suite before opening a PR.

## Commit & Pull Request Guidelines
Follow the existing short, imperative commit style (`fix README`, `add cliui`). Each commit should be scoped to one concern and include updates to docs/tests. Pull requests should describe motivation, summarize functional changes, note testing performed, and link related issues. Attach screenshots or CLI output when UX changes occur, and mention any new environment variables or commands. Keep PRs small enough for a focused review and ensure lint/test checks pass in CI.

## Security & Configuration Notes
Threat Thinker depends on LLM provider credentials. Never commit keys; load them via `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or AWS environment variables/profile before running CLI or Web UI commands. When sharing reports, scrub sensitive diagram content and threat evidence, and store generated artifacts under `reports/` rather than `docs/` unless they are intended for publication.
