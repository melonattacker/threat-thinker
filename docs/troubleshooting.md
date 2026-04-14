# Troubleshooting & Safety Notes

## Common Issues
- **Missing API keys**: Ensure `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or AWS credentials are set before runs.
- **Diff inputs**: `threat-thinker diff` requires JSON reports (not Markdown/HTML) for `--before` and `--after`.
- **KB not found / empty**: Verify KB name matches `~/.threat-thinker/kb/<name>/`; run `kb build` after adding files to `raw/`.
- **No threats identified**: Check diagram quality and business context; consider `--infer-hints` and `--require-asvs` only if applicable.
- **LLM errors/rate limits**: Retry with a smaller `--topn` or switch provider/model; ensure network access/quotas.

## Security & Privacy
- Do not place secrets, keys, or credentials in diagrams, business context, or KB documents.
- Generated reports may contain sensitive architecture details; handle and store them accordingly.
- Source docs for RAG stay local, but inference uses your configured remote LLM provider.

## Web UI Tips
- Reports are available via the download buttons after a run; they are written to a temporary path.
- Upload business context documents when the diagram needs additional scope, asset, or workflow assumptions.
