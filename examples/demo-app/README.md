# Threat Thinker Demo App

This demo app provides a simple, modern UI for Threat Thinker that keeps backend API keys server-side. It runs a demo proxy (FastAPI), the Threat Thinker `serve` API, a worker, and Redis via Docker Compose.

## What it does
- Browser UI for Mermaid, draw.io XML, or Threat Dragon JSON (text-only).
- Proxy adds the backend API key and forces reports to `markdown` + `html`.
- Markdown is shown on-screen with a sanitized HTML preview.
- HTML report can be downloaded as a file.

## Prerequisites
- Docker + Docker Compose
- One of the LLM provider API keys (OpenAI/Anthropic/AWS) for the backend `serve` container.

## Quick start
1. Set environment variables (example using OpenAI):

   ```bash
   export OPENAI_API_KEY=your_key_here
   export SERVE_API_KEYS=tt-demo-key
   export DEMO_RATE_LIMIT_RPM=20
   ```

2. Start the demo stack:

   ```bash
   docker compose -f examples/demo-app/compose.yaml up --build
   ```

3. Open the UI:

   ```text
   http://localhost:8081
   ```

## Environment variables

### Proxy
- `TT_BACKEND_URL` (default `http://server:8000`)
- `TT_BACKEND_API_KEY` (set automatically from `SERVE_API_KEYS` in compose)
- `DEMO_RATE_LIMIT_RPM` (optional, default 20)
- `DEMO_MAX_INPUT_CHARS` (optional, default 200000)
- `DEMO_MAX_BODY_BYTES` (optional, default 400000)

### Backend (serve/worker)
- `SERVE_API_KEYS` (Bearer API key for Threat Thinker serve)
- `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` or AWS credentials

## Usage notes
- Only the proxy is exposed on port 8081. The backend server/worker/redis are internal to the compose network.
- The UI fetches Markdown/HTML from the proxy and sanitizes HTML previews with DOMPurify.
- The UI loads `marked` and `dompurify` from a CDN. If you need an air-gapped demo, vendor these files and update `index.html`.

## Troubleshooting
- If jobs never complete, check the worker container logs and ensure your LLM API keys are set.
- If you see 401 errors, make sure `SERVE_API_KEYS` matches the proxy `TT_BACKEND_API_KEY`.
