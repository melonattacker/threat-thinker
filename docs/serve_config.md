# Serve/Worker Config YAML Guide

`threat-thinker serve` and `threat-thinker worker` load the same YAML configuration file.
This guide documents the schema defined in `src/threat_thinker/serve/config.py` and uses
`examples/demo-app/serve.example.yaml` as a sample starting point, not a mandatory template.

> [!WARNING]
> `serve` and `worker` are intended for internal or private network use only.
> They are not designed to be exposed on the public internet.

## 1. How to Load the Config

```bash
threat-thinker serve --config examples/demo-app/serve.example.yaml
threat-thinker worker --config examples/demo-app/serve.example.yaml
```

- `serve` starts the HTTP API server.
- `worker` pulls analysis jobs from the Redis queue.

## 2. Environment Variables and List Syntax

### 2.1 Environment Variable Expansion
All string values in YAML are expanded for environment variables.

- `${VAR}`: empty string if unset.
- `${VAR:-default}`: uses `default` if unset.
- `$VAR` is also supported (via `os.path.expandvars`).

Example:
```yaml
queue:
  redis_url: "${REDIS_URL:-redis://localhost:6379/0}"
security:
  auth:
    api_keys: "${SERVE_API_KEYS}"
```

### 2.2 List Values
Lists such as `allow_origins` and `api_keys` accept YAML arrays or comma-separated strings.

```yaml
security:
  auth:
    api_keys:
      - "key-a"
      - "key-b"

# Or
security:
  auth:
    api_keys: "key-a,key-b"
```

## 3. Top-Level Sections

The root YAML sections are:

- `server`
- `security`
- `queue`
- `engine`
- `observability`

Missing values fall back to defaults in `config.py`. The only hard requirement is that
**API keys must be provided when `security.auth.mode = api_key`** (see below).

### 3.1 server
Bind address, port, and OpenAPI UI exposure.

```yaml
server:
  bind: "0.0.0.0"
  port: 8000
  cors:
    enabled: false
    allow_origins: []    # Example: ["https://example.com"]
  openapi:
    enabled: true
    docs_enabled: true   # /docs
    redoc_enabled: true  # /redoc
```

### 3.2 security
Authentication, rate limits, request caps, timeouts, and concurrency limits.

```yaml
security:
  auth:
    mode: "api_key"          # none | api_key
    scheme: "bearer"         # bearer | header
    header_name: "Authorization"
    api_keys: "${SERVE_API_KEYS}"
  rate_limit:
    enabled: true
    scope: "ip"               # ip | api_key
    requests_per_minute: 10
  request_limits:
    max_body_bytes: 8000000
    max_files: 1
    max_text_chars: 200000
    allowed_image_types:
      - "image/png"
      - "image/jpeg"
      - "image/webp"
    max_image_bytes: 4000000
  timeouts:
    analyze_seconds: 90
  concurrency:
    max_in_flight_per_worker: 1
```

Notes:
- When `auth.mode = api_key`, `api_keys` is required.
  - Provide it in YAML or via `SERVE_API_KEYS` or `SERVE_API_KEY`.
- With `auth.scheme = bearer`, clients must send `Authorization: Bearer <token>`.
- `rate_limit.scope = api_key` applies rate limiting per API key.

### 3.3 queue
Job queue settings. Only **Redis is supported** at the moment.

```yaml
queue:
  backend: "redis"
  redis_url: "${REDIS_URL}"            # Defaults to redis://localhost:6379/0
  queue_key: "tt:queue"
  job_key_prefix: "tt:job"
  job_ttl_seconds: 900
```

Note:
- `backend` values other than `redis` cause a startup error.

### 3.4 engine
Allowed inputs and LLM settings.

```yaml
engine:
  allowed_inputs:
    - "mermaid"
    - "drawio"
    - "threat-dragon"
    - "image"
  autodetect: true
  report:
    default_format: "markdown"    # markdown | json | html | both
    default_language: "ja"        # Example: en, ja
  model:
    provider: "openai"            # openai | anthropic | bedrock | ollama
    name: "gpt-4.1-mini"
    params:
      temperature: 0.2
      max_output_tokens: 1200
    aws_profile: null             # For bedrock
    aws_region: null              # For bedrock
    ollama_host: null             # For ollama
```

Notes:
- `allowed_inputs` supports YAML arrays or comma-separated strings.
- `report.default_language` mirrors the CLI `--lang` option.
- `model.params` is passed directly to the provider adapter.

### 3.5 observability
Logging level and redaction policy.

```yaml
observability:
  log_level: "info"         # debug | info | warning | error
  redact:
    input_content: true
    result_content: true
```

## 4. Minimal Example

If you keep API key auth enabled, you must provide API keys. Everything else can default.

```yaml
security:
  auth:
    mode: "api_key"
    api_keys: "${SERVE_API_KEYS}"
```

## 5. Full Example (Sample)

`examples/demo-app/serve.example.yaml` is a **sample** that demonstrates all fields. Use it as a
starting point and override only what you need for your environment.

```yaml
server:
  bind: "0.0.0.0"
  port: 8000
  cors:
    enabled: true
    allow_origins:
      - "https://app.example.com"
  openapi:
    enabled: true
    docs_enabled: false
    redoc_enabled: false

security:
  auth:
    mode: "api_key"
    scheme: "bearer"
    header_name: "Authorization"
    api_keys: "${SERVE_API_KEYS}"
  rate_limit:
    enabled: true
    scope: "api_key"
    requests_per_minute: 30
  request_limits:
    max_body_bytes: 8000000
    max_files: 1
    max_text_chars: 200000
    allowed_image_types:
      - "image/png"
      - "image/jpeg"
      - "image/webp"
    max_image_bytes: 4000000
  timeouts:
    analyze_seconds: 120
  concurrency:
    max_in_flight_per_worker: 2

queue:
  backend: "redis"
  redis_url: "${REDIS_URL:-redis://localhost:6379/0}"
  queue_key: "tt:queue"
  job_key_prefix: "tt:job"
  job_ttl_seconds: 900

engine:
  allowed_inputs: "mermaid,drawio,threat-dragon,image"
  autodetect: true
  report:
    default_format: "markdown"
    default_language: "ja"
  model:
    provider: "openai"
    name: "gpt-4.1-mini"
    params:
      temperature: 0.2
      max_output_tokens: 1200

observability:
  log_level: "info"
  redact:
    input_content: true
    result_content: true
```

## 6. Common Startup Errors
- `security.auth.mode: api_key` with no API keys configured results in a startup error.
- `queue.backend` values other than `redis` result in a startup error.

If you are unsure, start from `examples/demo-app/serve.example.yaml` and apply minimal overrides.
