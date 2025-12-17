"""
Configuration loader for `threat-thinker serve` and `worker`.

Keeps a minimal set of defaults while allowing environment variable expansion
inside YAML (e.g., `${REDIS_URL}` or `${SERVE_API_KEYS}`).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

DEFAULT_ALLOWED_INPUTS = ["mermaid", "drawio", "threat_dragon", "image"]
DEFAULT_ALLOWED_IMAGE_TYPES = ["image/png", "image/jpeg", "image/webp"]


@dataclass
class OpenAPIConfig:
    enabled: bool = True
    docs_enabled: bool = False
    redoc_enabled: bool = False


@dataclass
class CorsConfig:
    enabled: bool = False
    allow_origins: List[str] = field(default_factory=list)


@dataclass
class ServerConfig:
    bind: str = "0.0.0.0"
    port: int = 8000
    cors: CorsConfig = field(default_factory=CorsConfig)
    openapi: OpenAPIConfig = field(default_factory=OpenAPIConfig)


@dataclass
class AuthConfig:
    mode: str = "api_key"  # none | api_key
    scheme: str = "bearer"  # bearer | header
    header_name: str = "Authorization"
    api_keys: List[str] = field(default_factory=list)


@dataclass
class RateLimitConfig:
    enabled: bool = True
    scope: str = "ip"  # ip | api_key
    requests_per_minute: int = 10


@dataclass
class RequestLimitsConfig:
    max_body_bytes: int = 8_000_000
    max_files: int = 1
    max_text_chars: int = 200_000
    allowed_image_types: List[str] = field(
        default_factory=lambda: list(DEFAULT_ALLOWED_IMAGE_TYPES)
    )
    max_image_bytes: int = 4_000_000


@dataclass
class TimeoutConfig:
    analyze_seconds: int = 90


@dataclass
class ConcurrencyConfig:
    max_in_flight_per_worker: int = 1


@dataclass
class SecurityConfig:
    auth: AuthConfig = field(default_factory=AuthConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    request_limits: RequestLimitsConfig = field(default_factory=RequestLimitsConfig)
    timeouts: TimeoutConfig = field(default_factory=TimeoutConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)


@dataclass
class QueueConfig:
    backend: str = "redis"
    redis_url: str = "redis://localhost:6379/0"
    queue_key: str = "tt:queue"
    job_key_prefix: str = "tt:job"
    job_ttl_seconds: int = 900


@dataclass
class ReportConfig:
    default_format: str = "markdown"
    default_language: str = "en"


@dataclass
class ModelConfig:
    provider: str = "openai"
    name: str = "gpt-4.1-mini"
    params: Dict[str, Any] = field(default_factory=dict)
    aws_profile: Optional[str] = None
    aws_region: Optional[str] = None
    ollama_host: Optional[str] = None


@dataclass
class EngineConfig:
    allowed_inputs: List[str] = field(
        default_factory=lambda: list(DEFAULT_ALLOWED_INPUTS)
    )
    autodetect: bool = True
    report: ReportConfig = field(default_factory=ReportConfig)
    model: ModelConfig = field(default_factory=ModelConfig)


@dataclass
class RedactConfig:
    input_content: bool = True
    result_content: bool = True


@dataclass
class ObservabilityConfig:
    log_level: str = "info"
    redact: RedactConfig = field(default_factory=RedactConfig)


@dataclass
class ServeConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    queue: QueueConfig = field(default_factory=QueueConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    observability: ObservabilityConfig = field(default_factory=ObservabilityConfig)


def _expand_env(obj: Any) -> Any:
    """Recursively expand environment variables within strings.

    Supports ${VAR} and ${VAR:-default}. Unset variables without a default become "".
    """

    def _expand_string(value: str) -> str:
        pattern = re.compile(r"\$\{([^}:]+)(:-([^}]+))?\}")

        def repl(match: re.Match[str]) -> str:
            var_name = match.group(1)
            default = match.group(3)
            return os.getenv(var_name, default or "")

        return pattern.sub(repl, os.path.expandvars(value))

    if isinstance(obj, str):
        return _expand_string(obj)
    if isinstance(obj, list):
        return [_expand_env(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _expand_env(v) for k, v in obj.items()}
    return obj


def _coerce_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(value).strip()]


def _load_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return _expand_env(data)


def _load_server(data: Dict[str, Any]) -> ServerConfig:
    srv = data.get("server", {}) or {}
    cors_data = srv.get("cors", {}) or {}
    openapi_data = srv.get("openapi", {}) or {}
    return ServerConfig(
        bind=srv.get("bind", "0.0.0.0"),
        port=int(srv.get("port", 8000)),
        cors=CorsConfig(
            enabled=bool(cors_data.get("enabled", False)),
            allow_origins=_coerce_list(cors_data.get("allow_origins")),
        ),
        openapi=OpenAPIConfig(
            enabled=bool(openapi_data.get("enabled", True)),
            docs_enabled=bool(openapi_data.get("docs_enabled", False)),
            redoc_enabled=bool(openapi_data.get("redoc_enabled", False)),
        ),
    )


def _load_security(data: Dict[str, Any]) -> SecurityConfig:
    sec = data.get("security", {}) or {}
    auth_data = sec.get("auth", {}) or {}
    rate_data = sec.get("rate_limit", {}) or {}
    limits_data = sec.get("request_limits", {}) or {}
    timeouts_data = sec.get("timeouts", {}) or {}
    conc_data = sec.get("concurrency", {}) or {}

    api_keys = _coerce_list(auth_data.get("api_keys"))
    mode = auth_data.get("mode", "api_key")
    if mode == "api_key" and not api_keys:
        env_keys = _coerce_list(os.getenv("SERVE_API_KEYS"))
        if not env_keys:
            env_keys = _coerce_list(os.getenv("SERVE_API_KEY"))
        api_keys = api_keys or env_keys
    return SecurityConfig(
        auth=AuthConfig(
            mode=mode,
            scheme=auth_data.get("scheme", "bearer"),
            header_name=auth_data.get("header_name", "Authorization"),
            api_keys=api_keys,
        ),
        rate_limit=RateLimitConfig(
            enabled=bool(rate_data.get("enabled", True)),
            scope=rate_data.get("scope", "ip"),
            requests_per_minute=int(rate_data.get("requests_per_minute", 10)),
        ),
        request_limits=RequestLimitsConfig(
            max_body_bytes=int(limits_data.get("max_body_bytes", 8_000_000)),
            max_files=int(limits_data.get("max_files", 1)),
            max_text_chars=int(limits_data.get("max_text_chars", 200_000)),
            allowed_image_types=_coerce_list(
                limits_data.get("allowed_image_types")
                or list(DEFAULT_ALLOWED_IMAGE_TYPES)
            ),
            max_image_bytes=int(limits_data.get("max_image_bytes", 4_000_000)),
        ),
        timeouts=TimeoutConfig(
            analyze_seconds=int(timeouts_data.get("analyze_seconds", 90))
        ),
        concurrency=ConcurrencyConfig(
            max_in_flight_per_worker=int(
                conc_data.get("max_in_flight_per_worker", 1)
            )
        ),
    )


def _load_queue(data: Dict[str, Any]) -> QueueConfig:
    q = data.get("queue", {}) or {}
    redis_url = q.get("redis_url") or os.getenv("REDIS_URL") or "redis://localhost:6379/0"
    return QueueConfig(
        backend=q.get("backend", "redis"),
        redis_url=redis_url,
        queue_key=q.get("queue_key", "tt:queue"),
        job_key_prefix=q.get("job_key_prefix", "tt:job"),
        job_ttl_seconds=int(q.get("job_ttl_seconds", 900)),
    )


def _load_engine(data: Dict[str, Any]) -> EngineConfig:
    eng = data.get("engine", {}) or {}
    report = eng.get("report", {}) or {}
    model = eng.get("model", {}) or {}
    allowed_inputs = _coerce_list(
        eng.get("allowed_inputs") or list(DEFAULT_ALLOWED_INPUTS)
    )
    if not allowed_inputs:
        allowed_inputs = list(DEFAULT_ALLOWED_INPUTS)
    return EngineConfig(
        allowed_inputs=allowed_inputs,
        autodetect=bool(eng.get("autodetect", True)),
        report=ReportConfig(
            default_format=report.get("default_format", "markdown"),
            default_language=report.get("default_language", "en"),
        ),
        model=ModelConfig(
            provider=model.get("provider", "openai"),
            name=model.get("name", "gpt-4.1-mini"),
            params=model.get("params", {}) or {},
            aws_profile=model.get("aws_profile"),
            aws_region=model.get("aws_region"),
            ollama_host=model.get("ollama_host"),
        ),
    )


def _load_observability(data: Dict[str, Any]) -> ObservabilityConfig:
    obs = data.get("observability", {}) or {}
    redact_data = obs.get("redact", {}) or {}
    return ObservabilityConfig(
        log_level=obs.get("log_level", "info"),
        redact=RedactConfig(
            input_content=bool(redact_data.get("input_content", True)),
            result_content=bool(redact_data.get("result_content", True)),
        ),
    )


def load_config(path: str) -> ServeConfig:
    """
    Load serve configuration from YAML file.

    Raises:
        FileNotFoundError: when path does not exist
        ValueError: when required sections are missing
    """
    data = _load_yaml(path)
    cfg = ServeConfig(
        server=_load_server(data),
        security=_load_security(data),
        queue=_load_queue(data),
        engine=_load_engine(data),
        observability=_load_observability(data),
    )
    if cfg.security.auth.mode == "api_key" and not cfg.security.auth.api_keys:
        raise ValueError(
            "API key authentication is enabled but no API keys are configured. "
            "Set security.auth.api_keys or SERVE_API_KEYS."
        )
    if cfg.queue.backend != "redis":
        raise ValueError("Only Redis queue backend is supported in the serve MVP.")
    return cfg
