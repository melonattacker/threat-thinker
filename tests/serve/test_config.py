import os
from pathlib import Path

from threat_thinker.serve.config import load_config


def test_load_config_expands_env(tmp_path: Path, monkeypatch):
    config_path = tmp_path / "serve.yaml"
    config_path.write_text(
        """
security:
  auth:
    api_keys: "${SERVE_API_KEYS}"
queue:
  redis_url: "${REDIS_URL}"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("SERVE_API_KEYS", "key1,key2")
    monkeypatch.setenv("REDIS_URL", "redis://example:6379/1")

    cfg = load_config(str(config_path))
    assert cfg.security.auth.api_keys == ["key1", "key2"]
    assert cfg.queue.redis_url == "redis://example:6379/1"
    assert "mermaid" in cfg.engine.allowed_inputs


def test_load_config_single_api_key_env(tmp_path: Path, monkeypatch):
    config_path = tmp_path / "serve.yaml"
    config_path.write_text("{}", encoding="utf-8")
    monkeypatch.delenv("SERVE_API_KEYS", raising=False)
    monkeypatch.setenv("SERVE_API_KEY", "solo-key")

    cfg = load_config(str(config_path))
    assert cfg.security.auth.api_keys == ["solo-key"]


def test_generic_env_expansion(tmp_path: Path, monkeypatch):
    config_path = tmp_path / "serve.yaml"
    config_path.write_text(
        """
security:
  auth:
    api_keys: "${SERVE_API_KEYS}"
queue:
  redis_url: "${CUSTOM_REDIS_URL:-redis://fallback:6379/0}"
engine:
  model:
    name: "${MODEL_NAME}"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("SERVE_API_KEYS", "keyA,keyB")
    monkeypatch.setenv("CUSTOM_REDIS_URL", "redis://custom:6380/2")
    monkeypatch.setenv("MODEL_NAME", "custom-model")

    cfg = load_config(str(config_path))
    assert cfg.queue.redis_url == "redis://custom:6380/2"
    assert cfg.engine.model.name == "custom-model"


def test_rate_limit_proxy_settings(tmp_path: Path):
    config_path = tmp_path / "serve.yaml"
    config_path.write_text(
        """
security:
  auth:
    mode: "none"
  rate_limit:
    trust_proxy_headers: true
    trusted_proxies: "10.0.0.0/8,192.168.0.1"
""",
        encoding="utf-8",
    )

    cfg = load_config(str(config_path))
    assert cfg.security.rate_limit.trust_proxy_headers is True
    assert cfg.security.rate_limit.trusted_proxies == ["10.0.0.0/8", "192.168.0.1"]
