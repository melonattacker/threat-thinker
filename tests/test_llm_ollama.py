from unittest.mock import MagicMock, patch

import pytest

import requests

from llm.inference import _call_llm_json_with_retry
from llm.providers.ollama import OllamaProvider


def test_ollama_provider_uses_schema_and_host():
    provider = OllamaProvider(host="http://ollama:11434")
    fake_response = MagicMock()
    fake_response.json.return_value = {"message": {"content": '{"ok": true}'}}
    fake_response.raise_for_status.return_value = None
    with patch("llm.providers.ollama.requests.post", return_value=fake_response) as mock_post:
        content = provider.call_api(
            model="my-model",
            system_prompt="sys",
            user_prompt="user",
            response_format={"type": "json_object"},
            json_schema={"type": "object"},
            temperature=0.1,
            max_tokens=10,
        )

    assert content == '{"ok": true}'
    payload = mock_post.call_args[1]["json"]
    assert payload["model"] == "my-model"
    assert payload["format"] == {"type": "object"}
    assert payload["stream"] is False
    assert payload["options"]["num_predict"] == 10
    assert payload["messages"][0]["role"] == "system"


def test_call_llm_json_with_retry_fails_after_invalid_json():
    attempts = {"count": 0}

    def _bad_call() -> str:
        attempts["count"] += 1
        return "not-json"

    with pytest.raises(RuntimeError):
        _call_llm_json_with_retry(_bad_call, lambda payload: None, attempts=2)

    assert attempts["count"] == 2
