"""
Ollama LLM provider implementation
"""

import json
import os
from typing import Dict, Optional

import requests

from . import LLMProvider


class OllamaProvider(LLMProvider):
    """
    Ollama (local LLM) provider implementation.
    Uses the /api/chat endpoint with optional JSON schema enforcement.
    """

    def __init__(self, host: Optional[str] = None, timeout: float = 120.0):
        """
        Initialize Ollama provider.

        Args:
            host: Ollama host URL (defaults to env OLLAMA_HOST or http://localhost:11434)
            timeout: Request timeout in seconds
        """
        self.host = (host or os.getenv("OLLAMA_HOST") or "http://localhost:11434").rstrip(
            "/"
        )
        self.timeout = timeout

    def call_api(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        *,
        response_format: Optional[Dict[str, str]] = None,
        json_schema: Optional[Dict] = None,
        temperature: float = 0.2,
        max_tokens: int = 10000,
    ) -> str:
        """Call Ollama chat API with structured output support."""
        format_param = None
        if json_schema:
            format_param = json_schema
        elif response_format:
            format_param = "json"

        chat_payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": True,
            "options": {
                "temperature": temperature,
                "top_p": 0.9,
                "num_predict": max_tokens,
            },
        }
        if format_param is not None:
            chat_payload["format"] = format_param

        chat_url = f"{self.host}/api/chat"
        try:
            resp = requests.post(
                chat_url,
                json=chat_payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
                stream=True,
            )
            resp.raise_for_status()
            chunks: list[str] = []
            for line in resp.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    # Skip non-JSON lines but keep streaming
                    continue
                message = data.get("message") or {}
                content_part = message.get("content") or data.get("response") or ""
                if content_part:
                    chunks.append(content_part)
                if data.get("error"):
                    raise RuntimeError(f"Ollama API error: {data['error']}")
            content = "".join(chunks).strip()
            if not content:
                raise RuntimeError("Ollama returned empty content")
            return content
        except requests.RequestException as exc:
            raise RuntimeError(
                f"Ollama API request failed ({getattr(exc.response, 'status_code', 'unknown')}): "
                f"{getattr(exc.response, 'text', '') or exc}"
            ) from exc
