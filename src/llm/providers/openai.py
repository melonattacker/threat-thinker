"""
OpenAI LLM provider implementation
"""

import os
from typing import Dict, Optional
from openai import OpenAI

from . import LLMProvider


class OpenAIProvider(LLMProvider):
    """
    OpenAI LLM provider implementation.
    """
    
    def __init__(self):
        """Initialize OpenAI provider."""
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not set")
        self.client = OpenAI()
    
    def call_api(self,
                 model: str,
                 system_prompt: str,
                 user_prompt: str,
                 *,
                 response_format: Optional[Dict[str, str]] = None,
                 temperature: float = 0.2,
                 max_tokens: int = 1600) -> str:
        """
        Call OpenAI API with given parameters.
        
        Args:
            model: Model name
            system_prompt: System prompt
            user_prompt: User prompt
            response_format: Optional response format specification
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response
            
        Returns:
            String response from OpenAI API
            
        Raises:
            RuntimeError: If response is empty
        """
        kwargs = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format is not None:
            kwargs["response_format"] = response_format

        resp = self.client.chat.completions.create(**kwargs)
        content = resp.choices[0].message.content
        if not content:
            raise RuntimeError("LLM returned empty content")
        return content