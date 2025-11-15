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

    def call_api(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        *,
        response_format: Optional[Dict[str, str]] = None,
        temperature: float = 0.2,
        max_tokens: int = 10000,
    ) -> str:
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
        # gpt-5 models don't need temperature
        if model.startswith("gpt-5"):
            kwargs = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
        else:
            kwargs = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": temperature,
                "max_completion_tokens": max_tokens,
            }
        if response_format is not None:
            kwargs["response_format"] = response_format

        resp = self.client.chat.completions.create(**kwargs)
        content = resp.choices[0].message.content
        if not content:
            raise RuntimeError("LLM returned empty content")
        return content

    def analyze_image(
        self,
        model: str,
        base64_image: str,
        media_type: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: int = 10000,
    ) -> str:
        """
        Analyze an image using OpenAI's Responses API (required for image analysis).

        Args:
            model: Model name (should be a vision-capable model like gpt-4o)
            base64_image: Base64 encoded image data
            media_type: MIME type of the image
            system_prompt: System prompt for the analysis task
            user_prompt: User prompt describing what to extract
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            String response from OpenAI Responses API

        Raises:
            RuntimeError: If Responses API is not available or response is empty
        """
        try:
            response = self.client.responses.create(
                model=model,
                input=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": f"{system_prompt}\n\n{user_prompt}",
                            },
                            {
                                "type": "input_image",
                                "image_url": f"data:{media_type};base64,{base64_image}",
                            },
                        ],
                    }
                ],
            )
            content = response.output_text
            if not content:
                raise RuntimeError(
                    "OpenAI Responses API returned empty content for image analysis"
                )
            return content

        except AttributeError:
            raise RuntimeError(
                "OpenAI Responses API is not available. Image analysis requires the Responses API."
            )
        except Exception as e:
            raise RuntimeError(f"OpenAI Responses API image analysis failed: {e}")
