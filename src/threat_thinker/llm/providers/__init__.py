"""
LLM providers base classes and interfaces
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.
    """

    @abstractmethod
    def call_api(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        *,
        response_format: Optional[Dict[str, str]] = None,
        json_schema: Optional[Dict] = None,
        temperature: float = 0.2,
        max_tokens: int = 1600,
    ) -> str:
        """
        Call the LLM API with given parameters.

        Args:
            model: Model name
            system_prompt: System prompt
            user_prompt: User prompt
            response_format: Optional response format specification
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            String response from LLM

        Raises:
            RuntimeError: If API call fails or response is empty
        """
        pass

    def analyze_image(
        self,
        model: str,
        base64_image: str,
        media_type: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: int = 2000,
    ) -> str:
        """
        Analyze an image using the LLM's vision capabilities.
        Default implementation raises NotImplementedError.

        Args:
            model: Model name
            base64_image: Base64 encoded image data
            media_type: MIME type of the image
            system_prompt: System prompt for the analysis task
            user_prompt: User prompt describing what to extract
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            String response from LLM

        Raises:
            NotImplementedError: If provider doesn't support image analysis
        """
        raise NotImplementedError("Image analysis not implemented for this provider")


def get_provider(
    api: str,
    aws_profile: Optional[str] = None,
    aws_region: Optional[str] = None,
    ollama_host: Optional[str] = None,
) -> LLMProvider:
    """
    Get the appropriate LLM provider instance.

    Args:
        api: LLM API provider name
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)

    Returns:
        LLMProvider instance

    Raises:
        NotImplementedError: If API provider is not supported
    """
    api_normalized = api.lower()

    if api_normalized == "openai":
        from .openai import OpenAIProvider

        return OpenAIProvider()
    elif api_normalized == "anthropic":
        from .anthropic import AnthropicProvider

        return AnthropicProvider()
    elif api_normalized == "bedrock":
        from .bedrock import BedrockProvider

        return BedrockProvider(aws_profile=aws_profile, aws_region=aws_region)
    elif api_normalized == "ollama":
        from .ollama import OllamaProvider

        return OllamaProvider(host=ollama_host)
    else:
        raise NotImplementedError(f"LLM api '{api}' is not supported yet.")
