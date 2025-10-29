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
    def call_api(self,
                 model: str,
                 system_prompt: str,
                 user_prompt: str,
                 *,
                 response_format: Optional[Dict[str, str]] = None,
                 temperature: float = 0.2,
                 max_tokens: int = 1600) -> str:
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


def get_provider(api: str, aws_profile: Optional[str] = None, aws_region: Optional[str] = None) -> LLMProvider:
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
    else:
        raise NotImplementedError(f"LLM api '{api}' is not supported yet.")