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


def get_provider(api: str) -> LLMProvider:
    """
    Get the appropriate LLM provider instance.
    
    Args:
        api: LLM API provider name
        
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
    else:
        raise NotImplementedError(f"LLM api '{api}' is not supported yet.")