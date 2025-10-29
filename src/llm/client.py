"""
LLM client functionality
"""

from typing import Dict, Optional

from .providers import get_provider


def call_llm(api: str,
             model: str,
             system_prompt: str,
             user_prompt: str,
             *,
             response_format: Optional[Dict[str, str]] = None,
             temperature: float = 0.2,
             max_tokens: int = 1600,
             aws_profile: Optional[str] = None,
             aws_region: Optional[str] = None) -> str:
    """
    Call LLM API with given parameters.
    
    Args:
        api: LLM API provider (e.g., "openai", "anthropic", "bedrock")
        model: Model name
        system_prompt: System prompt
        user_prompt: User prompt
        response_format: Optional response format specification
        temperature: Sampling temperature
        max_tokens: Maximum tokens in response
        aws_profile: AWS profile name (for bedrock provider only)
        aws_region: AWS region (for bedrock provider only)
        
    Returns:
        String response from LLM
        
    Raises:
        NotImplementedError: If API provider is not supported
        RuntimeError: If API key is not set or response is empty
    """
    provider = get_provider(api, aws_profile=aws_profile, aws_region=aws_region)
    return provider.call_api(
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        temperature=temperature,
        max_tokens=max_tokens
    )