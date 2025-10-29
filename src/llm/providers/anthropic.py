"""
Anthropic Claude LLM provider implementation
"""

import os
from typing import Dict, Optional
from anthropic import Anthropic

from . import LLMProvider


class AnthropicProvider(LLMProvider):
    """
    Anthropic Claude LLM provider implementation.
    """
    
    def __init__(self):
        """Initialize Anthropic provider."""
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self.client = Anthropic(api_key=api_key)
    
    def call_api(self,
                 model: str,
                 system_prompt: str,
                 user_prompt: str,
                 *,
                 response_format: Optional[Dict[str, str]] = None,
                 temperature: float = 0.2,
                 max_tokens: int = 1600) -> str:
        """
        Call Anthropic API with given parameters.
        
        Args:
            model: Model name (e.g., claude-3-sonnet-20240229, claude-3-haiku-20240307)
            system_prompt: System prompt
            user_prompt: User prompt
            response_format: Optional response format specification (Note: Anthropic doesn't support JSON mode like OpenAI)
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response
            
        Returns:
            String response from Anthropic API
            
        Raises:
            RuntimeError: If response is empty or API call fails
        """
        try:
            # Anthropic API uses different parameter structure
            message = self.client.messages.create(
                model=model,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ],
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            # Extract content from response
            if not message.content or len(message.content) == 0:
                raise RuntimeError("LLM returned empty content")
            
            # Anthropic returns content as a list of content blocks
            content = ""
            for block in message.content:
                if hasattr(block, 'text'):
                    content += block.text
                
            if not content:
                raise RuntimeError("LLM returned empty content")
                
            return content
            
        except Exception as e:
            raise RuntimeError(f"Anthropic API call failed: {str(e)}")