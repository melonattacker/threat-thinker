"""
LLM client functionality
"""

import os
from typing import Dict, Optional

from .providers import get_provider


class LLMClient:
    """
    LLM client for both text and image analysis
    """

    def __init__(
        self,
        api: Optional[str] = None,
        model: Optional[str] = None,
        aws_profile: Optional[str] = None,
        aws_region: Optional[str] = None,
        ollama_host: Optional[str] = None,
    ):
        """
        Initialize LLM client with provider settings.

        Args:
            api: LLM API provider (defaults to first available: openai, anthropic, bedrock)
            model: Model name (defaults to provider's best text/vision model)
            aws_profile: AWS profile name (for bedrock provider only)
            aws_region: AWS region (for bedrock provider only)
        """
        self.aws_profile = aws_profile
        self.aws_region = aws_region
        self.ollama_host = ollama_host or os.getenv("OLLAMA_HOST")

        # Auto-detect API if not specified
        if not api:
            if os.getenv("OPENAI_API_KEY"):
                api = "openai"
            elif os.getenv("ANTHROPIC_API_KEY"):
                api = "anthropic"
            else:
                api = "bedrock"  # Fallback to bedrock

        self.api = api

        # Handle mock API for testing
        if api == "mock":
            self.model = "mock-model"
            self.provider = None
            return

        # Set default models
        if not model:
            if api == "openai":
                model = "gpt-4o"  # Best OpenAI text/vision model
            elif api == "anthropic":
                model = "claude-3-5-sonnet-20241022"  # Claude 3.5 Sonnet latest
            elif api == "bedrock":
                model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
            elif api == "ollama":
                model = "llama3.1"

        self.model = model

        # Initialize provider once during client creation
        self.provider = get_provider(
            self.api,
            aws_profile=self.aws_profile,
            aws_region=self.aws_region,
            ollama_host=self.ollama_host,
        )

    def call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        response_format: Optional[Dict[str, str]] = None,
        json_schema: Optional[Dict] = None,
        temperature: float = 0.2,
        max_tokens: int = 1600,
    ) -> str:
        """
        Call LLM API with given parameters using the client's configuration.

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            response_format: Optional response format specification
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            String response from LLM

        Raises:
            NotImplementedError: If API provider is not supported
            RuntimeError: If API key is not set or response is empty
        """
        # Handle mock API for testing
        if self.api == "mock":
            if "diff" in user_prompt.lower() or "changes" in user_prompt.lower():
                return """## Analysis

The comparison between the before and after systems shows several significant changes in the threat landscape:

### Graph Changes Summary
No architectural changes were detected between the two system diagrams - the same nodes and edges are present in both versions.

### Threat Changes Summary  
While the system architecture remained identical, the threat modeling analysis produced different results, with 5 threats being removed and 5 new threats being added.

### Security Impact Analysis
The threat changes indicate a refinement in the threat analysis rather than fundamental architectural security changes:

1. **Authentication Controls**: Both versions identify similar authentication gaps but with slightly different threat identifications
2. **Communication Security**: Protocol-related threats remain a consistent concern across both analyses
3. **Authorization Controls**: Authorization gaps are identified in both versions

### Risk Assessment
The overall security risk level appears consistent between the two analyses. The changes represent different ways of categorizing and identifying essentially the same underlying security concerns.

### Recommendations
1. **Implement Authentication**: Address the consistent authentication gaps identified in both analyses
2. **Secure Communications**: Implement encrypted protocols for all inter-component communications  
3. **Authorization Controls**: Add proper authorization checks to all system components
4. **Protocol Specification**: Clearly define and secure all communication protocols between components"""
            else:
                return "Mock LLM response for testing. This is a basic analysis of the provided data."

        return self.provider.call_api(
            model=self.model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            json_schema=json_schema,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def analyze_image_for_graph(
        self,
        base64_image: str,
        media_type: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: int = 2000,
    ) -> str:
        """
        Analyze an image using LLM vision capabilities to extract graph data.

        Args:
            base64_image: Base64 encoded image data
            media_type: MIME type of the image (e.g., "image/jpeg", "image/png")
            system_prompt: System prompt for the analysis task
            user_prompt: User prompt describing what to extract
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            String response from LLM (expected to be JSON)

        Raises:
            NotImplementedError: If API provider doesn't support image analysis
            RuntimeError: If API call fails
        """
        # Check if provider supports image analysis
        if hasattr(self.provider, "analyze_image"):
            return self.provider.analyze_image(
                model=self.model,
                base64_image=base64_image,
                media_type=media_type,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        else:
            raise NotImplementedError(
                f"Provider {self.api} does not support image analysis"
            )
