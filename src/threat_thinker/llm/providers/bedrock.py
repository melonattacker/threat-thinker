"""
AWS Bedrock LLM provider implementation
"""

import json
import os
from typing import Dict, Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from . import LLMProvider


class BedrockProvider(LLMProvider):
    """
    AWS Bedrock LLM provider implementation.
    Supports Claude models through AWS Bedrock.
    """

    def __init__(
        self, aws_profile: Optional[str] = None, aws_region: Optional[str] = None
    ):
        """
        Initialize Bedrock provider.

        Args:
            aws_profile: AWS profile name to use for authentication
            aws_region: AWS region (defaults to us-east-1 if not specified)
        """
        # Default region if not provided
        region = aws_region or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"

        try:
            # Initialize AWS session
            if aws_profile:
                session = boto3.Session(profile_name=aws_profile, region_name=region)
                self.client = session.client("bedrock-runtime")
            else:
                # Use default credentials (environment variables or IAM role)
                self.client = boto3.client("bedrock-runtime", region_name=region)

        except NoCredentialsError:
            raise RuntimeError(
                "AWS credentials not found. Please set AWS_ACCESS_KEY_ID, "
                "AWS_SECRET_ACCESS_KEY, and optionally AWS_SESSION_TOKEN environment variables, "
                "or configure AWS profile with 'aws configure'"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize AWS Bedrock client: {str(e)}")

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
        """
        Call AWS Bedrock API with given parameters.

        Args:
            model: Model name (e.g., anthropic.claude-3-5-sonnet-20240620-v1:0)
            system_prompt: System prompt
            user_prompt: User prompt
            response_format: Optional response format specification
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            String response from Bedrock API

        Raises:
            RuntimeError: If response is empty or API call fails
        """
        try:
            # Prepare the request body for Claude models
            # AWS Bedrock Claude models use the Anthropic message format
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            # Convert body to JSON
            body_json = json.dumps(body)

            # Call Bedrock API
            response = self.client.invoke_model(
                modelId=model,
                contentType="application/json",
                accept="application/json",
                body=body_json,
            )

            # Parse response
            response_body = json.loads(response["body"].read())

            # Extract content from response
            if "content" not in response_body or not response_body["content"]:
                raise RuntimeError("Bedrock returned empty content")

            # Claude models return content as a list of content blocks
            content = ""
            for block in response_body["content"]:
                if "text" in block:
                    content += block["text"]

            if not content:
                raise RuntimeError("Bedrock returned empty content")

            return content

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            raise RuntimeError(
                f"AWS Bedrock API call failed: {error_code} - {error_message}"
            )
        except Exception as e:
            raise RuntimeError(f"Bedrock API call failed: {str(e)}")

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
        Analyze an image using Claude via AWS Bedrock.

        Args:
            model: Model name (should be a vision-capable Claude model)
            base64_image: Base64 encoded image data
            media_type: MIME type of the image
            system_prompt: System prompt for the analysis task
            user_prompt: User prompt describing what to extract
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            String response from Bedrock API

        Raises:
            RuntimeError: If response is empty or API call fails
        """
        try:
            # Prepare the request body with image for Claude models via Bedrock
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "system": system_prompt,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": media_type,
                                    "data": base64_image,
                                },
                            },
                            {"type": "text", "text": user_prompt},
                        ],
                    }
                ],
            }

            # Convert body to JSON
            body_json = json.dumps(body)

            # Call Bedrock API
            response = self.client.invoke_model(
                modelId=model,
                contentType="application/json",
                accept="application/json",
                body=body_json,
            )

            # Parse response
            response_body = json.loads(response["body"].read())

            # Extract content from response
            if "content" not in response_body or not response_body["content"]:
                raise RuntimeError("Bedrock returned empty content for image analysis")

            # Claude models return content as a list of content blocks
            content = ""
            for block in response_body["content"]:
                if "text" in block:
                    content += block["text"]

            if not content:
                raise RuntimeError("Bedrock returned empty content for image analysis")

            return content

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            raise RuntimeError(
                f"AWS Bedrock image analysis failed: {error_code} - {error_message}"
            )
        except Exception as e:
            raise RuntimeError(f"Bedrock image analysis failed: {str(e)}")
