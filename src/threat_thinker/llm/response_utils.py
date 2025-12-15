"""
Utility functions for parsing LLM responses
"""

import json
import re


def clean_json_response(response: str) -> str:
    """
    Clean LLM response to extract valid JSON.
    Removes markdown code block markers and extra formatting.

    Args:
        response: Raw response from LLM

    Returns:
        Cleaned JSON string
    """
    # Remove common markdown markers
    response = response.strip()

    # Remove ```json and ``` markers
    if response.startswith("```json"):
        response = response[7:]  # Remove '```json'
    elif response.startswith("```"):
        response = response[3:]  # Remove '```'

    if response.endswith("```"):
        response = response[:-3]  # Remove trailing '```'

    # Strip whitespace again
    response = response.strip()

    return response


def fix_truncated_json(json_str: str) -> str:
    """
    Attempt to fix truncated JSON by properly closing arrays and objects.

    Args:
        json_str: Potentially truncated JSON string

    Returns:
        Fixed JSON string
    """
    # Try to parse as-is first
    try:
        json.loads(json_str)
        return json_str  # Already valid
    except json.JSONDecodeError:
        pass

    # Count unclosed brackets and braces
    open_braces = json_str.count("{")
    close_braces = json_str.count("}")
    open_brackets = json_str.count("[")
    close_brackets = json_str.count("]")

    # Remove any trailing incomplete content after the last complete threat
    # Look for the pattern that indicates we're in the middle of a threat definition
    lines = json_str.split("\n")
    fixed_lines = []
    in_truncated_section = False

    for i, line in enumerate(lines):
        # If we find a line that looks like it's starting a new object but incomplete
        if '"id":' in line or '"title":' in line:
            # Check if this line is properly formatted
            if line.strip().endswith(",") or line.strip().endswith('"'):
                fixed_lines.append(line)
            else:
                # This looks like a truncated line, stop here
                in_truncated_section = True
                break
        elif not in_truncated_section:
            fixed_lines.append(line)

    # Reconstruct the JSON
    fixed_json = "\n".join(fixed_lines)

    # Remove trailing comma if it exists before closing
    fixed_json = re.sub(r",(\s*[}\]])", r"\1", fixed_json)

    # Count brackets again after cleanup
    open_braces = fixed_json.count("{")
    close_braces = fixed_json.count("}")
    open_brackets = fixed_json.count("[")
    close_brackets = fixed_json.count("]")

    # Add missing closing brackets and braces
    missing_brackets = open_brackets - close_brackets
    missing_braces = open_braces - close_braces

    for _ in range(missing_brackets):
        fixed_json += "]"

    for _ in range(missing_braces):
        fixed_json += "}"

    return fixed_json


def safe_json_loads(response: str) -> dict:
    """
    Safely parse JSON response from LLM, with cleanup if needed.

    Args:
        response: Raw response from LLM

    Returns:
        Parsed JSON as dictionary

    Raises:
        json.JSONDecodeError: If JSON parsing fails after cleanup
    """
    cleaned_response = clean_json_response(response)

    # First try to parse as-is
    try:
        return json.loads(cleaned_response)
    except json.JSONDecodeError as e:
        print(f"Initial JSON parse failed: {e}")

        # Try to fix truncated JSON
        try:
            fixed_response = fix_truncated_json(cleaned_response)
            print("Fixed response:", fixed_response)
            return json.loads(fixed_response)
        except json.JSONDecodeError as e2:
            print(f"Failed to fix truncated JSON: {e2}")
            # Re-raise the original error
            raise e
