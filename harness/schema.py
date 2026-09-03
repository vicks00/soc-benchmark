"""Provider-specific structured-output wrappers around OUTPUT_SCHEMA.

OpenAI strict JSON schema, Gemini response_schema, and Anthropic forced tool input_schema each
reject different keywords, so we strip per provider. Probabilities summing to 1 and non-empty
strings are still checked in validate_output.
"""

from __future__ import annotations

from copy import deepcopy

from harness.config import OUTPUT_SCHEMA

TOOL_NAME = "submit_triage"

_OPENAI_UNSUPPORTED = {"minLength", "maxLength", "pattern", "format", "minimum", "maximum"}
_GEMINI_UNSUPPORTED = {"additionalProperties", "minLength", "maximum", "minimum"}


def _without(node, unsupported: set[str]):
    if isinstance(node, dict):
        return {
            key: _without(value, unsupported)
            for key, value in node.items()
            if key not in unsupported
        }
    if isinstance(node, list):
        return [_without(item, unsupported) for item in node]
    return node


def openai_response_format() -> dict:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": TOOL_NAME,
            "strict": True,
            "schema": _without(deepcopy(OUTPUT_SCHEMA), _OPENAI_UNSUPPORTED),
        },
    }


def gemini_response_schema() -> dict:
    return _without(deepcopy(OUTPUT_SCHEMA), _GEMINI_UNSUPPORTED)


def anthropic_tool() -> dict:
    return {
        "name": TOOL_NAME,
        "description": "Submit the triage decision for this alert.",
        "input_schema": deepcopy(OUTPUT_SCHEMA),
    }
