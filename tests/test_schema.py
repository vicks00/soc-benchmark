"""harness/schema.py: the provider translations of the output contract.

These lock the schema to the validator. A field added to one and not the other would otherwise
only surface as invalid responses partway through a paid sweep.
"""

from __future__ import annotations

import unittest

from harness.config import CLASSIFICATIONS, OUTPUT_FIELDS, OUTPUT_SCHEMA, validate_output
from harness.schema import (
    TOOL_NAME,
    anthropic_tool,
    gemini_response_schema,
    openai_response_format,
)
from tests.fixtures import valid_output


def _keys_at_every_level(node, found: set[str]) -> set[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(key)
            _keys_at_every_level(value, found)
    elif isinstance(node, list):
        for item in node:
            _keys_at_every_level(item, found)
    return found


class ContractAgreementTests(unittest.TestCase):
    def test_schema_and_validator_describe_the_same_fields(self):
        self.assertEqual(set(OUTPUT_SCHEMA["properties"]), OUTPUT_FIELDS)
        self.assertEqual(set(OUTPUT_SCHEMA["required"]), OUTPUT_FIELDS)

    def test_a_response_matching_the_schema_passes_validation(self):
        self.assertIsNone(validate_output(valid_output()))

    def test_probability_keys_match_the_classification_enum(self):
        probabilities = OUTPUT_SCHEMA["properties"]["classification_probabilities"]
        self.assertEqual(set(probabilities["properties"]), set(CLASSIFICATIONS))
        self.assertEqual(
            set(OUTPUT_SCHEMA["properties"]["classification"]["enum"]), set(CLASSIFICATIONS)
        )


class ProviderTranslationTests(unittest.TestCase):
    def test_openai_strict_mode_drops_only_unsupported_keywords(self):
        schema = openai_response_format()["json_schema"]["schema"]
        self.assertTrue(openai_response_format()["json_schema"]["strict"])
        present = _keys_at_every_level(schema, set())
        for unsupported in ("pattern", "minLength", "minimum", "maximum"):
            self.assertNotIn(unsupported, present)
        # Strict mode requires every object to forbid extra properties, which is what stops a
        # model inventing a field the scorer would reject.
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["properties"]), OUTPUT_FIELDS)

    def test_openai_keeps_the_technique_format_in_a_description(self):
        schema = openai_response_format()["json_schema"]["schema"]
        items = schema["properties"]["mitre_techniques"]["items"]
        self.assertIn("T1003", items["description"])

    def test_gemini_schema_drops_keywords_openapi_rejects(self):
        present = _keys_at_every_level(gemini_response_schema(), set())
        self.assertNotIn("additionalProperties", present)
        self.assertEqual(set(gemini_response_schema()["properties"]), OUTPUT_FIELDS)

    def test_anthropic_tool_carries_the_full_schema(self):
        tool = anthropic_tool()
        self.assertEqual(tool["name"], TOOL_NAME)
        self.assertEqual(tool["input_schema"], OUTPUT_SCHEMA)

    def test_translations_do_not_mutate_the_source_schema(self):
        before = OUTPUT_SCHEMA["properties"]["mitre_techniques"]["items"].copy()
        openai_response_format()
        gemini_response_schema()
        anthropic_tool()
        self.assertEqual(OUTPUT_SCHEMA["properties"]["mitre_techniques"]["items"], before)


if __name__ == "__main__":
    unittest.main()
