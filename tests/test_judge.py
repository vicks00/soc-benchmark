"""Structured grounding-judge contracts and deterministic citation checks."""

from __future__ import annotations

import unittest

from harness.judge import _v10_key, _v10_tool, validate_judgment
from tests.fixtures import reference_key, valid_output


def valid_judgment() -> dict:
    return {
        "observations": [{"candidate_id": "E1", "covered_gold_ids": ["O1"], "grounded": True}],
        "inferences": [{"candidate_id": "I1", "covered_gold_ids": ["I1"]}],
        "entities": [{"candidate_id": "A1", "covered_gold_ids": ["EN1"]}],
        "investigations": [{"candidate_id": "P1", "covered_gold_ids": ["P1"]}],
        "unknowns": [{"candidate_id": "U1", "covered_gold_ids": ["U1"]}],
    }


class JudgeSchemaTests(unittest.TestCase):
    def test_valid_judgment_aligns_every_candidate(self):
        self.assertIsNone(validate_judgment(valid_judgment(), reference_key(), valid_output()))

    def test_unknown_gold_id_is_rejected(self):
        judgment = valid_judgment()
        judgment["observations"][0]["covered_gold_ids"] = ["O999"]
        self.assertIn(
            "unknown reference ids",
            validate_judgment(judgment, reference_key(), valid_output()),
        )

    def test_missing_candidate_is_rejected(self):
        judgment = valid_judgment()
        judgment["observations"] = []
        self.assertIn(
            "does not align",
            validate_judgment(judgment, reference_key(), valid_output()),
        )

    def test_duplicate_candidate_is_rejected(self):
        judgment = valid_judgment()
        judgment["observations"].append({**judgment["observations"][0]})
        self.assertIn(
            "duplicate",
            validate_judgment(judgment, reference_key(), valid_output()),
        )

    def test_grounded_is_a_boolean(self):
        judgment = valid_judgment()
        judgment["observations"][0]["grounded"] = "yes"
        self.assertIn(
            "must be boolean",
            validate_judgment(judgment, reference_key(), valid_output()),
        )

    def test_anthropic_tool_forbids_extra_fields(self):
        schema = _v10_tool(reference_key())["input_schema"]
        self.assertIs(schema["additionalProperties"], False)
        for field in schema["properties"].values():
            self.assertIs(field["items"]["additionalProperties"], False)

    def test_cache_key_includes_the_context_tier(self):
        first = _v10_key("scenario_001_lsass_comsvcs", "minimal", reference_key(), valid_output())
        second = _v10_key("scenario_001_lsass_comsvcs", "verbose", reference_key(), valid_output())
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
