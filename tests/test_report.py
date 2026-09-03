"""The standalone HTML explains the evaluation without repository context."""

from __future__ import annotations

import re
import unittest

from tools.report_template import render


class ReportContentTests(unittest.TestCase):
    def setUp(self):
        self.html = render(
            {
                "sweeps": ["test-sweep"],
                "instrument_version": "3.4",
                "scoring_version": "3.4",
                "judge_version": "v10",
                "grounding_mode": "structured Haiku judge",
                "generated": "2026-01-01T00:00:00Z",
                "scenario_count": 10,
                "runs": [],
                "summaries": [],
                "profiles": {},
                "baseline": {
                    "policy": {
                        "classification": "Malicious",
                        "severity": "High",
                        "recommended_action": "Escalate for Investigation",
                    }
                },
            }
        )
        visible = re.sub(
            r"<!--.*?-->|<script.*?</script>|<style.*?</style>", " ", self.html, flags=re.S
        )
        self.visible_text = re.sub(r"<[^>]+>", " ", visible)

    def test_report_uses_soc_alert_triage_name(self):
        self.assertIn("SOC alert triage benchmark", self.html)
        self.assertNotIn("MDR triage benchmark", self.html)

    def test_report_defines_operational_terms(self):
        for label in (
            "Unsafe close/monitor",
            "Recommended review mode",
            "Confidence skill",
            "Evaluation cost/scenario (3 runs)",
        ):
            self.assertIn(label, self.html)

    def test_report_omits_removed_sections(self):
        for text in (
            "methodology.pdf",
            "Operational flags",
            "Where the ranking comes from",
            "Credited alternatives",
            "Accepted alternatives",
            "dot size = runs in bin",
            "calibration-model",
        ):
            self.assertNotIn(text, self.html)

    def test_report_explains_the_study_design(self):
        self.assertIn("security alerts", self.html)
        self.assertIn("three times each", self.html)
        self.assertIn("frozen telemetry", self.html)

    def test_internal_versions_are_hidden_from_visible_text(self):
        for text in ("v3", "v9", "instrument v", "scored with", "collected with"):
            self.assertNotIn(text, self.visible_text)

    def test_report_contains_required_visual_encodings(self):
        for text in (
            "score-track",
            "score-negative",
            "Pareto frontier",
            "log scale",
            "Confidence quality",
            'id="confidence"',
        ):
            self.assertIn(text, self.html)


if __name__ == "__main__":
    unittest.main()
