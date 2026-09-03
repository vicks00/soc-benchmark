"""The companion white paper is derived from the scorecard and explains the report."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.paper import render


class PaperContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scorecard = (
            Path.home() / "Downloads" / "mdr-benchmark" / "20260804T032630Z" / "scorecard.json"
        )
        if not scorecard.exists():
            raise unittest.SkipTest("completed scorecard is not available")
        cls.html = render(json.loads(scorecard.read_text()))

    def test_paper_covers_methods_results_and_limitations(self):
        for heading in (
            "Evaluation design",
            "Decision and confidence measurements",
            "Evidence support and safety",
            "How to read the HTML report",
            "Results snapshot",
            "Limitations and use",
        ):
            self.assertIn(heading, self.html)

    def test_paper_defines_reader_facing_terms(self):
        for term in (
            "Unsafe close or monitor",
            "Confidence error",
            "Recommended review mode",
            "Credited alternatives",
        ):
            self.assertIn(term, self.html)


if __name__ == "__main__":
    unittest.main()
