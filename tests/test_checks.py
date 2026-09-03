"""tools/checks/: the guards that stop a newly authored scenario shipping something it should not.

These cover the guard logic on synthetic input. The same guards run against the committed scenarios
in tools/validate.py, which is what CI executes.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from typing import ClassVar

from tests.fixtures import reference_key
from tools.checks.payloads import identifier_problems
from tools.checks.references import _check_verdict
from tools.checks.report import Report
from tools.checks.specs import spec_problems


class SpecSchemaTests(unittest.TestCase):
    @staticmethod
    def _spec() -> dict:
        return {
            "scenario_id": "scenario_011_example",
            "scenario_family": "clear_malicious",
            "title": "Example",
            "source": {
                "kind": "host",
                "zip": "example.zip",
                "citation": "Example",
                "upstream_path": "datasets/example.zip",
            },
            "environment": {},
            "alert": {},
            "select": {
                "minimal": [{"event_id": "Sysmon/1"}],
                "curated": [{"event_id": "Sysmon/1"}],
                "verbose": {"hosts": ["HOST"]},
            },
            "enrichment": {},
            "gold": {},
        }

    def test_a_well_formed_spec_has_no_problems(self):
        self.assertEqual(spec_problems("scenario_011_example", self._spec()), [])

    def test_every_problem_is_reported_not_just_the_first(self):
        spec = self._spec()
        del spec["gold"]
        spec["source"]["kind"] = "sasquatch"
        spec["scenario_id"] = "mismatched"
        problems = spec_problems("scenario_011_example", spec)
        self.assertTrue(any("missing ['gold']" in problem for problem in problems), problems)
        self.assertTrue(any("sasquatch" in problem for problem in problems), problems)
        self.assertTrue(any("does not match its directory" in problem for problem in problems))

    def test_derived_scenarios_require_a_transform(self):
        spec = self._spec()
        spec["source"]["kind"] = "derived"
        self.assertTrue(
            any("transform" in problem for problem in spec_problems("scenario_011_example", spec))
        )

    def test_unknown_selector_operator_is_rejected(self):
        spec = self._spec()
        spec["select"]["curated"] = [{"where": {"image__regex": "x"}}]
        self.assertTrue(
            any("regex" in problem for problem in spec_problems("scenario_011_example", spec))
        )


class IdentifierHygieneTests(unittest.TestCase):
    MAPPING: ClassVar[dict] = {"WORKSTATION5": "WKS-4471", "172.18.39.5": "10.24.8.21"}

    def test_substituted_payload_is_clean(self):
        payload = json.dumps({"host": "WKS-4471", "ip": "10.24.8.21", "sid": "S-1-5-18"})
        self.assertEqual(identifier_problems("ctx", payload, self.MAPPING), [])

    def test_unmapped_identifiers_are_caught(self):
        """The failure mode this exists for: a new capture whose identifiers nobody listed."""
        for payload, expected in (
            ({"ip": "192.168.7.9"}, "192.168.7.9"),
            ({"sid": "S-1-5-21-111-222-333"}, "S-1-5-21-111-222-333"),
            ({"host": "WORKSTATION5"}, "workstation5"),
        ):
            with self.subTest(payload=payload):
                problems = identifier_problems("ctx", json.dumps(payload), self.MAPPING)
                self.assertTrue(any(expected in problem for problem in problems), problems)


class AlternativeCreditTests(unittest.TestCase):
    @staticmethod
    def _verdict() -> dict:
        verdict = reference_key()["verdict"]
        alternative = verdict["acceptable_alternatives"][0]
        alternative["rationale"] = (
            "O1 and R000140 support the alternative reading while escalation remains required."
        )
        alternative["terminal_action_allowed"] = False
        return verdict

    def test_full_credit_defaults_to_existing_behavior(self):
        report = Report()
        _check_verdict(report, "scenario_test", self._verdict())
        self.assertEqual(report.failures, [])

    def test_credit_must_be_numeric_and_bounded(self):
        for credit in (-0.1, 1.1, True, "0.5"):
            verdict = self._verdict()
            verdict["acceptable_alternatives"][0]["credit"] = credit
            report = Report()
            with contextlib.redirect_stdout(io.StringIO()):
                _check_verdict(report, "scenario_test", verdict)
            self.assertTrue(any("credit must be numeric" in item for item in report.failures))

    def test_partial_credit_requires_an_inferiority_rationale(self):
        verdict = self._verdict()
        verdict["acceptable_alternatives"][0]["credit"] = 0.5
        report = Report()
        with contextlib.redirect_stdout(io.StringIO()):
            _check_verdict(report, "scenario_test", verdict)
        self.assertTrue(any("credit_rationale" in item for item in report.failures))

    def test_alternative_cannot_expand_terminal_action_envelope(self):
        verdict = self._verdict()
        alternative = verdict["acceptable_alternatives"][0]
        alternative.update(recommended_action="Close", terminal_action_allowed=True)
        report = Report()
        with contextlib.redirect_stdout(io.StringIO()):
            _check_verdict(report, "scenario_test", verdict)
        self.assertTrue(any("expands permission to Close" in item for item in report.failures))


class ReportTests(unittest.TestCase):
    def test_failures_are_scoped_to_one_report(self):
        first, second = Report(), Report()
        with contextlib.redirect_stdout(io.StringIO()):
            first.fail("broken")
            self.assertEqual(second.failures, [])
            self.assertEqual(first.summarize(), 1)
            self.assertEqual(second.summarize(), 0)


if __name__ == "__main__":
    unittest.main()
