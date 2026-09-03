"""tools/build_scenarios.py: selectors, projection reuse, transforms, and anonymization."""

from __future__ import annotations

import json
import unittest
from typing import ClassVar

from harness.blinding import blind_context
from tools.build_scenarios import (
    Capture,
    _even_sample,
    anonymize,
    apply_transform,
    case_id,
    matches,
    select,
)


class SelectorTests(unittest.TestCase):
    RECORD: ClassVar[dict] = {
        "event_id": "Sysmon/1",
        "image": "C:\\Windows\\cmd.exe",
        "utc_time": "2020-10-21",
    }

    def test_each_operator(self):
        for where, expected in (
            ({"image": "C:\\Windows\\cmd.exe"}, True),
            ({"image": "c:\\windows\\CMD.exe"}, False),
            ({"image__ieq": "c:\\windows\\CMD.exe"}, True),
            ({"image__contains": "CMD"}, True),
            ({"image__not_contains": "powershell"}, True),
            ({"image__not_contains": "cmd"}, False),
            ({"image__startswith": "c:\\win"}, True),
            ({"image__endswith": "CMD.EXE"}, True),
            ({"image__in": ["c:\\windows\\cmd.exe", "other"]}, True),
            ({"utc_time__gte": "2020-10-20"}, True),
            ({"utc_time__lte": "2020-10-20"}, False),
        ):
            with self.subTest(where=where):
                self.assertIs(matches(self.RECORD, where), expected)

    def test_conditions_are_anded(self):
        self.assertTrue(matches(self.RECORD, {"event_id": "Sysmon/1", "image__contains": "cmd"}))
        self.assertFalse(matches(self.RECORD, {"event_id": "Sysmon/1", "image__contains": "nope"}))

    def test_absent_field_never_matches(self):
        self.assertFalse(matches(self.RECORD, {"missing_field": "x"}))

    def test_unknown_operator_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown selector operator"):
            matches(self.RECORD, {"image__regex": ".*"})

    def test_selection_deduplicates_and_orders_chronologically(self):
        records = [
            {"event_id": "Sysmon/1", "utc_time": "2020-01-02"},
            {"event_id": "Sysmon/1", "utc_time": "2020-01-01"},
            {"event_id": "Sysmon/1", "utc_time": "2020-01-02"},
        ]
        picked = select(records, [{"event_id": "Sysmon/1"}, {"event_id": "Sysmon/1"}])
        self.assertEqual([item["utc_time"] for item in picked], ["2020-01-01", "2020-01-02"])

    def test_limit_is_honoured(self):
        records = [{"event_id": "Sysmon/1", "utc_time": f"2020-01-0{n}"} for n in range(1, 5)]
        self.assertEqual(len(select(records, [{"event_id": "Sysmon/1", "limit": 2}])), 2)

    def test_host_filter_applies_when_hosts_are_supplied(self):
        records = [
            {"event_id": "Sysmon/1", "utc_time": "2020-01-01"},
            {"event_id": "Sysmon/1", "utc_time": "2020-01-02"},
        ]
        picked = select(
            records, [{"event_id": "Sysmon/1", "host": "WKS-2"}], hosts=["WKS-1", "WKS-2"]
        )
        self.assertEqual([item["utc_time"] for item in picked], ["2020-01-02"])


class CaptureTests(unittest.TestCase):
    @staticmethod
    def _capture() -> Capture:
        return Capture(
            [
                {
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": 1,
                    "Hostname": "HOST-A.corp.example",
                    "UtcTime": f"2020-10-21 20:30:0{index}.000",
                }
                for index in range(3)
            ]
        )

    def test_a_projection_is_reused_rather_than_rebuilt(self):
        capture = self._capture()
        self.assertIs(capture.normalized(), capture.normalized())

    def test_host_visibility_is_a_separate_projection(self):
        capture = self._capture()
        self.assertNotIn("host", capture.normalized()[0])
        self.assertEqual(capture.normalized(include_host=True)[0]["host"], "HOST-A")

    def test_record_ids_are_stable_and_survive_projection(self):
        first = self._capture()
        second = self._capture()
        self.assertEqual(
            [record["record_id"] for record in first.events],
            ["R000001", "R000002", "R000003"],
        )
        self.assertEqual(
            [record["record_id"] for record in first.normalized()],
            [record["record_id"] for record in second.normalized()],
        )
        self.assertEqual(first.events[1]["record_id"], first.normalized()[1]["record_id"])

    def test_even_sample_is_deterministic_and_bounded(self):
        items = list(range(10))
        self.assertEqual(_even_sample(items, 5), _even_sample(items, 5))
        self.assertEqual(len(_even_sample(items, 5)), 5)
        self.assertEqual(_even_sample(items, 20), items)


class TransformTests(unittest.TestCase):
    def test_replace_updates_structured_fields_and_message_text_together(self):
        """A half-applied rewrite leaves a scenario whose reference key describes absent behaviour."""
        transformed, stats = apply_transform(
            [
                {
                    "EventID": 4688,
                    "SubjectUserName": "legacy-user",
                    "SubjectUserSid": "legacy-sid",
                    "Message": "Account Name:\t\tlegacy-user",
                }
            ],
            {
                "replace": [
                    {
                        "where": {"SubjectUserName": "legacy-user"},
                        "set": {"SubjectUserName": "SYSTEM", "SubjectUserSid": "S-1-5-18"},
                        "pairs": [["legacy-user", "SYSTEM"]],
                    }
                ]
            },
        )
        self.assertEqual(stats["replaced"], 1)
        self.assertEqual(transformed[0]["SubjectUserSid"], "S-1-5-18")
        self.assertIn("SYSTEM", transformed[0]["Message"])


class AnonymizationTests(unittest.TestCase):
    def test_substitution_reaches_nested_structures(self):
        blob = str(anonymize({"a": ["theshire.local", {"b": "MORDORDC"}]}))
        self.assertNotIn("theshire", blob)
        self.assertNotIn("MORDORDC", blob)

    def test_longest_match_wins_so_fqdns_are_not_half_rewritten(self):
        self.assertEqual(anonymize("theshire.local"), "corp.example")

    def test_case_id_is_stable_and_encodes_nothing(self):
        first = case_id("scenario_002_mimikatz_lsass_memory")
        self.assertEqual(first, case_id("scenario_002_mimikatz_lsass_memory"))
        for fragment in ("002", "mimikatz", "lsass", "scenario"):
            self.assertNotIn(fragment, first.lower())


class BlindingTests(unittest.TestCase):
    CONTEXT: ClassVar[dict] = {
        "alert": {
            "rule_id": "TNX-CRED-T1003.001",
            "rule_name": "Credential Access: Suspicious Process",
            "mitre_attack": {"technique": "T1003.001"},
        }
    }

    def test_answer_bearing_alert_metadata_is_removed(self):
        blinded = blind_context(self.CONTEXT)
        self.assertNotIn("mitre_attack", blinded["alert"])
        self.assertNotIn("T1003", blinded["alert"]["rule_id"])
        self.assertEqual(blinded["alert"]["rule_name"], "Suspicious Process")

    def test_the_source_context_is_not_mutated(self):
        original = json.loads(json.dumps(self.CONTEXT))
        blind_context(self.CONTEXT)
        self.assertEqual(self.CONTEXT, original)


if __name__ == "__main__":
    unittest.main()
