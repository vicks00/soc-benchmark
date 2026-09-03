"""tools/normalize.py: one clock across channels, and projection onto the flat tier schema."""

from __future__ import annotations

import unittest

from tools import normalize


class EventTimeTests(unittest.TestCase):
    """Channels disagree about time fields, and a time window is only meaningful on one clock."""

    def test_sysmon_utc_wins_over_collector_local_time(self):
        raw = {"UtcTime": "2020-10-21 20:30:01.123", "EventTime": "2020-10-22 12:30:01"}
        self.assertEqual(normalize.event_time(raw), "2020-10-21 20:30:01.123")

    def test_shipper_timestamp_wins_over_collector_local_time(self):
        raw = {"@timestamp": "2020-10-21T20:30:01.123Z", "TimeCreated": "2020-10-22 12:30:01"}
        self.assertEqual(normalize.event_time(raw), "2020-10-21 20:30:01.123")

    def test_whole_second_timestamps_are_padded_to_milliseconds(self):
        self.assertEqual(
            normalize.event_time({"UtcTime": "2020-10-21 20:30:01"}), "2020-10-21 20:30:01.000"
        )

    def test_a_record_with_no_time_field_does_not_raise(self):
        self.assertEqual(normalize.event_time({}), "")


class ProjectionTests(unittest.TestCase):
    def test_channel_routing(self):
        for channel, expected in (
            ("Microsoft-Windows-Sysmon/Operational", "sysmon"),
            ("Microsoft-Windows-PowerShell/Operational", "powershell"),
            ("Application", "application"),
            ("System", "system"),
            ("Security", "security"),
            ("", "security"),
        ):
            with self.subTest(channel=channel):
                self.assertEqual(normalize.channel_kind(channel), expected)

    def test_mapped_fields_are_renamed(self):
        record = normalize.normalize(
            {
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventID": 1,
                "UtcTime": "2020-10-21 20:30:01.000",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd /c whoami",
            }
        )
        self.assertEqual(record["event_id"], "Sysmon/1")
        self.assertEqual(record["event_type"], "ProcessCreate")
        self.assertEqual(record["command_line"], "cmd /c whoami")

    def test_placeholder_values_are_dropped(self):
        record = normalize.normalize(
            {
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventID": 1,
                "UtcTime": "2020-10-21 20:30:01.000",
                "Image": "-",
                "CommandLine": "",
                "User": None,
            }
        )
        for absent in ("image", "command_line", "user"):
            self.assertNotIn(absent, record)

    def test_unmapped_event_still_produces_a_citable_record(self):
        """A scenario must be able to cite an event before the mapping table covers it."""
        record = normalize.normalize(
            {"Channel": "Security", "EventID": 9999, "UtcTime": "2020-10-21 20:30:01.000"},
            include_host=True,
        )
        self.assertEqual(record["event_id"], "Security/9999")
        self.assertEqual(record["event_type"], "SecurityEvent9999")
        self.assertIn("host", record)


if __name__ == "__main__":
    unittest.main()
