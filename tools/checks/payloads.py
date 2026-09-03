"""What may and may not appear in a model-facing context."""

from __future__ import annotations

import json
import re
from pathlib import Path

from harness.config import SCENARIOS, TIERS, load_context
from tools.checks.report import Report

BASE = Path(__file__).resolve().parent.parent.parent

LEAK_TERMS = {
    "mimikatz",
    "empire",
    "covenant",
    "grunt",
    "mordor",
    "otrf",
    "security-datasets",
    "atomic/windows",
    "credential_access",
    "privilege_escalation",
    "lateral_movement",
    "defense_evasion",
    "negative control",
    "false positive",
    "ground truth",
    "benign control",
    "scenario_0",
    "t1003",
    "t1021",
    "t1047",
    "t1127",
    "t1218",
    "t1548",
    "t1574",
}

LEAK_ALLOW = {
    "scenario_001_lsass_comsvcs": {"comsvcs", "minidump"},
    "scenario_003_dcsync_drsuapi": {"drsuapi"},
    "scenario_004_fodhelper_uac_bypass": {"fodhelper"},
    "scenario_005_wbemcomn_dll_hijack": {"wbemcomn"},
}

SOURCE_MARKERS = {
    "otrf",
    "security-datasets",
    "mordor",
    "empire",
    "covenant",
}

SID_PATTERN = re.compile(r"S-1-5-21-\d+-\d+-\d+")
PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"
)


def environment_map() -> dict[str, str]:
    return json.loads((BASE / "tools" / "environment_map.json").read_text())["map"]


def identifier_problems(label: str, payload: str, mapping: dict[str, str]) -> list[str]:
    """Unmapped lab identifiers still present in a model payload."""
    problems = []
    lowered = payload.lower()
    for original in sorted({key.lower() for key in mapping}):
        if original in lowered:
            problems.append(f"{label}: un-substituted lab identifier {original!r}")

    substituted = {value.lower() for value in mapping.values()}
    found = set(SID_PATTERN.findall(payload)) | set(PRIVATE_IP_PATTERN.findall(payload))
    for token in sorted(found):
        if token.lower() not in substituted:
            problems.append(
                f"{label}: identifier {token!r} is absent from tools/environment_map.json; "
                "add a substitution before shipping it"
            )
    return problems


def check_identifier_hygiene(report: Report) -> str:
    mapping = environment_map()
    for scenario_id in SCENARIOS:
        for tier in TIERS:
            payload = json.dumps(load_context(scenario_id, tier))
            for problem in identifier_problems(f"{scenario_id}/{tier}", payload, mapping):
                report.fail(problem)
    return "contexts contain only identifiers the anonymization map produced"


def check_leakage(report: Report) -> str:
    for scenario_id in SCENARIOS:
        allowed = LEAK_ALLOW.get(scenario_id, set())
        for tier in TIERS:
            context = load_context(scenario_id, tier)
            framing = json.dumps(
                {key: value for key, value in context.items() if key != "telemetry"}
            ).lower()
            for term in LEAK_TERMS:
                if term in framing and term not in allowed:
                    report.fail(f"{scenario_id}/{tier}: answer-bearing term {term!r} in framing")
            payload = json.dumps(context).lower()
            for marker in SOURCE_MARKERS:
                if marker in payload:
                    report.fail(f"{scenario_id}/{tier}: source marker {marker!r} in model payload")
            if "mitre_attack" in payload:
                report.fail(f"{scenario_id}/{tier}: explicit MITRE block survived blinding")
            if not str(context.get("case_id", "")).startswith("CASE-"):
                report.fail(f"{scenario_id}/{tier}: opaque case id is missing")
    return "committed model payloads contain no source, answer, or scenario leakage"
