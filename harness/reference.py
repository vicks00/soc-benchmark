"""The triage decision vocabulary and the accepted-verdict rules built on it."""

from __future__ import annotations

CLASSIFICATIONS = ("Malicious", "Suspicious", "Benign", "Undetermined")
ACTIONS = (
    "Close",
    "Continue Monitoring",
    "Escalate for Investigation",
    "Contain / Isolate Endpoint",
)
ACTION_ALIASES = {"Escalate to Customer": "Escalate for Investigation"}
SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}
TERMINAL_ACTIONS = {"Close", "Continue Monitoring"}


def accepted_verdicts(gold: dict) -> list[dict]:
    verdict = gold["verdict"]
    primary = {
        key: verdict[key]
        for key in (
            "classification",
            "recommended_action",
            "severity",
            "mitre_techniques",
        )
    }
    primary.update(
        credit=1.0,
        source="primary",
        terminal_action_allowed=verdict["terminal_action_allowed"],
    )
    alternatives = []
    for index, authored in enumerate(verdict.get("acceptable_alternatives", []), start=1):
        alternative = dict(authored)
        alternative.setdefault("credit", 1.0)
        alternative.setdefault("credit_rationale", "")
        alternative.setdefault("terminal_action_allowed", verdict["terminal_action_allowed"])
        alternative["source"] = f"alternative_{index}"
        alternatives.append(alternative)
    return [primary, *alternatives]


def accepted_classifications(gold: dict) -> set[str]:
    """Classifications treated as fully correct for exact-accuracy and reliability metrics."""
    return {
        verdict["classification"] for verdict in accepted_verdicts(gold) if verdict["credit"] == 1.0
    }
