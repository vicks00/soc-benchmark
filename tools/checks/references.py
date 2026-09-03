"""Reference key structure, and whether its claims are reachable from the telemetry."""

from __future__ import annotations

import json
import re

from harness.config import SCENARIOS, TECHNIQUE_PATTERN, load_context, load_gold
from harness.reference import (
    ACTIONS,
    CLASSIFICATIONS,
    SEVERITIES,
    TERMINAL_ACTIONS,
    accepted_verdicts,
)
from tools.checks.report import Report

TECHNIQUE = re.compile(TECHNIQUE_PATTERN)
TIMESTAMP_PATTERN = re.compile(r"20\d{2}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?")

OBSOLETE_GOLD_FIELDS = {
    "confidence_anchor",
    "signal_strength_anchor",
    "benign_plausibility_anchor",
    "_rationale",
    "evidence",
    "pivots",
}

# Absence claims belong in inferences, not observations.
ABSENCE_PATTERN = re.compile(
    r"\b(no|none|absent|without|never|nothing|did not|does not|not observed)\b", re.I
)

TOP_LEVEL_FIELDS = {
    "verdict",
    "observations",
    "inferences",
    "entities",
    "investigations",
    "unknowns",
    "scenario_id",
    "scenario_family",
}
VERDICT_FIELDS = {
    "classification",
    "recommended_action",
    "severity",
    "mitre_techniques",
    "terminal_action_allowed",
    "rationale",
    "acceptable_alternatives",
}
ALTERNATIVE_REQUIRED_FIELDS = {
    "classification",
    "recommended_action",
    "severity",
    "mitre_techniques",
    "rationale",
    "terminal_action_allowed",
}
ALTERNATIVE_OPTIONAL_FIELDS = {"credit", "credit_rationale"}


def has_matcher(item: dict) -> bool:
    return bool(item.get("all") or item.get("any"))


def matcher_values(item: dict) -> list[str]:
    return [str(value).lower() for value in (item.get("all") or item.get("any") or [])]


def _walk_keys(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _walk_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_keys(nested)


def _signature(verdict: dict) -> tuple:
    return (
        verdict["classification"],
        verdict["recommended_action"],
        verdict["severity"],
        tuple(verdict["mitre_techniques"]),
    )


def _check_verdict(report: Report, scenario_id: str, verdict: dict):
    if set(verdict) != VERDICT_FIELDS:
        report.fail(f"{scenario_id}: verdict fields do not match the schema")
        return
    if verdict["classification"] not in CLASSIFICATIONS:
        report.fail(f"{scenario_id}: invalid primary classification")
    if verdict["recommended_action"] not in ACTIONS:
        report.fail(f"{scenario_id}: invalid primary action")
    if verdict["severity"] not in SEVERITIES:
        report.fail(f"{scenario_id}: invalid primary severity")
    if not isinstance(verdict["terminal_action_allowed"], bool):
        report.fail(f"{scenario_id}: terminal_action_allowed must be boolean")
    if not isinstance(verdict["rationale"], str) or not verdict["rationale"].strip():
        report.fail(f"{scenario_id}: verdict rationale is empty")
    if not isinstance(verdict["mitre_techniques"], list) or any(
        not TECHNIQUE.fullmatch(str(value)) for value in verdict["mitre_techniques"]
    ):
        report.fail(f"{scenario_id}: invalid primary MITRE techniques")

    seen = {_signature(verdict)}
    for alternative in verdict["acceptable_alternatives"]:
        fields = set(alternative)
        if not fields >= ALTERNATIVE_REQUIRED_FIELDS or fields - (
            ALTERNATIVE_REQUIRED_FIELDS | ALTERNATIVE_OPTIONAL_FIELDS
        ):
            report.fail(f"{scenario_id}: acceptable alternative fields do not match the schema")
            continue
        signature = _signature(alternative)
        if signature in seen:
            report.fail(f"{scenario_id}: duplicate accepted verdict {signature}")
        seen.add(signature)
        if alternative["classification"] not in CLASSIFICATIONS:
            report.fail(f"{scenario_id}: alternative has invalid classification")
        if alternative["recommended_action"] not in ACTIONS:
            report.fail(f"{scenario_id}: alternative has invalid action")
        if alternative["severity"] not in SEVERITIES:
            report.fail(f"{scenario_id}: alternative has invalid severity")
        if not alternative["rationale"].strip():
            report.fail(f"{scenario_id}: alternative rationale is empty")
        if not isinstance(alternative["terminal_action_allowed"], bool):
            report.fail(f"{scenario_id}: alternative terminal_action_allowed must be boolean")
        credit = alternative.get("credit", 1.0)
        valid_credit = not (
            isinstance(credit, bool)
            or not isinstance(credit, (int, float))
            or not 0.0 <= credit <= 1.0
        )
        if not valid_credit:
            report.fail(f"{scenario_id}: alternative credit must be numeric from 0 to 1")
        if (
            valid_credit
            and credit < 1.0
            and not str(alternative.get("credit_rationale", "")).strip()
        ):
            report.fail(f"{scenario_id}: partial-credit alternative needs a credit_rationale")
        if not re.search(r"\bO\d+\b", alternative["rationale"]) or not re.search(
            r"\b[RFP]\d{6}\b", alternative["rationale"]
        ):
            report.fail(
                f"{scenario_id}: alternative rationale must cite observation and record ids"
            )
        if (
            alternative["recommended_action"] in TERMINAL_ACTIONS
            and not alternative["terminal_action_allowed"]
        ):
            report.fail(
                f"{scenario_id}: alternative permits an unsafe Close or Continue Monitoring"
            )
        if alternative["terminal_action_allowed"] and not verdict["terminal_action_allowed"]:
            report.fail(
                f"{scenario_id}: alternative expands permission to Close or Continue Monitoring"
            )


def _check_reference_items(report: Report, scenario_id: str, gold: dict):
    observations = gold["observations"]
    observation_ids = {item.get("id") for item in observations}
    if len(observation_ids) != len(observations) or None in observation_ids:
        report.fail(f"{scenario_id}: observation ids are missing or duplicated")
    for observation in observations:
        identifier = observation.get("id")
        record_refs = observation.get("record_refs")
        if (
            not isinstance(record_refs, list)
            or not record_refs
            or any(not isinstance(ref, str) or not ref.strip() for ref in record_refs)
        ):
            report.fail(f"{scenario_id}: observation {identifier} has no telemetry record refs")
        if not observation.get("event_refs") or not all(
            isinstance(reference, str) and reference.strip()
            for reference in observation["event_refs"]
        ):
            report.fail(f"{scenario_id}: observation {identifier} has no event refs")
        if not has_matcher(observation):
            report.fail(f"{scenario_id}: observation {identifier} has no matcher")
        if ABSENCE_PATTERN.search(observation.get("desc", "")):
            report.fail(
                f"{scenario_id}: observation {identifier} is an absence claim; "
                "move it to inference and scope it to coverage"
            )

    inference_ids = set()
    for inference in gold["inferences"]:
        inference_id = inference.get("id")
        if not inference_id or inference_id in inference_ids:
            report.fail(f"{scenario_id}: inference ids are missing or duplicated")
        inference_ids.add(inference_id)
        supports = set(inference.get("supports", []))
        if not supports or not supports <= observation_ids:
            report.fail(f"{scenario_id}: inference {inference_id} has invalid observation support")
        if not has_matcher(inference):
            report.fail(f"{scenario_id}: inference {inference_id} has no matcher")

    for key in ("entities", "investigations", "unknowns"):
        if not isinstance(gold[key], list) or not gold[key]:
            report.fail(f"{scenario_id}: reference {key} must be a non-empty list")
            continue
        for item in gold[key]:
            if not has_matcher(item):
                report.fail(
                    f"{scenario_id}: {key} item {item.get('id') or item.get('type')} has no matcher"
                )


def check_references(report: Report) -> str:
    for scenario_id in SCENARIOS:
        gold = load_gold(scenario_id)
        if set(gold) != TOP_LEVEL_FIELDS:
            report.fail(f"{scenario_id}: top-level reference fields do not match the schema")
            continue
        obsolete = OBSOLETE_GOLD_FIELDS & set(_walk_keys(gold))
        if obsolete:
            report.fail(f"{scenario_id}: obsolete V2 fields survived: {sorted(obsolete)}")
        _check_verdict(report, scenario_id, gold["verdict"])
        _check_reference_items(report, scenario_id, gold)
        if gold["verdict"]["terminal_action_allowed"] and not any(
            verdict["classification"] == "Benign" for verdict in accepted_verdicts(gold)
        ):
            report.fail(
                f"{scenario_id}: Close or Continue Monitoring allowed without an accepted Benign decision"
            )
    return f"{len(SCENARIOS)} reference keys are structurally valid"


def check_reference_reachability(report: Report) -> str:
    for scenario_id in SCENARIOS:
        gold = load_gold(scenario_id)
        verbose_context = load_context(scenario_id, "verbose")
        verbose = json.dumps(verbose_context).lower()
        record_ids = {record.get("record_id") for record in verbose_context["telemetry"]}
        for key in ("observations", "entities"):
            for item in gold[key]:
                values = matcher_values(item)
                if not values or not any(value in verbose for value in values):
                    report.fail(
                        f"{scenario_id}: {key} item {item.get('id') or item.get('type')} "
                        "has no matcher present in verbose telemetry"
                    )
        for observation in gold["observations"]:
            missing_refs = set(observation.get("record_refs", [])) - record_ids
            if missing_refs:
                report.fail(
                    f"{scenario_id}: observation {observation['id']} cites absent telemetry "
                    f"records {sorted(missing_refs)}"
                )
            timestamps = [
                match.replace("T", " ")
                for reference in observation["event_refs"]
                for match in TIMESTAMP_PATTERN.findall(reference)
            ]
            if timestamps and not any(timestamp.lower() in verbose for timestamp in timestamps):
                report.fail(
                    f"{scenario_id}: observation {observation['id']} event reference timestamp "
                    "is not present in verbose telemetry"
                )
    return "all required observations and entities are reachable from verbose telemetry"
