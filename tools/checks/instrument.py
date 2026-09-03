"""Smoke tests over the instrument itself: output contract, scoring, manifests, and balance."""

from __future__ import annotations

import statistics
from collections import Counter

from harness.batch import build_jobs
from harness.config import (
    DEFAULT_RUN_TIERS,
    ENTITY_TYPES,
    RUNS_PER_CELL,
    SCENARIOS,
    TIERS,
    build_experiment_manifest,
    load_context,
    load_gold,
    validate_experiment_manifest,
    validate_output,
)
from harness.reference import CLASSIFICATIONS
from harness.scoring import decision_scores, multiclass_brier, score_technique
from tools.checks.report import Report

# Always-Malicious baseline must stay below this or the suite can't separate real triage.
MAX_ALWAYS_MALICIOUS_SCORE = 0.9


def perfect_output(gold: dict) -> dict:
    """The response a reference key describes, used to prove the scorer credits it fully."""
    verdict = gold["verdict"]
    probabilities = dict.fromkeys(CLASSIFICATIONS, 0.0)
    probabilities[verdict["classification"]] = 1.0
    observation_ids = {item["id"]: index for index, item in enumerate(gold["observations"])}
    return {
        "classification": verdict["classification"],
        "severity": verdict["severity"],
        "recommended_action": verdict["recommended_action"],
        "classification_probabilities": probabilities,
        "mitre_techniques": verdict["mitre_techniques"],
        "observations": [
            {
                "id": f"E{index + 1}",
                "record_refs": item["record_refs"],
                "facts": [],
                "description": item["desc"],
            }
            for index, item in enumerate(gold["observations"])
        ],
        "inferences": [
            {
                "id": f"I{index + 1}",
                "supported_by": [
                    f"E{observation_ids[support] + 1}" for support in item["supports"]
                ],
                "description": item["desc"],
            }
            for index, item in enumerate(gold["inferences"])
        ],
        "affected_entities": [
            {
                "id": f"A{index + 1}",
                "type": entity["type"] if entity["type"] in ENTITY_TYPES else "other",
                "value": entity["value"],
                "record_refs": gold["observations"][0]["record_refs"],
            }
            for index, entity in enumerate(gold["entities"])
        ],
        "recommended_investigations": [
            {
                "id": f"P{index + 1}",
                "category": "other",
                "description": investigation["desc"],
            }
            for index, investigation in enumerate(gold["investigations"])
        ],
        "key_evidence_ids": ["E1"],
        "requires_verification": [
            {"id": f"U{index + 1}", "category": "other", "description": unknown["desc"]}
            for index, unknown in enumerate(gold["unknowns"])
        ],
        "summary": verdict["rationale"],
    }


def always_malicious_score() -> float:
    """Mean classification score for a system that answers Malicious to everything."""
    scores = [
        decision_scores(
            {
                "classification": "Malicious",
                "severity": "Critical",
                "recommended_action": "Contain / Isolate Endpoint",
                "mitre_techniques": ["T1003.001"],
            },
            load_gold(scenario_id),
        )["classification_score"]
        for scenario_id in SCENARIOS
    ]
    return statistics.mean(scores) if scores else 0.0


def check_scoring_and_manifests(report: Report) -> str:
    for scenario_id in SCENARIOS:
        gold = load_gold(scenario_id)
        output = perfect_output(gold)
        error = validate_output(output)
        if error:
            report.fail(f"{scenario_id}: gold-identical output violates schema: {error}")
            continue
        scores = decision_scores(output, gold)
        if any(value != 1.0 for key, value in scores.items() if key.endswith("_score")):
            report.fail(
                f"{scenario_id}: accepted primary decision does not receive full credit: {scores}"
            )
        if multiclass_brier(output["classification_probabilities"], gold) != 0.0:
            report.fail(
                f"{scenario_id}: one-hot accepted primary decision has non-zero Brier score"
            )

        for tier in TIERS:
            manifest = build_experiment_manifest(
                "test-model", tier, load_context(scenario_id, tier)
            )
            manifest_error = validate_experiment_manifest(manifest)
            if manifest_error:
                report.fail(f"{scenario_id}/{tier}: invalid experiment manifest: {manifest_error}")

    legacy_output = perfect_output(load_gold(next(iter(SCENARIOS))))
    legacy_output["signal_strength"] = 0.9
    if "unexpected fields" not in (validate_output(legacy_output) or ""):
        report.fail("obsolete confidence fields are not rejected by the output schema")

    mean = always_malicious_score()
    report.note(f"always-Malicious classification score: {mean:.3f}")
    if mean > MAX_ALWAYS_MALICIOUS_SCORE:
        report.fail("suite does not sufficiently expose always-Malicious behavior")
    if score_technique(["T1003.001"], []) >= 1.0:
        report.fail("asserting a technique on an empty accepted technique set is not penalized")

    default_jobs = build_jobs(["test-model"])
    if DEFAULT_RUN_TIERS != ["verbose"]:
        report.fail(f"default collection tiers are {DEFAULT_RUN_TIERS}, expected ['verbose']")
    if len(default_jobs) != len(SCENARIOS) * RUNS_PER_CELL:
        report.fail("default collection does not create three verbose runs per scenario and model")
    if any(job["tier"] != "verbose" for job in default_jobs):
        report.fail("default collection includes a non-verbose context tier")
    return "output, scoring dimensions and manifests pass smoke tests"


def check_balance(report: Report) -> str:
    classifications = Counter(
        load_gold(scenario)["verdict"]["classification"] for scenario in SCENARIOS
    )
    actions = Counter(
        load_gold(scenario)["verdict"]["recommended_action"] for scenario in SCENARIOS
    )
    report.note(f"primary classifications: {dict(classifications)}")
    report.note(f"primary actions: {dict(actions)}")
    if sum(count for label, count in classifications.items() if label != "Malicious") < 2:
        report.fail("fewer than two primary non-malicious references")
    return "suite includes malicious and non-malicious primary decisions"
