"""Score saved benchmark results without collapsing distinct measurements into one number."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from harness import judge
from harness.config import (
    INSTRUMENT_VERSION,
    LEGACY_OUTPUT_DIR,
    LOWER_IS_BETTER,
    OUTPUT_DIR,
    REVIEW_MODES,
    SCENARIOS,
    SOC_PROFILE,
    TIERS,
    USE_LLM_JUDGE,
    WEIGHTING_PROFILES,
    band_of,
    context_sha256,
    cost_usd,
    instrument_at_least,
    load_context,
    load_gold,
    profile_disqualifiers,
    profile_score,
    provider_of,
    recommended_review_mode,
    sweep_output_dir,
    validate_experiment_manifest,
    validate_output,
)
from harness.reference import (
    ACTION_ALIASES,
    ACTIONS,
    CLASSIFICATIONS,
    SEVERITIES,
    SEVERITY_RANK,
    TERMINAL_ACTIONS,
    accepted_classifications,
    accepted_verdicts,
)

CLASS_MATRIX = {
    "Malicious": {"Malicious": 1.0, "Suspicious": 0.7, "Undetermined": 0.3, "Benign": 0.0},
    "Suspicious": {"Suspicious": 1.0, "Malicious": 0.7, "Undetermined": 0.6, "Benign": 0.1},
    "Benign": {"Benign": 1.0, "Suspicious": 0.6, "Undetermined": 0.6, "Malicious": 0.3},
    "Undetermined": {"Undetermined": 1.0, "Suspicious": 0.7, "Malicious": 0.5, "Benign": 0.5},
}


def _norm(value, options):
    if not value:
        return None
    candidate = str(value).strip().lower()
    return next((option for option in options if candidate == option.lower()), None)


def score_classification(pred, gold):
    prediction = _norm(pred, CLASSIFICATIONS)
    return CLASS_MATRIX.get(gold, {}).get(prediction, 0.0) if prediction else 0.0


def score_action(pred, gold):
    pred = ACTION_ALIASES.get(pred, pred)
    gold = ACTION_ALIASES.get(gold, gold)
    prediction = _norm(pred, ACTIONS)
    if prediction is None:
        return 0.0
    distance = ACTIONS.index(prediction) - ACTIONS.index(gold)
    penalty = 0.34 if distance < 0 else 0.17
    return max(0.0, 1 - penalty * abs(distance))


def score_severity(pred, gold):
    """Quadratic ordinal utility: exact=1, one level away=.75, two or more=0."""
    prediction = _norm(pred, SEVERITIES)
    if prediction is None:
        return 0.0
    distance = abs(SEVERITY_RANK[prediction] - SEVERITY_RANK[gold])
    return max(0.0, 1 - (distance / 2) ** 2)


def severity_measurements(pred, gold: dict) -> dict:
    prediction = _norm(pred, SEVERITIES)
    references = accepted_verdicts(gold)
    if prediction is None:
        return {
            "severity_score": 0.0,
            "severity_exact": 0.0,
            "severity_mae": 4.0,
            "severity_undercall": True,
            "severe_undercall": True,
            "severity_credit_source": "primary",
            "severity_credit": 1.0,
        }
    rank = SEVERITY_RANK[prediction]
    primary_distance = abs(rank - SEVERITY_RANK[references[0]["severity"]])
    credited_distance = float(primary_distance)
    source, credit = "primary", 1.0
    severity_score, score_source, score_credit = _credited_score(
        prediction, references, score_severity, "severity"
    )
    for reference in references[1:]:
        alternative_distance = abs(rank - SEVERITY_RANK[reference["severity"]])
        relieved = primary_distance - reference["credit"] * max(
            0, primary_distance - alternative_distance
        )
        if relieved < credited_distance:
            credited_distance = relieved
            source, credit = reference["source"], reference["credit"]

    fully_accepted_ranks = [
        SEVERITY_RANK[reference["severity"]]
        for reference in references
        if reference["credit"] == 1.0
    ]
    exact = any(rank == value for value in fully_accepted_ranks)
    undercall_distance = min(fully_accepted_ranks) - rank
    return {
        "severity_score": severity_score,
        "severity_exact": float(exact),
        "severity_mae": credited_distance,
        "severity_undercall": undercall_distance > 0,
        "severe_undercall": undercall_distance >= 2,
        "severity_credit_source": score_source if severity_score > 0 else source,
        "severity_credit": score_credit if severity_score > 0 else credit,
    }


def score_technique(pred_list, gold_list):
    predicted = {str(value).upper().strip() for value in (pred_list or []) if str(value).strip()}
    if not gold_list:
        return 1.0 if not predicted else max(0.0, 1 - 0.34 * len(predicted))
    total = sum(
        1.0
        if gold.upper() in predicted
        else (
            0.5
            if any(item.split(".")[0] == gold.upper().split(".")[0] for item in predicted)
            else 0.0
        )
        for gold in gold_list
    )
    return total / len(gold_list)


def _credited_score(
    prediction, references: list[dict], scorer, field: str
) -> tuple[float, str, float]:
    """Blend relief from an inferior alternative with the raw score against the primary.

    Credit 1 reproduces best-of-accepted-set scoring. Credit 0 gives no relief. Intermediate
    credit moves only the improvement over the primary, so an alternative can never make a raw
    distance score worse.
    """
    primary = scorer(prediction, references[0][field])
    best = (primary, "primary", 1.0)
    for reference in references[1:]:
        alternative = scorer(prediction, reference[field])
        blended = primary + reference["credit"] * max(0.0, alternative - primary)
        if blended > best[0]:
            best = (blended, reference["source"], reference["credit"])
    return best


def decision_scores(output: dict, gold: dict) -> dict:
    references = accepted_verdicts(gold)
    measurements = {
        "classification": _credited_score(
            output.get("classification"), references, score_classification, "classification"
        ),
        "action": _credited_score(
            output.get("recommended_action"), references, score_action, "recommended_action"
        ),
        "technique": _credited_score(
            output.get("mitre_techniques"), references, score_technique, "mitre_techniques"
        ),
    }
    scores = {}
    for metric, (value, source, credit) in measurements.items():
        scores[f"{metric}_score"] = value
        scores[f"{metric}_credit_source"] = source
        scores[f"{metric}_credit"] = credit
    scores.update(severity_measurements(output.get("severity"), gold))
    return scores


def brier_measurement(probabilities: dict, gold: dict) -> dict:
    """Score confidence against the primary or a credit-weighted alternative target.

    A partial alternative moves probability mass from the primary label to the alternative label.
    Confidence concentrated on an inferior answer therefore remains penalized, while credit 1
    reproduces the previous minimum-over-accepted-labels behavior.
    """
    references = accepted_verdicts(gold)
    primary_class = references[0]["classification"]
    targets = [("primary", 1.0, {primary_class: 1.0})]
    for reference in references[1:]:
        target = {primary_class: 1.0 - reference["credit"]}
        target[reference["classification"]] = (
            target.get(reference["classification"], 0.0) + reference["credit"]
        )
        targets.append((reference["source"], reference["credit"], target))

    scored = []
    for source, credit, target in targets:
        value = sum(
            (float(probabilities[classification]) - target.get(classification, 0.0)) ** 2
            for classification in CLASSIFICATIONS
        )
        scored.append((value, source, credit))
    value, source, credit = min(scored, key=lambda item: item[0])
    return {"brier": value, "brier_credit_source": source, "brier_credit": credit}


def multiclass_brier(probabilities: dict, gold: dict) -> float:
    """Lower is better. Range is 0 to 2 for a four-class one-hot outcome."""
    return brier_measurement(probabilities, gold)["brier"]


UNIFORM_BRIER = 0.75


def brier_skill(brier: float) -> float:
    """Improvement over assigning 0.25 probability to each classification."""
    return 1 - brier / UNIFORM_BRIER


def probability_consistent(output: dict) -> bool:
    probabilities = output["classification_probabilities"]
    maximum = max(probabilities.values())
    modes = {key for key, value in probabilities.items() if value == maximum}
    return output["classification"] in modes


def _text(item):
    if isinstance(item, dict):
        return " ".join(str(value) for value in item.values()).lower()
    return str(item).lower()


def _matches(text, reference):
    required = [value.lower() for value in reference.get("all", [])]
    alternatives = [value.lower() for value in reference.get("any", [])]
    if required and not all(value in text for value in required):
        return False
    if alternatives and not any(value in text for value in alternatives):
        return False
    return bool(required or alternatives)


def _coverage(model_items, reference_items) -> float:
    texts = [_text(item) for item in (model_items or [])]
    if not reference_items:
        return 1.0
    covered = sum(
        1 for reference in reference_items if any(_matches(text, reference) for text in texts)
    )
    return covered / len(reference_items)


def _keyword_precision(model_items, reference_items) -> float:
    texts = [_text(item) for item in (model_items or [])]
    if not texts:
        return 1.0
    return sum(
        1 for text in texts if any(_matches(text, reference) for reference in reference_items)
    ) / len(texts)


def grounding_scores(
    output: dict,
    gold: dict,
    scenario_id: str,
    use_judge: bool,
    allow_judge_fallback: bool = False,
    tier: str = "verbose",
    instrument_version: str = INSTRUMENT_VERSION,
) -> dict:
    if use_judge:
        try:
            return judge.judge_grounding(
                scenario_id, tier, gold, output, instrument_version=instrument_version
            )
        except Exception as exc:
            if not allow_judge_fallback:
                raise RuntimeError(f"grounding judge failed for {scenario_id}") from exc
            print(f"  [judge fallback -> keyword] {exc}")

    legacy = not instrument_at_least(instrument_version, (3, 4))
    observations = output.get("evidence", []) if legacy else output.get("observations", [])
    inferences = [] if legacy else output.get("inferences", [])
    evidence = [*observations, *inferences]
    evidence_references = [*gold["observations"], *gold["inferences"]]
    evidence_precision = _keyword_precision(evidence, evidence_references)
    entity_precision = _keyword_precision(output.get("affected_entities"), gold["entities"])
    return {
        "evidence_precision": evidence_precision,
        "observation_recall": _coverage(observations, gold["observations"]),
        "inference_recall": _coverage(evidence, gold["inferences"]),
        "entity_precision": entity_precision,
        "entity_recall": _coverage(output.get("affected_entities"), gold["entities"]),
        "investigation_recall": _coverage(
            output.get("recommended_investigations"), gold["investigations"]
        ),
        "unknown_recall": _coverage(output.get("requires_verification"), gold["unknowns"]),
        "unsupported_claim": bool(evidence) and evidence_precision < 1.0,
    }


RUN_METRICS = (
    "classification_score",
    "action_score",
    "severity_score",
    "severity_exact",
    "severity_mae",
    "technique_score",
    "evidence_precision",
    "observation_recall",
    "inference_recall",
    "entity_precision",
    "entity_recall",
    "investigation_recall",
    "unknown_recall",
    "brier",
    "brier_skill",
)

# Null on failed runs so failures are not scored as zeros.
UNSCORED_FIELDS = (
    *RUN_METRICS,
    "probability_consistent",
    "unsupported_claim",
    "classification",
    "confidence",
    "correct",
    "acceptable",
    "classification_match_credit",
    "credited_alternative",
    "classification_credit_source",
    "classification_credit",
    "action_credit_source",
    "action_credit",
    "severity_credit_source",
    "severity_credit",
    "technique_credit_source",
    "technique_credit",
    "brier_credit_source",
    "brier_credit",
    "unsafe_close_or_monitor",
    "false_alarm",
    "correct_close",
    "severity_undercall",
    "severe_undercall",
)


def score_run(
    result: dict,
    gold: dict,
    use_judge: bool,
    allow_judge_fallback: bool = False,
) -> dict:
    output = result.get("output")
    manifest = result.get("experiment") or {}
    instrument_version = manifest.get("instrument_version", "")
    records_by_id = None
    if instrument_at_least(instrument_version, (3, 4)):
        context = load_context(result["scenario"], result["tier"])
        records_by_id = {
            record["record_id"]: record
            for record in context["telemetry"]
            if record.get("record_id")
        }
    output_error = (
        validate_output(
            output,
            instrument_version=instrument_version,
            records_by_id=records_by_id,
        )
        if output is not None
        else "missing output"
    )
    # The instrument version is not checked here: main() has already established that every run in
    # this scoring pass shares one, and a run is not invalid for having been collected earlier.
    manifest_error = validate_experiment_manifest(result.get("experiment"), expected_version=None)
    valid = (
        output is not None
        and not result.get("error")
        and output_error is None
        and manifest_error is None
    )
    error_text = str(result.get("error") or output_error or manifest_error or "").lower()
    failure_kind = None
    if not valid:
        if any(marker in error_text for marker in ("refusal", "refused", "safety policy")):
            failure_kind = "refusal"
        elif any(marker in error_text for marker in ("timeout", "timed out", "expired")):
            failure_kind = "timeout"
        elif output_error:
            failure_kind = "invalid_output"
        else:
            failure_kind = "provider_error"
    primary = gold["verdict"]
    row = {
        "sweep": result.get("sweep", ""),
        "scenario": result["scenario"],
        "model": result["model"],
        "model_version": result.get("model_version") or result["model"],
        "run_idx": result.get("run_idx", 0),
        "tier": result["tier"],
        "experiment_id": (result.get("experiment") or {}).get("experiment_id", ""),
        "prompt_id": (result.get("experiment") or {}).get("prompt_id", ""),
        "expected_runs": (result.get("experiment") or {}).get("runs_per_cell", 0),
        "valid": valid,
        "failure_kind": failure_kind,
        "reference_class": primary["classification"],
        "scenario_family": gold.get("scenario_family", "unclassified"),
        "input_tokens": result["input_tokens"],
        "output_tokens": result["output_tokens"],
        "total_tokens": result["input_tokens"] + result["output_tokens"],
        "cost": cost_usd(
            result["model"], result["input_tokens"], result["output_tokens"], batch=True
        ),
    }
    if not valid:
        row.update(dict.fromkeys(UNSCORED_FIELDS))
        return row

    row.update(decision_scores(output, gold))
    row.update(
        grounding_scores(
            output,
            gold,
            result["scenario"],
            use_judge,
            allow_judge_fallback,
            tier=result["tier"],
            instrument_version=instrument_version,
        )
    )
    predicted_class = _norm(output.get("classification"), CLASSIFICATIONS)
    predicted_action = _norm(
        ACTION_ALIASES.get(output.get("recommended_action"), output.get("recommended_action")),
        ACTIONS,
    )
    references = accepted_verdicts(gold)
    accepted_classes = accepted_classifications(gold)
    acceptable_classes = {
        reference["classification"] for reference in references if reference["credit"] > 0
    }
    classification_credit = max(
        (
            reference["credit"]
            for reference in references
            if reference["classification"] == predicted_class
        ),
        default=0.0,
    )
    brier_result = brier_measurement(output["classification_probabilities"], gold)
    raw_brier = round(brier_result["brier"], 4)
    safe_terminal = primary["terminal_action_allowed"] or any(
        reference["credit"] == 1.0
        and reference["terminal_action_allowed"]
        and ACTION_ALIASES.get(reference["recommended_action"], reference["recommended_action"])
        == predicted_action
        for reference in references[1:]
    )
    credit_sources = [
        row["classification_credit_source"],
        row["action_credit_source"],
        row["severity_credit_source"],
        row["technique_credit_source"],
        brier_result["brier_credit_source"],
    ]
    row.update(
        brier=raw_brier,
        brier_skill=round(brier_skill(raw_brier), 4),
        brier_credit_source=brier_result["brier_credit_source"],
        brier_credit=brier_result["brier_credit"],
        probability_consistent=probability_consistent(output),
        classification=predicted_class,
        # Stated confidence paired with whether the call was right, so a reliability diagram can
        # be drawn without re-reading every raw response.
        confidence=round(max(output["classification_probabilities"].values()), 4),
        correct=predicted_class in accepted_classes,
        acceptable=predicted_class in acceptable_classes,
        classification_match_credit=classification_credit,
        credited_alternative=any(source != "primary" for source in credit_sources),
        unsafe_close_or_monitor=(not safe_terminal and predicted_action in TERMINAL_ACTIONS),
        false_alarm=(accepted_classes == {"Benign"} and predicted_class == "Malicious"),
        correct_close=(safe_terminal and predicted_action == "Close"),
    )
    return row


def _numeric(values):
    return [
        value for value in values if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]


def _mean(values):
    numeric = _numeric(values)
    return round(statistics.mean(numeric), 4) if numeric else None


def _stdev(values):
    """Sample standard deviation, or None when fewer than two observations exist."""
    numeric = _numeric(values)
    return round(statistics.stdev(numeric), 4) if len(numeric) > 1 else None


def aggregate(rows: list[dict]) -> list[dict]:
    cells = defaultdict(list)
    for row in rows:
        cells[(row["scenario"], row["experiment_id"])].append(row)

    aggregated = []
    for (scenario, experiment), runs in cells.items():
        valid = [run for run in runs if run["valid"]]
        first = runs[0]
        expected_runs = max(run["expected_runs"] for run in runs)
        # Prefer the valid runs' token usage, but fall back to all runs when none scored. A mean of
        # exactly zero is a real measurement, so this cannot be an `or` chain.
        mean_tokens = _mean([run["total_tokens"] for run in valid])
        if mean_tokens is None:
            mean_tokens = _mean([run["total_tokens"] for run in runs])
        item = {
            "scenario": scenario,
            "reference_class": first["reference_class"],
            "scenario_family": first["scenario_family"],
            "provider": provider_of(first["model"]),
            "band": band_of(first["model"]),
            "model": first["model"],
            "model_versions": ", ".join(sorted({run["model_version"] for run in runs})),
            "tier": first["tier"],
            "experiment_id": experiment,
            "prompt_id": first["prompt_id"],
            "runs": expected_runs,
            "observed_runs": len(runs),
            "valid_runs": len(valid),
            "completion": round(len(valid) / expected_runs, 3) if expected_runs else 0.0,
            "missing_result_runs": max(0, expected_runs - len(runs)),
            "probability_consistency": (
                round(sum(bool(run["probability_consistent"]) for run in valid) / len(valid), 3)
                if valid
                else None
            ),
            "unsupported_claim_runs": sum(bool(run["unsupported_claim"]) for run in valid),
            "refusal_runs": sum(run["failure_kind"] == "refusal" for run in runs),
            "timeout_runs": sum(run["failure_kind"] == "timeout" for run in runs),
            "invalid_output_runs": sum(run["failure_kind"] == "invalid_output" for run in runs),
            "provider_error_runs": sum(run["failure_kind"] == "provider_error" for run in runs),
            "unsafe_close_or_monitor_runs": sum(
                bool(run["unsafe_close_or_monitor"]) for run in valid
            ),
            "false_alarms": sum(bool(run["false_alarm"]) for run in valid),
            "correct_closes": sum(bool(run["correct_close"]) for run in valid),
            "acceptable_runs": sum(bool(run["acceptable"]) for run in valid),
            "credited_alternative_runs": sum(bool(run["credited_alternative"]) for run in valid),
            "severity_undercalls": sum(bool(run["severity_undercall"]) for run in valid),
            "severe_undercalls": sum(bool(run["severe_undercall"]) for run in valid),
            "total_tokens": mean_tokens,
            "cost": round(sum(run["cost"] for run in runs if isinstance(run["cost"], float)), 4),
        }
        item.update({metric: _mean([run[metric] for run in valid]) for metric in RUN_METRICS})
        aggregated.append(item)
    aggregated.sort(key=lambda item: (item["scenario"], item["experiment_id"]))
    return aggregated


def _profile_input(scenarios: list[dict]) -> dict:
    summary = {metric: _mean([item[metric] for item in scenarios]) for metric in RUN_METRICS}
    for counter in (
        "unsafe_close_or_monitor_runs",
        "false_alarms",
        "unsupported_claim_runs",
        "severity_undercalls",
        "severe_undercalls",
    ):
        summary[counter] = sum(item[counter] for item in scenarios)
    return summary


def _ranked_experiments(scores: dict[str, tuple[float | None, list[str]]]) -> list[str]:
    return [
        experiment
        for experiment, _ in sorted(
            scores.items(),
            key=lambda item: (
                bool(item[1][1]),
                -(item[1][0] if item[1][0] is not None else -999),
                item[0],
            ),
        )
    ]


def model_summary(aggregated: list[dict]) -> list[dict]:
    experiments = defaultdict(list)
    for item in aggregated:
        experiments[item["experiment_id"]].append(item)

    summaries = []
    for experiment, scenarios in experiments.items():
        first = scenarios[0]
        summary = {
            "provider": first["provider"],
            "band": first["band"],
            "model": first["model"],
            "model_versions": ", ".join(sorted({item["model_versions"] for item in scenarios})),
            "tier": first["tier"],
            "experiment_id": experiment,
            "prompt_id": first["prompt_id"],
            "scenarios": len(scenarios),
            "valid_scenarios": sum(item["valid_runs"] > 0 for item in scenarios),
            "completion": _mean([item["completion"] for item in scenarios]),
            "probability_consistency": _mean(
                [item["probability_consistency"] for item in scenarios]
            ),
            "unsafe_close_or_monitor_runs": sum(
                item["unsafe_close_or_monitor_runs"] for item in scenarios
            ),
            "false_alarms": sum(item["false_alarms"] for item in scenarios),
            "correct_closes": sum(item["correct_closes"] for item in scenarios),
            "acceptable_runs": sum(item["acceptable_runs"] for item in scenarios),
            "credited_alternative_runs": sum(
                item["credited_alternative_runs"] for item in scenarios
            ),
            "severity_undercalls": sum(item["severity_undercalls"] for item in scenarios),
            "severe_undercalls": sum(item["severe_undercalls"] for item in scenarios),
            "unsupported_claim_runs": sum(item["unsupported_claim_runs"] for item in scenarios),
            "refusal_runs": sum(item["refusal_runs"] for item in scenarios),
            "timeout_runs": sum(item["timeout_runs"] for item in scenarios),
            "invalid_output_runs": sum(item["invalid_output_runs"] for item in scenarios),
            "provider_error_runs": sum(item["provider_error_runs"] for item in scenarios),
            "missing_result_runs": sum(item["missing_result_runs"] for item in scenarios),
            "cost": round(sum(item["cost"] for item in scenarios), 4),
        }
        # Spread is across scenarios, which is what the mean is taken over. With ten scenarios it
        # is the honest indication of whether two models are actually separated.
        for metric in RUN_METRICS:
            values = [item[metric] for item in scenarios]
            summary[metric] = _mean(values)
            summary[f"{metric}_sd"] = _stdev(values)
        summaries.append(summary)

    # Every declared profile is scored here rather than in the report, so the weighting is applied
    # once and the CSVs and the HTML can never disagree about a ranking.
    baseline = baseline_scores()
    for summary in summaries:
        review_mode = recommended_review_mode(summary)
        summary["profile_scores"] = {
            profile_id: profile_score(summary, profile_id, baseline)
            for profile_id in WEIGHTING_PROFILES
        }
        summary["profile_disqualifiers"] = {
            profile_id: profile_disqualifiers(summary, profile_id)
            for profile_id in WEIGHTING_PROFILES
        }
        summary["review_mode"] = review_mode
        # Flattened alongside the nested form so the CSV, which holds scalars only, still carries
        # the two values a reader is most likely to sort on.
        summary["soc_triage_score"] = summary["profile_scores"][SOC_PROFILE]
        summary["review_mode_label"] = review_mode["label"]

        scenario_cells = experiments[summary["experiment_id"]]
        families = defaultdict(list)
        for cell in scenario_cells:
            families[cell["scenario_family"]].append(cell)
        summary["family_scores"] = {}
        for family, cells in sorted(families.items()):
            family_input = _profile_input(cells)
            family_baseline = baseline_scores([cell["scenario"] for cell in cells])
            summary["family_scores"][family] = {
                "scenarios": len(cells),
                "soc_triage_score": profile_score(family_input, SOC_PROFILE, family_baseline),
                "classification_score": family_input["classification_score"],
                "action_score": family_input["action_score"],
                "unsafe_close_or_monitor_runs": family_input["unsafe_close_or_monitor_runs"],
            }

    # Jackknife the composite over scenarios. This shows how far a score or rank moves when any
    # single alert is removed, which is the relevant sensitivity check with only ten scenarios.
    scenario_ids = sorted({item["scenario"] for item in aggregated})
    loo_scores: dict[str, dict[str, tuple[float | None, list[str]]]] = {}
    for omitted in scenario_ids:
        remaining_ids = [scenario for scenario in scenario_ids if scenario != omitted]
        baseline = baseline_scores(remaining_ids)
        scores = {}
        for experiment, cells in experiments.items():
            remaining = [cell for cell in cells if cell["scenario"] != omitted]
            candidate = _profile_input(remaining)
            scores[experiment] = (
                profile_score(candidate, SOC_PROFILE, baseline),
                profile_disqualifiers(candidate, SOC_PROFILE),
            )
        loo_scores[omitted] = scores

    full_order = _ranked_experiments(
        {
            summary["experiment_id"]: (
                summary["soc_triage_score"],
                summary["profile_disqualifiers"][SOC_PROFILE],
            )
            for summary in summaries
        }
    )
    full_winner = full_order[0] if full_order else None
    for summary in summaries:
        experiment = summary["experiment_id"]
        by_scenario = {}
        ranks = []
        for omitted, scores in loo_scores.items():
            order = _ranked_experiments(scores)
            rank = order.index(experiment) + 1
            ranks.append(rank)
            by_scenario[omitted] = {
                "score": scores[experiment][0],
                "rank": rank,
                "winner_changed": bool(order and order[0] != full_winner),
            }
        values = [item["score"] for item in by_scenario.values() if item["score"] is not None]
        summary["leave_one_out"] = {
            "by_scenario": by_scenario,
            "score_min": min(values) if values else None,
            "score_max": max(values) if values else None,
            "rank_min": min(ranks) if ranks else None,
            "rank_max": max(ranks) if ranks else None,
            "winner_changes": sum(item["winner_changed"] for item in by_scenario.values()),
        }

    summaries.sort(key=lambda item: (item["provider"], item["band"], item["experiment_id"]))
    return summaries


def _write_csv(path, rows):
    # Nested values belong to the JSON, which the report reads. A CSV cell holding a dict is
    # unreadable in a spreadsheet, so those columns are dropped and their scalar equivalents kept.
    scalar = [
        key
        for key, value in (rows[0] if rows else {}).items()
        if not isinstance(value, (dict, list))
    ]
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=scalar, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def baseline_scores(scenario_ids: list[str] | None = None) -> dict:
    """A conservative queue policy that performs no case-specific analysis."""
    fixed = {
        "classification": "Malicious",
        "severity": "High",
        "recommended_action": "Escalate for Investigation",
        "mitre_techniques": [],
    }
    selected = scenario_ids or list(SCENARIOS)
    per_scenario = [decision_scores(fixed, load_gold(scenario)) for scenario in selected]
    return {
        "label": "conservative fixed policy",
        "policy": fixed,
        "brier": UNIFORM_BRIER,
        "brier_skill": 0.0,
        **{
            metric: _mean([scores[metric] for scores in per_scenario])
            for metric in ("classification_score", "action_score", "severity_score")
        },
    }


def suite_health(aggregated: list[dict], summaries: list[dict]) -> dict:
    by_scenario = defaultdict(list)
    for cell in aggregated:
        by_scenario[cell["scenario"]].append(cell)
    influence = []
    baseline = baseline_scores()
    for scenario, cells in sorted(by_scenario.items()):
        values = _numeric([cell["classification_score"] for cell in cells])
        soc_values = _numeric([profile_score(cell, SOC_PROFILE, baseline) for cell in cells])
        influence.append(
            {
                "scenario": scenario,
                "family": cells[0]["scenario_family"],
                "reference_class": cells[0]["reference_class"],
                "classification_range": round(max(values) - min(values), 4) if values else None,
                "soc_triage_score_range": (
                    round(max(soc_values) - min(soc_values), 4) if soc_values else None
                ),
                "unsafe_close_or_monitor_runs": sum(
                    cell["unsafe_close_or_monitor_runs"] for cell in cells
                ),
                "winner_changed": any(
                    summary["leave_one_out"]["by_scenario"][scenario]["winner_changed"]
                    for summary in summaries
                ),
            }
        )
    family_counts = defaultdict(int)
    class_counts = defaultdict(int)
    for cells in by_scenario.values():
        family_counts[cells[0]["scenario_family"]] += 1
        class_counts[cells[0]["reference_class"]] += 1
    warnings = []
    sparse_families = sorted(family for family, count in family_counts.items() if count < 3)
    if sparse_families:
        warnings.append(
            "Scenario families with fewer than three alerts: " + ", ".join(sparse_families)
        )
    sparse_classes = sorted(label for label, count in class_counts.items() if count < 3)
    if sparse_classes:
        warnings.append(
            "Reference classes with fewer than three alerts: " + ", ".join(sparse_classes)
        )
    changed = [item["scenario"] for item in influence if item["winner_changed"]]
    if changed:
        warnings.append("Removing one scenario changes the winner: " + ", ".join(changed))
    return {
        "warnings": warnings,
        "family_counts": dict(sorted(family_counts.items())),
        "reference_class_counts": dict(sorted(class_counts.items())),
        "scenario_influence": sorted(
            influence,
            key=lambda item: (
                -(item["classification_range"] or 0),
                -item["unsafe_close_or_monitor_runs"],
                item["scenario"],
            ),
        ),
    }


def scorecard_dir(sweeps: list[str]) -> Path:
    """Scorecards land beside the raw runs they were computed from. Scoring several sweeps at once
    gets its own directory so a combined view never overwrites either single-sweep scorecard."""
    if len(sweeps) == 1:
        return sweep_output_dir(sweeps[0])
    if not sweeps:
        return OUTPUT_DIR / "unlabelled"
    return OUTPUT_DIR / f"{sweeps[0]}_to_{sweeps[-1]}"


def write_reports(
    runs: list[dict],
    aggregated: list[dict],
    summaries: list[dict],
    grounding_mode: str,
    sweeps: list[str],
    instrument_version: str = INSTRUMENT_VERSION,
) -> Path:
    destination = scorecard_dir(sweeps)
    judge_version = (
        judge.JUDGE_VERSION
        if instrument_at_least(instrument_version, (3, 4))
        else judge.LEGACY_JUDGE_VERSION
    )
    destination.mkdir(parents=True, exist_ok=True)
    _write_csv(destination / "scorecard.csv", aggregated)
    _write_csv(destination / "scorecard_by_model.csv", summaries)
    _write_csv(destination / "scorecard_runs.csv", runs)
    (destination / "scorecard.json").write_text(
        json.dumps(
            {
                "instrument_version": instrument_version,
                "scoring_version": INSTRUMENT_VERSION,
                "judge_version": judge_version,
                "grounding_mode": grounding_mode,
                "generated": datetime.now(UTC).isoformat(timespec="seconds"),
                "sweeps": sweeps,
                "scenario_count": len(SCENARIOS),
                "run_metrics": list(RUN_METRICS),
                "lower_is_better": sorted(LOWER_IS_BETTER),
                "default_profile": SOC_PROFILE,
                "review_modes": REVIEW_MODES,
                "profiles": {
                    profile_id: {
                        "label": profile["label"],
                        "weights": profile["weights"],
                        "disqualify": list(profile["disqualify"]),
                        "baseline_relative": bool(profile.get("baseline_relative")),
                    }
                    for profile_id, profile in WEIGHTING_PROFILES.items()
                },
                "baseline": baseline_scores(),
                "suite_health": suite_health(aggregated, summaries),
                "alternative_catalog": {
                    scenario: [
                        {
                            "source": reference["source"],
                            "credit": reference["credit"],
                            "classification": reference["classification"],
                            "recommended_action": reference["recommended_action"],
                            "severity": reference["severity"],
                            "mitre_techniques": reference["mitre_techniques"],
                            "terminal_action_allowed": reference["terminal_action_allowed"],
                            "rationale": reference.get("rationale", ""),
                            "credit_rationale": reference.get("credit_rationale", ""),
                        }
                        for reference in accepted_verdicts(load_gold(scenario))[1:]
                    ]
                    for scenario in SCENARIOS
                },
                "runs": runs,
                "cells": aggregated,
                "summaries": summaries,
            },
            indent=2,
        )
        + "\n"
    )

    lines = [
        (
            f"# Benchmark scorecard (collection v{instrument_version}, "
            f"scoring v{INSTRUMENT_VERSION}, judge {judge_version})"
        ),
        "",
        f"Grounding: **{grounding_mode}**. The SOC score uses the declared `{SOC_PROFILE}` profile.",
        "Lower confidence error and mean levels off are better; higher values are better elsewhere.",
        "",
        "## System configurations",
        "",
        "| Provider | Model | Snapshot | Context | Prompt | Valid | Completion | SOC score | "
        "Review mode | Alert classification | Response action | Severity utility | Severity exact | "
        "Mean levels off | Technique | Supported evidence | Important facts found | "
        "Confidence error | Confidence skill | Unsafe close/monitor | False alarms | "
        "Unsupported-claim runs | Failures R/T/I/M | Cost |",
        "|" + "---|" * 24,
    ]
    for item in summaries:
        lines.append(
            f"| {item['provider']} | {item['model']} | {item['model_versions']} | {item['tier']} | "
            f"{item['prompt_id']} | "
            f"{item['valid_scenarios']}/{item['scenarios']} | {item['completion']} | "
            f"{item['soc_triage_score']} | {item['review_mode_label']} | {item['classification_score']} | "
            f"{item['action_score']} | {item['severity_score']} | {item['severity_exact']} | "
            f"{item['severity_mae']} | {item['technique_score']} | "
            f"{item['evidence_precision']} | {item['observation_recall']} | "
            f"{item['brier']} | {item['brier_skill']} | {item['unsafe_close_or_monitor_runs']} | "
            f"{item['false_alarms']} | {item['unsupported_claim_runs']} | "
            f"{item['refusal_runs']}/{item['timeout_runs']}/{item['invalid_output_runs']}/"
            f"{item['missing_result_runs']} | ${item['cost']} |"
        )

    lines += ["", "## Per scenario", ""]
    header = (
        "| Model | Context | Prompt | Valid | Failures R/T/I/M | Alert classification | "
        "Response action | Severity utility | Severity exact | Mean levels off | Technique | "
        "Supported evidence | Important facts found | Inference recall | Confidence error | "
        "Confidence skill | Unsafe close/monitor | Cost |"
    )
    separator = "|" + "---|" * 18
    for scenario in sorted({item["scenario"] for item in aggregated}):
        reference = next(
            item["reference_class"] for item in aggregated if item["scenario"] == scenario
        )
        lines += [f"### {scenario} _(reference: {reference})_", "", header, separator]
        for item in (row for row in aggregated if row["scenario"] == scenario):
            lines.append(
                f"| {item['model']} | {item['tier']} | {item['prompt_id']} | "
                f"{item['valid_runs']}/{item['runs']} | "
                f"{item['refusal_runs']}/{item['timeout_runs']}/{item['invalid_output_runs']}/"
                f"{item['missing_result_runs']} | "
                f"{item['classification_score']} | "
                f"{item['action_score']} | {item['severity_score']} | {item['severity_exact']} | "
                f"{item['severity_mae']} | {item['technique_score']} | "
                f"{item['evidence_precision']} | {item['observation_recall']} | "
                f"{item['inference_recall']} | {item['brier']} | {item['brier_skill']} | "
                f"{item['unsafe_close_or_monitor_runs']} | "
                f"${item['cost']} |"
            )
        lines.append("")
    (destination / "scorecard.md").write_text("\n".join(lines) + "\n")
    return destination


def _validate_result_manifest(result: dict, expected_version: str | None = None) -> str | None:
    manifest = result.get("experiment")
    error = validate_experiment_manifest(manifest, expected_version=expected_version)
    if error:
        return error
    if manifest["requested_model"] != result.get("model"):
        return "manifest requested model does not match result model"
    if manifest["context_tier"] != result.get("tier"):
        return "manifest context tier does not match result tier"
    if not instrument_at_least(manifest["instrument_version"], (3, 4)):
        # Earlier contexts remain identified by the hash stored in their immutable manifest. The
        # current checkout contains the v3.4 contexts with added record IDs, so comparing an
        # archived hash to the current file would make every old sweep unreadable.
        return None
    try:
        expected = context_sha256(result["scenario"], result["tier"])
    except (KeyError, OSError) as exc:
        return f"result references unavailable context: {exc}"
    if manifest["context_sha256"] != expected:
        return "result context hash does not match the current frozen context"
    return None


def main(
    allow_keyword_fallback: bool = False,
    model: list[str] | None = None,
    prompt: list[str] | None = None,
    tier: list[str] | None = None,
    experiment: list[str] | None = None,
    sweep: list[str] | None = None,
) -> int:
    # Recursive so any nesting under the output directory loads, including sweeps collected before
    # the per-sweep layout existed.
    roots = {OUTPUT_DIR, LEGACY_OUTPUT_DIR}
    files = sorted(
        path for root in roots if root.exists() for path in root.rglob("*__exp-*__run*.json")
    )
    if not files:
        print(f"No results found under {OUTPUT_DIR}. Run the collection runners first.")
        return 1

    judge_available = judge.is_available()
    if USE_LLM_JUDGE and not judge_available and not allow_keyword_fallback:
        print(
            "ERROR: the configured grounding judge is unavailable. Set ANTHROPIC_API_KEY or pass "
            "--allow-keyword-fallback for exploratory scoring."
        )
        return 1
    use_judge = USE_LLM_JUDGE and judge_available
    grounding_mode = "cached or live grounding judge" if use_judge else "keyword fallback"

    gold_cache = {scenario: load_gold(scenario) for scenario in SCENARIOS}
    rows = []
    scored_versions: set[str] = set()
    for path in files:
        try:
            result = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: cannot read {path.name}: {exc}")
            return 1
        manifest_error = _validate_result_manifest(result)
        if manifest_error:
            print(f"ERROR: {path.name}: {manifest_error}")
            return 1
        manifest = result["experiment"]
        if model and result["model"] not in model:
            continue
        if prompt and manifest["prompt_id"] not in prompt:
            continue
        if tier and result["tier"] not in tier:
            continue
        if experiment and manifest["experiment_id"] not in experiment:
            continue
        if sweep and result.get("sweep") not in sweep:
            continue
        gold = gold_cache.get(result["scenario"])
        if gold is None:
            print(f"ERROR: {path.name} has no matching scenario reference")
            return 1
        try:
            rows.append(score_run(result, gold, use_judge, allow_keyword_fallback))
        except RuntimeError as exc:
            print(f"ERROR: {exc}")
            return 1
        scored_versions.add(manifest["instrument_version"])

    if not rows:
        print("No results matched the requested experiment filters.")
        return 1

    # Reading an older sweep is fine; scoring two instruments into one scorecard is not, because
    # their scores answer different questions.
    if len(scored_versions) > 1:
        print(
            "ERROR: the selected results span instrument versions "
            f"{', '.join(sorted(scored_versions))}. Score them separately with --sweep."
        )
        return 1
    instrument_version = scored_versions.pop()
    if use_judge:
        grounding_mode = (
            "structured Haiku judge over cited telemetry records and the reference key"
            if instrument_at_least(instrument_version, (3, 4))
            else "v9 Haiku judge over free-text evidence and the verbose telemetry digest"
        )
    else:
        grounding_mode = "keyword fallback (exploratory only)"
    print(f"Grounding mode: {grounding_mode}")
    if instrument_version != INSTRUMENT_VERSION:
        print(
            f"NOTE: scoring instrument {instrument_version} results with a {INSTRUMENT_VERSION} "
            "checkout; the scorecard records both the collection and scoring versions."
        )

    aggregated = aggregate(rows)
    summaries = model_summary(aggregated)
    sweeps = sorted({row["sweep"] for row in rows if row["sweep"]})
    destination = write_reports(
        rows, aggregated, summaries, grounding_mode, sweeps, instrument_version
    )
    print(
        f"Scored {len(rows)} runs across {len(aggregated)} scenario-system cells and "
        f"{len(summaries)} system configurations."
    )
    print(f"Sweeps: {', '.join(sweeps) or 'unlabelled'}")
    print(f"Wrote scorecard.json, scorecard.md, and three CSVs to {destination}")
    print("Render the HTML report with: python tools/report.py")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-keyword-fallback",
        action="store_true",
        help="permit weaker keyword grounding for exploratory scoring",
    )
    parser.add_argument("--model", action="append", help="include only this requested model")
    parser.add_argument("--prompt", action="append", help="include only this prompt id")
    parser.add_argument(
        "--tier", action="append", choices=TIERS, help="include only this context tier"
    )
    parser.add_argument("--experiment", action="append", help="include only this experiment id")
    parser.add_argument("--sweep", action="append", help="include only this collection sweep")
    raise SystemExit(main(**vars(parser.parse_args())))
