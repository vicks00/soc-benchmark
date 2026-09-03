"""harness/scoring.py: decision credit, calibration, aggregation, and failure accounting."""

from __future__ import annotations

import unittest
from unittest import mock

from harness.config import SCENARIOS, build_experiment_manifest, load_context
from harness.scoring import (
    _mean,
    aggregate,
    brier_measurement,
    brier_skill,
    decision_scores,
    grounding_scores,
    model_summary,
    multiclass_brier,
    probability_consistent,
    score_action,
    score_classification,
    score_run,
    score_severity,
    score_technique,
    severity_measurements,
)
from tests.fixtures import reference_key, scored_row, valid_output


class DecisionCreditTests(unittest.TestCase):
    def test_accepted_alternative_receives_full_credit(self):
        """Professional disagreement the evidence cannot settle must not be penalised."""
        output = valid_output()
        output.update(
            classification="Suspicious",
            severity="High",
            recommended_action="Escalate to Customer",
        )
        scores = decision_scores(output, reference_key())
        self.assertEqual(scores["classification_score"], 1.0)
        self.assertEqual(scores["action_score"], 1.0)
        self.assertEqual(scores["severity_score"], 1.0)

    def test_under_reaction_costs_more_than_over_reaction(self):
        under = score_action("Continue Monitoring", "Escalate to Customer")
        over = score_action("Contain / Isolate Endpoint", "Escalate to Customer")
        self.assertLess(under, over)

    def test_severity_degrades_with_rank_distance(self):
        self.assertEqual(score_severity("High", "High"), 1.0)
        self.assertEqual(score_severity("Critical", "High"), 0.75)
        self.assertEqual(score_severity("Low", "High"), 0.0)
        self.assertEqual(score_severity("Informational", "Critical"), 0.0)

    def test_severity_reports_exact_distance_and_undercalls(self):
        gold = reference_key()
        one_low = severity_measurements("Medium", gold)
        self.assertEqual(one_low["severity_score"], 0.75)
        self.assertEqual(one_low["severity_exact"], 0.0)
        self.assertEqual(one_low["severity_mae"], 1.0)
        self.assertTrue(one_low["severity_undercall"])
        self.assertFalse(one_low["severe_undercall"])

        two_low = severity_measurements("Low", gold)
        self.assertEqual(two_low["severity_score"], 0.0)
        self.assertTrue(two_low["severe_undercall"])

    def test_technique_credits_parent_and_penalises_invention(self):
        self.assertEqual(score_technique(["T1003.001"], ["T1003.001"]), 1.0)
        self.assertEqual(score_technique(["T1003.002"], ["T1003.001"]), 0.5)
        self.assertEqual(score_technique([], []), 1.0)
        self.assertLess(score_technique(["T1003.001"], []), 1.0)

    def test_negated_labels_score_zero_rather_than_matching(self):
        self.assertEqual(score_classification("not malicious", "Malicious"), 0.0)
        self.assertEqual(score_action("do not close", "Close"), 0.0)

    def test_full_credit_alternative_preserves_best_of_set_scoring(self):
        output = valid_output()
        output["classification"] = "Suspicious"
        self.assertEqual(decision_scores(output, reference_key())["classification_score"], 1.0)

    def test_partial_credit_blends_relief_with_the_primary_distance(self):
        gold = reference_key()
        gold["verdict"]["acceptable_alternatives"][0]["credit"] = 0.5
        output = valid_output()
        output["classification"] = "Suspicious"
        # Suspicious against the Malicious primary is 0.7; halfway to the exact alternative is .85.
        self.assertAlmostEqual(decision_scores(output, gold)["classification_score"], 0.85)

    def test_low_credit_never_scores_below_the_raw_primary_distance(self):
        gold = reference_key()
        gold["verdict"]["acceptable_alternatives"][0]["credit"] = 0.1
        output = valid_output()
        output["classification"] = "Suspicious"
        score = decision_scores(output, gold)["classification_score"]
        self.assertAlmostEqual(score, 0.73)
        self.assertGreaterEqual(score, score_classification("Suspicious", "Malicious"))

    def test_partial_alternative_does_not_lower_severity_safety_floor(self):
        gold = reference_key()
        alternative = gold["verdict"]["acceptable_alternatives"][0]
        alternative.update(severity="Medium", credit=0.5)
        measurements = severity_measurements("Low", gold)
        self.assertTrue(measurements["severe_undercall"])
        self.assertEqual(measurements["severity_exact"], 0.0)


class CalibrationTests(unittest.TestCase):
    def test_brier_uses_the_best_accepted_class(self):
        probabilities = {"Malicious": 0.0, "Suspicious": 1.0, "Benign": 0.0, "Undetermined": 0.0}
        self.assertEqual(multiclass_brier(probabilities, reference_key()), 0.0)

    def test_probability_consistency_tracks_the_stated_class(self):
        self.assertTrue(probability_consistent(valid_output()))
        inconsistent = valid_output()
        inconsistent["classification"] = "Benign"
        self.assertFalse(probability_consistent(inconsistent))

    def test_brier_skill_uses_a_uniform_forecast_as_zero(self):
        self.assertEqual(brier_skill(0.0), 1.0)
        self.assertEqual(brier_skill(0.75), 0.0)
        self.assertLess(brier_skill(1.0), 0.0)

    def test_partial_alternative_uses_a_soft_confidence_target(self):
        gold = reference_key()
        gold["verdict"]["acceptable_alternatives"][0]["credit"] = 0.5
        probabilities = {
            "Malicious": 0.05,
            "Suspicious": 0.95,
            "Benign": 0.0,
            "Undetermined": 0.0,
        }
        partial = brier_measurement(probabilities, gold)
        gold["verdict"]["acceptable_alternatives"][0]["credit"] = 1.0
        full = brier_measurement(probabilities, gold)
        self.assertGreater(partial["brier"], full["brier"])
        self.assertEqual(partial["brier_credit"], 0.5)


class GroundingTests(unittest.TestCase):
    def test_judge_failure_raises_instead_of_degrading_silently(self):
        with (
            mock.patch(
                "harness.scoring.judge.judge_grounding", side_effect=RuntimeError("unavailable")
            ),
            self.assertRaisesRegex(RuntimeError, "grounding judge failed"),
        ):
            grounding_scores(valid_output(), reference_key(), "scenario_001", use_judge=True)


class ScoreRunTests(unittest.TestCase):
    def test_failed_run_reports_null_not_zero(self):
        """A refusal scored as zero would be indistinguishable from a confident wrong answer."""
        result = {
            "scenario": "scenario_001",
            "model": "test-model",
            "tier": "verbose",
            "output": None,
            "error": "model refusal",
            "input_tokens": 0,
            "output_tokens": 0,
            "experiment": {},
        }
        row = score_run(result, {"verdict": {"classification": "Malicious"}}, use_judge=False)
        self.assertFalse(row["valid"])
        self.assertEqual(row["failure_kind"], "refusal")
        for field in ("classification_score", "brier", "unsupported_claim", "classification"):
            self.assertIsNone(row[field], field)

    def test_partial_alternative_is_acceptable_without_becoming_correct(self):
        scenario = next(iter(SCENARIOS))
        gold = reference_key()
        gold["verdict"]["acceptable_alternatives"][0]["credit"] = 0.5
        output = valid_output()
        output["classification"] = "Suspicious"
        output["classification_probabilities"] = {
            "Malicious": 0.2,
            "Suspicious": 0.8,
            "Benign": 0.0,
            "Undetermined": 0.0,
        }
        manifest = build_experiment_manifest(
            "gpt-test", "minimal", load_context(scenario, "minimal")
        )
        row = score_run(
            {
                "scenario": scenario,
                "model": "gpt-test",
                "model_version": "gpt-test",
                "tier": "minimal",
                "output": output,
                "error": None,
                "input_tokens": 0,
                "output_tokens": 0,
                "experiment": manifest,
            },
            gold,
            use_judge=False,
        )
        self.assertFalse(row["correct"])
        self.assertTrue(row["acceptable"])
        self.assertEqual(row["classification_match_credit"], 0.5)
        self.assertTrue(row["credited_alternative"])

    def test_partial_alternative_never_expands_safe_terminal_actions(self):
        scenario = next(iter(SCENARIOS))
        gold = reference_key()
        alternative = gold["verdict"]["acceptable_alternatives"][0]
        alternative.update(
            credit=0.5,
            recommended_action="Close",
            terminal_action_allowed=True,
        )
        output = valid_output()
        output["recommended_action"] = "Close"
        manifest = build_experiment_manifest(
            "gpt-test", "minimal", load_context(scenario, "minimal")
        )
        row = score_run(
            {
                "scenario": scenario,
                "model": "gpt-test",
                "model_version": "gpt-test",
                "tier": "minimal",
                "output": output,
                "error": None,
                "input_tokens": 0,
                "output_tokens": 0,
                "experiment": manifest,
            },
            gold,
            use_judge=False,
        )
        self.assertTrue(row["unsafe_close_or_monitor"])


class AggregateTests(unittest.TestCase):
    def test_zero_token_mean_is_reported_not_swallowed(self):
        """Regression: a falsy-`or` fallback used to discard a legitimate mean of zero."""
        self.assertEqual(aggregate([scored_row()])[0]["total_tokens"], 0)

    def test_invalid_runs_are_excluded_from_metric_means(self):
        rows = [
            scored_row(classification_score=1.0),
            scored_row(valid=False, failure_kind="refusal", classification_score=None),
        ]
        cell = aggregate(rows)[0]
        self.assertEqual(cell["classification_score"], 1.0)
        self.assertEqual(cell["valid_runs"], 1)

    def test_failure_kinds_are_counted_separately(self):
        rows = [
            scored_row(valid=False, failure_kind=kind)
            for kind in ("refusal", "timeout", "invalid_output", "provider_error")
        ]
        cell = aggregate(rows)[0]
        self.assertEqual(cell["refusal_runs"], 1)
        self.assertEqual(cell["timeout_runs"], 1)
        self.assertEqual(cell["invalid_output_runs"], 1)
        self.assertEqual(cell["provider_error_runs"], 1)
        self.assertEqual(cell["valid_runs"], 0)

    def test_results_never_written_still_count_against_completion(self):
        scenario = next(iter(SCENARIOS))
        manifest = build_experiment_manifest(
            "gpt-test", "minimal", load_context(scenario, "minimal")
        )
        row = score_run(
            {
                "scenario": scenario,
                "model": "gpt-test",
                "model_version": "gpt-test",
                "tier": "minimal",
                "output": valid_output(),
                "error": None,
                "input_tokens": 100,
                "output_tokens": 50,
                "experiment": manifest,
            },
            reference_key(),
            use_judge=False,
        )
        cell = aggregate([row])[0]
        self.assertEqual(cell["observed_runs"], 1)
        self.assertEqual(cell["missing_result_runs"], 2)
        self.assertEqual(cell["completion"], 0.333)

    def test_mean_ignores_booleans(self):
        # bool is a subclass of int, so a flag column would otherwise skew a metric mean.
        self.assertIsNone(_mean([]))
        self.assertEqual(_mean([True, False, 1.0, 3.0]), 2.0)


class SensitivityTests(unittest.TestCase):
    def test_leave_one_out_exposes_rank_changes(self):
        first, second = list(SCENARIOS)[:2]
        rows = [
            scored_row(
                scenario=first,
                experiment_id="exp-a",
                model="model-a",
                classification_score=1.0,
                action_score=1.0,
            ),
            scored_row(
                scenario=second,
                experiment_id="exp-a",
                model="model-a",
                classification_score=0.0,
                action_score=0.0,
            ),
            scored_row(
                scenario=first,
                experiment_id="exp-b",
                model="model-b",
                classification_score=0.6,
                action_score=0.6,
            ),
            scored_row(
                scenario=second,
                experiment_id="exp-b",
                model="model-b",
                classification_score=0.6,
                action_score=0.6,
            ),
        ]
        summaries = {item["model"]: item for item in model_summary(aggregate(rows))}
        self.assertGreater(
            summaries["model-a"]["leave_one_out"]["rank_max"],
            summaries["model-a"]["leave_one_out"]["rank_min"],
        )
        self.assertTrue(
            any(
                item["winner_changed"]
                for item in summaries["model-a"]["leave_one_out"]["by_scenario"].values()
            )
        )


if __name__ == "__main__":
    unittest.main()
