"""harness/config.py: the output contract, experiment manifests, pricing, and response parsing."""

from __future__ import annotations

import math
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

from harness import config
from harness.config import (
    REVIEW_MODE_BRIER_CEILING,
    SCENARIOS,
    SOC_PROFILE,
    WEIGHTING_PROFILES,
    RunResult,
    baseline_lift,
    build_experiment_manifest,
    cost_usd,
    experiment_id,
    load_context,
    parse_json,
    profile_disqualifiers,
    profile_score,
    recommended_review_mode,
    validate_experiment_manifest,
    validate_output,
)
from harness.scoring import RUN_METRICS, baseline_scores
from tests.fixtures import valid_output


class OutputContractTests(unittest.TestCase):
    def test_valid_output_passes(self):
        self.assertIsNone(validate_output(valid_output()))

    def test_missing_and_unexpected_fields_are_rejected(self):
        missing = valid_output()
        del missing["summary"]
        self.assertIn("missing fields", validate_output(missing))

        extra = valid_output()
        extra["signal_strength"] = 0.9
        self.assertIn("unexpected fields", validate_output(extra))

    def test_probabilities_must_be_complete_and_normalized(self):
        short = valid_output()
        short["classification_probabilities"]["Malicious"] = 0.7
        self.assertIn("sum to 1.0", validate_output(short))

        incomplete = valid_output()
        del incomplete["classification_probabilities"]["Undetermined"]
        self.assertIn("exactly the four classes", validate_output(incomplete))

    def test_non_numeric_probabilities_are_rejected(self):
        # True is an int in Python and NaN compares false against any bound, so both slip through
        # a naive numeric check.
        for value in (-0.1, 1.1, float("nan"), True, "0.8"):
            with self.subTest(value=value):
                output = valid_output()
                output["classification_probabilities"]["Malicious"] = value
                self.assertIsNotNone(validate_output(output))

    def test_technique_ids_must_look_like_techniques(self):
        output = valid_output()
        output["mitre_techniques"] = ["credential_access"]
        self.assertIsNotNone(validate_output(output))

    def test_record_references_must_exist_in_the_supplied_context(self):
        output = valid_output()
        records = {
            "R000140": {
                "record_id": "R000140",
                "source_image": "C:\\Windows\\System32\\rundll32.exe",
            }
        }
        self.assertIsNone(validate_output(output, records_by_id=records))
        output["observations"][0]["record_refs"] = ["R999999"]
        output["observations"][0]["facts"][0]["record_ref"] = "R999999"
        self.assertIn("absent", validate_output(output, records_by_id=records))

    def test_exact_facts_must_match_the_cited_record(self):
        output = valid_output()
        records = {
            "R000140": {
                "record_id": "R000140",
                "source_image": "C:\\Windows\\System32\\rundll32.exe",
            }
        }
        output["observations"][0]["facts"][0]["value"] = "powershell.exe"
        self.assertIn("does not match", validate_output(output, records_by_id=records))

    def test_inferences_and_key_evidence_must_resolve(self):
        output = valid_output()
        output["inferences"][0]["supported_by"] = ["E999"]
        self.assertIn("invalid observation support", validate_output(output))
        output = valid_output()
        output["key_evidence_ids"] = ["E999"]
        self.assertIn("must cite candidate observations", validate_output(output))


class ExperimentManifestTests(unittest.TestCase):
    def test_manifest_is_deterministic(self):
        context = load_context(next(iter(SCENARIOS)), "minimal")
        first = build_experiment_manifest("model-a", "minimal", context)
        second = build_experiment_manifest("model-a", "minimal", context)
        self.assertEqual(first, second)
        self.assertIsNone(validate_experiment_manifest(first))
        self.assertEqual(first["experiment_id"], experiment_id(first))

    def test_identity_changes_with_tier_and_model(self):
        scenario = next(iter(SCENARIOS))
        minimal = build_experiment_manifest("model-a", "minimal", load_context(scenario, "minimal"))
        curated = build_experiment_manifest("model-a", "curated", load_context(scenario, "curated"))
        other = build_experiment_manifest("model-b", "minimal", load_context(scenario, "minimal"))
        self.assertNotEqual(minimal["experiment_id"], curated["experiment_id"])
        self.assertNotEqual(minimal["experiment_id"], other["experiment_id"])

    def test_decoding_change_invalidates_the_manifest(self):
        context = load_context(next(iter(SCENARIOS)), "minimal")
        manifest = build_experiment_manifest("model-a", "minimal", context)
        manifest["temperature"] = 0.7
        self.assertIn("temperature must be null", validate_experiment_manifest(manifest))


class ResponseParsingTests(unittest.TestCase):
    def test_recovers_an_object_from_fenced_or_chatty_output(self):
        self.assertEqual(parse_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(parse_json('Sure!\n{"a": 1}\nHope that helps.'), {"a": 1})
        self.assertEqual(parse_json('{"a": [1, 2,],}'), {"a": [1, 2]})

    def test_returns_none_when_there_is_no_object(self):
        for text in ("", "not json", "}{"):
            with self.subTest(text=text):
                self.assertIsNone(parse_json(text))


class WeightingProfileTests(unittest.TestCase):
    SUMMARY: ClassVar[dict] = {
        "classification_score": 0.9,
        "action_score": 0.8,
        "evidence_precision": 0.5,
        "observation_recall": 0.6,
        "brier": 0.4,
        "unsafe_close_or_monitor_runs": 0,
        "unsupported_claim_runs": 0,
        "false_alarms": 0,
    }

    def test_no_ranking_profile_produces_no_score(self):
        self.assertIsNone(profile_score(self.SUMMARY, "none"))

    def test_weights_shift_the_ranking(self):
        """The point of profiles: the same results order differently under different priorities."""
        strong_decision = {**self.SUMMARY, "classification_score": 1.0, "evidence_precision": 0.1}
        strong_grounding = {**self.SUMMARY, "classification_score": 0.5, "evidence_precision": 1.0}
        self.assertGreater(
            profile_score(strong_grounding, "grounding-first"),
            profile_score(strong_decision, "grounding-first"),
        )
        self.assertGreater(
            profile_score(strong_decision, "safety-first"),
            profile_score(strong_grounding, "safety-first"),
        )

    def test_brier_is_inverted_so_lower_helps(self):
        better = {**self.SUMMARY, "brier": 0.1}
        worse = {**self.SUMMARY, "brier": 1.5}
        self.assertGreater(
            profile_score(better, "grounding-first"), profile_score(worse, "grounding-first")
        )

    def test_missing_dimensions_are_skipped_not_counted_as_zero(self):
        partial = {key: value for key, value in self.SUMMARY.items() if key != "evidence_precision"}
        self.assertIsNotNone(profile_score(partial, "grounding-first"))

    def test_disqualifiers_are_reported_only_when_non_zero(self):
        self.assertEqual(profile_disqualifiers(self.SUMMARY, "grounding-first"), [])
        flagged = {**self.SUMMARY, "unsupported_claim_runs": 2}
        self.assertEqual(
            profile_disqualifiers(flagged, "grounding-first"), ["unsupported_claim_runs"]
        )
        self.assertEqual(profile_disqualifiers(flagged, "safety-first"), [])

    def test_every_profile_weights_only_known_metrics(self):
        known = set(RUN_METRICS)
        for profile_id, profile in WEIGHTING_PROFILES.items():
            with self.subTest(profile=profile_id):
                self.assertLessEqual(set(profile["weights"]), known)


class BaselineLiftTests(unittest.TestCase):
    """Answering Malicious to everything already scores 0.87 here, so a profile built on raw scores
    would rank a fixed guess alongside a real analyst."""

    BASELINE: ClassVar[dict] = {
        "classification_score": 0.885,
        "action_score": 0.898,
        "severity_score": 0.8125,
        "brier_skill": 0.0,
    }

    def test_lift_puts_the_baseline_at_zero_and_perfect_at_one(self):
        self.assertAlmostEqual(baseline_lift(0.87, 0.87), 0.0)
        self.assertAlmostEqual(baseline_lift(1.0, 0.87), 1.0)

    def test_scoring_worse_than_a_fixed_guess_goes_negative(self):
        self.assertLess(baseline_lift(0.84, 0.87), 0)

    def test_a_perfect_baseline_leaves_the_value_alone(self):
        """Guards the divide by zero when a metric has no headroom above the baseline."""
        self.assertEqual(baseline_lift(0.5, 1.0), 0.5)

    def test_a_model_matching_the_baseline_scores_zero_on_decisions(self):
        matches_baseline = {
            "classification_score": 0.885,
            "action_score": 0.898,
            "severity_score": 0.8125,
            "evidence_precision": 0.0,
            "observation_recall": 0.0,
            "brier_skill": 0.0,
        }
        self.assertAlmostEqual(profile_score(matches_baseline, SOC_PROFILE, self.BASELINE), 0.0)

    def test_the_baseline_is_only_applied_to_profiles_that_ask_for_it(self):
        summary = {"classification_score": 0.87, "action_score": 0.847}
        relative = profile_score(summary, SOC_PROFILE, self.BASELINE)
        absolute = profile_score(summary, "safety-first", self.BASELINE)
        self.assertLess(relative, absolute)

    def test_omitting_the_baseline_falls_back_to_raw_scores(self):
        """Callers that have no baseline to hand still get a score rather than an exception."""
        summary = {"classification_score": 0.87, "action_score": 0.847}
        self.assertIsNotNone(profile_score(summary, SOC_PROFILE))

    def test_baseline_policy_is_declared_and_computed_from_the_suite(self):
        baseline = baseline_scores()
        self.assertEqual(
            baseline["policy"],
            {
                "classification": "Malicious",
                "severity": "High",
                "recommended_action": "Escalate for Investigation",
                "mitre_techniques": [],
            },
        )
        for metric in ("classification_score", "action_score", "severity_score"):
            self.assertAlmostEqual(baseline[metric], self.BASELINE[metric], places=3)


class ReviewModeTests(unittest.TestCase):
    CLEAN: ClassVar[dict] = {
        "unsafe_close_or_monitor_runs": 0,
        "false_alarms": 0,
        "brier": 0.08,
    }

    def test_a_clean_calibrated_configuration_is_a_candidate(self):
        self.assertEqual(recommended_review_mode(self.CLEAN)["tier"], 3)

    def test_an_unsafe_action_drops_to_supervised(self):
        self.assertEqual(
            recommended_review_mode({**self.CLEAN, "unsafe_close_or_monitor_runs": 1})["tier"], 1
        )

    def test_a_false_alarm_drops_to_assisted(self):
        self.assertEqual(recommended_review_mode({**self.CLEAN, "false_alarms": 1})["tier"], 2)

    def test_poor_calibration_drops_to_assisted(self):
        at_ceiling = {**self.CLEAN, "brier": REVIEW_MODE_BRIER_CEILING}
        over_ceiling = {**self.CLEAN, "brier": REVIEW_MODE_BRIER_CEILING + 0.01}
        self.assertEqual(recommended_review_mode(at_ceiling)["tier"], 3)
        self.assertEqual(recommended_review_mode(over_ceiling)["tier"], 2)

    def test_an_unscorable_configuration_is_not_promoted(self):
        """No confidence to judge means no evidence of calibration, so it does not earn the top tier."""
        self.assertEqual(recommended_review_mode({**self.CLEAN, "brier": None})["tier"], 2)

    def test_an_unsafe_action_outranks_every_other_reason(self):
        worst = {"unsafe_close_or_monitor_runs": 2, "false_alarms": 1, "brier": 1.9}
        self.assertEqual(recommended_review_mode(worst)["tier"], 1)
        self.assertIn("closed or downgraded", recommended_review_mode(worst)["reason"])


class SweepTests(unittest.TestCase):
    def test_results_from_different_sweeps_do_not_collide(self):
        """Without a sweep directory a later run would overwrite an earlier one on the same config."""
        context = load_context(next(iter(SCENARIOS)), "minimal")
        manifest = build_experiment_manifest("model-a", "minimal", context)
        common = {
            "scenario": "scenario_001",
            "model": "model-a",
            "model_version": "model-a",
            "tier": "minimal",
            "run_idx": 0,
            "output": None,
            "raw_text": "",
            "input_tokens": 0,
            "output_tokens": 0,
            "experiment": manifest,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(config, "OUTPUT_DIR", root):
                first = RunResult(**common, sweep="20260101T000000Z").save()
                second = RunResult(**common, sweep="20260202T000000Z").save()
        self.assertNotEqual(first, second)
        self.assertEqual(first.name, second.name)
        # <output>/<sweep>/results/<record>.json
        self.assertEqual(first.parent.name, "results")
        self.assertEqual(first.parent.parent.name, "20260101T000000Z")
        self.assertEqual(second.parent.parent.name, "20260202T000000Z")


class PricingTests(unittest.TestCase):
    def test_dated_snapshot_ids_resolve_to_base_pricing(self):
        self.assertEqual(
            cost_usd("claude-haiku-4-5-20251001", 1_000_000, 0, batch=False),
            cost_usd("claude-haiku-4-5", 1_000_000, 0, batch=False),
        )

    def test_batch_pricing_is_half_of_interactive(self):
        interactive = cost_usd("claude-sonnet-5", 1_000_000, 1_000_000, batch=False)
        self.assertAlmostEqual(
            cost_usd("claude-sonnet-5", 1_000_000, 1_000_000, batch=True), interactive / 2
        )

    def test_unpriced_model_yields_nan_so_it_cannot_be_summed_as_free(self):
        self.assertTrue(math.isnan(cost_usd("no-such-model", 1000, 1000)))


if __name__ == "__main__":
    unittest.main()
