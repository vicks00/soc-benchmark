"""harness/batch.py and the provider runners: job identity, polling, and failure accounting."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import unittest
from typing import ClassVar
from unittest import mock

from harness import batch
from harness.config import (
    DEFAULT_RUN_TIERS,
    MAX_OUTPUT_TOKENS,
    OUTPUT_FIELDS,
    OUTPUT_SCHEMA,
    RUNS_PER_CELL,
    SCENARIOS,
    TEMPERATURE,
    TIERS,
    models_for,
    new_models_for,
    validate_experiment_manifest,
)

PROVIDER_SDKS = ("anthropic", "google.genai", "openai")
HAVE_PROVIDER_SDKS = all(importlib.util.find_spec(name) for name in PROVIDER_SDKS)

if HAVE_PROVIDER_SDKS:
    from harness.schema import TOOL_NAME


def google_batch_config(model: str) -> dict:
    from runners import google_batch

    job = {"custom_id": "request-1", "model": model, "system": "system", "user": "user"}
    return google_batch._request(job, model)["config"]


class JobBuildingTests(unittest.TestCase):
    def test_default_sweep_shape(self):
        jobs = batch.build_jobs(["model-a", "model-b"])
        self.assertEqual(DEFAULT_RUN_TIERS, ["verbose"])
        self.assertIsNone(TEMPERATURE)
        self.assertEqual(len(jobs), len(SCENARIOS) * 2 * RUNS_PER_CELL)
        self.assertEqual({job["tier"] for job in jobs}, {"verbose"})
        self.assertTrue(
            all(validate_experiment_manifest(job["experiment"]) is None for job in jobs)
        )

    def test_custom_ids_are_unique_and_provider_safe(self):
        ids = [job["custom_id"] for job in batch.build_jobs(["model-a", "model-b"])]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(len(custom_id) <= 64 for custom_id in ids))

    def test_context_tiers_remain_selectable(self):
        jobs = batch.build_jobs(["model-a"], tiers=TIERS)
        self.assertEqual(len(jobs), len(SCENARIOS) * len(TIERS) * RUNS_PER_CELL)
        self.assertEqual({job["tier"] for job in jobs}, set(TIERS))

    def test_id_collision_fails_closed(self):
        """Two scenarios sharing a numeric prefix would otherwise overwrite each other's results."""
        with (
            mock.patch.object(
                batch, "SCENARIOS", {"scenario_001_first": {}, "scenario_001_second": {}}
            ),
            mock.patch.object(batch, "RUNS_PER_CELL", 1),
            mock.patch.object(batch, "load_context", return_value={}),
            self.assertRaisesRegex(ValueError, "duplicate provider custom_id"),
        ):
            batch.build_jobs(["model"], tiers=["minimal"])

    def test_model_name_with_no_safe_characters_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no provider-safe characters"):
            batch.make_custom_id("scenario_001_example", "$$$", "minimal", 0)


class PollingTests(unittest.TestCase):
    def test_polling_stops_at_a_terminal_state(self):
        states = iter(["running", "running", "ended"])
        with contextlib.redirect_stdout(io.StringIO()):
            final = batch.poll_until_terminal(
                lambda: {"status": next(states)},
                lambda state: state["status"],
                {"ended"},
                interval=0,
            )
        self.assertEqual(final["status"], "ended")


class ModelSelectionTests(unittest.TestCase):
    def test_no_selection_returns_the_whole_ladder(self):
        self.assertEqual(batch.select_models("openai"), models_for("openai"))

    def test_selection_keeps_ladder_order(self):
        """A partial re-run collects in the same order as the pass it repairs, however it was asked
        for."""
        ladder = models_for("openai")
        self.assertEqual(batch.select_models("openai", list(reversed(ladder))), ladder)

    def test_unknown_model_fails_before_spending(self):
        with self.assertRaisesRegex(SystemExit, "unknown openai model"):
            batch.select_models("openai", ["gpt-does-not-exist"])

    def test_candidates_select_from_new_models(self):
        self.assertEqual(
            batch.select_models("anthropic", candidates=True), new_models_for("anthropic")
        )


class FinishTests(unittest.TestCase):
    def test_a_clean_pass_returns_normally(self):
        with contextlib.redirect_stdout(io.StringIO()):
            batch.finish(saved=90, failed=0)

    def test_uncollected_runs_fail_the_process(self):
        """CI must not read a sweep with missing runs as a green build."""
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            batch.finish(saved=80, failed=0, incomplete=10)

    def test_malformed_responses_alone_do_not_fail_the_process(self):
        """A model returning unusable output is itself a result worth recording."""
        with contextlib.redirect_stdout(io.StringIO()):
            batch.finish(saved=80, failed=10, incomplete=0)


class FailureAccountingTests(unittest.TestCase):
    def test_requests_the_provider_never_returned_are_recorded(self):
        """A dropped request must not look like a scenario nobody attempted."""
        jobs = {"a": {"custom_id": "a"}, "b": {"custom_id": "b"}}
        with mock.patch.object(batch, "save_result") as saved:
            missing = batch.record_missing(jobs, {"a"})
        self.assertEqual(missing, 1)
        self.assertEqual(saved.call_args.args[0]["custom_id"], "b")

    def test_record_all_marks_every_job(self):
        with mock.patch.object(batch, "save_result") as saved:
            count = batch.record_all([{"custom_id": "a"}, {"custom_id": "b"}], "batch failed")
        self.assertEqual(count, 2)
        self.assertEqual(saved.call_count, 2)


@unittest.skipUnless(HAVE_PROVIDER_SDKS, "provider SDKs are not installed")
class ProviderRequestTests(unittest.TestCase):
    """What each provider is actually sent.

    Every bug that has cost this benchmark a paid sweep lived here, in a request body no test
    looked at: an output cap that truncated the answer, a thinking budget the provider rejects, a
    batch naming more than one model, and a batch over the enqueued-token limit. None of them were
    visible until money had been spent, so each has a case below.
    """

    JOB: ClassVar[dict] = {
        "custom_id": "request-1",
        "model": "test-model",
        "system": "system",
        "user": "user",
    }

    def test_no_runner_sends_a_temperature(self):
        """Decoding is left at the provider default, and the manifest asserts temperature is null."""
        from runners import anthropic_batch, google_batch, openai_batch

        self.assertNotIn("temperature", anthropic_batch._request(self.JOB)["params"])
        self.assertNotIn("temperature", google_batch._request(self.JOB, "gemini-flash")["config"])
        self.assertNotIn("temperature", openai_batch._request(self.JOB)["body"])

    def test_no_output_cap_can_truncate_an_answer(self):
        """A cap low enough to cut off the JSON turns a good answer into an invalid one. Anthropic
        requires the field, so it gets a ceiling far above any observed response."""
        from runners import anthropic_batch, google_batch, openai_batch

        self.assertIsNone(MAX_OUTPUT_TOKENS)
        self.assertNotIn(
            "max_output_tokens", google_batch._request(self.JOB, "gemini-flash")["config"]
        )
        self.assertNotIn("max_completion_tokens", openai_batch._request(self.JOB)["body"])
        # 8,355 was the longest response observed across a full sweep.
        self.assertGreater(anthropic_batch._request(self.JOB)["params"]["max_tokens"], 8_355)

    def test_gemini_never_disables_thinking(self):
        """The Gemini 3 series rejects thinking_budget=0 outright, failing every request."""
        config = google_batch_config("gemini-3.6-flash")
        self.assertNotIn("thinking_config", config)
        self.assertNotIn("thinking_budget", json.dumps(config))

    def test_every_provider_is_sent_the_output_contract(self):
        """Each provider enforces the contract during generation, so a model cannot answer in a
        shape the scorer would reject."""
        from runners import anthropic_batch, google_batch, openai_batch

        params = anthropic_batch._request(self.JOB)["params"]
        self.assertEqual(params["tool_choice"], {"type": "tool", "name": TOOL_NAME})
        self.assertEqual(params["tools"][0]["input_schema"], OUTPUT_SCHEMA)

        config = google_batch._request(self.JOB, "gemini-3.6-flash")["config"]
        self.assertEqual(config["response_mime_type"], "application/json")
        self.assertEqual(set(config["response_schema"]["properties"]), OUTPUT_FIELDS)

        body = openai_batch._request(self.JOB)["body"]
        self.assertTrue(body["response_format"]["json_schema"]["strict"])
        self.assertEqual(
            set(body["response_format"]["json_schema"]["schema"]["properties"]), OUTPUT_FIELDS
        )


@unittest.skipUnless(HAVE_PROVIDER_SDKS, "provider SDKs are not installed")
class OpenAIBatchLimitTests(unittest.TestCase):
    """OpenAI rejects a whole batch that names two models or exceeds the enqueued-token limit."""

    # What the provider enforces, and the ratio measured against returned usage on this telemetry.
    # The assertions below use these rather than the runner's own budget, so setting that budget
    # too high is caught instead of silently agreed with.
    PROVIDER_ENQUEUED_LIMIT = 900_000
    MEASURED_CHARS_PER_TOKEN = 3.25

    def setUp(self):
        from runners import openai_batch

        self.runner = openai_batch
        self.jobs = batch.build_jobs(["gpt-5.6-terra"])

    def test_a_batch_names_exactly_one_model(self):
        for group in self.runner._chunks(self.jobs):
            models = {self.runner._request(job)["body"]["model"] for job in group}
            self.assertEqual(len(models), 1)

    def test_no_chunk_exceeds_the_providers_enqueued_limit(self):
        for group in self.runner._chunks(self.jobs):
            characters = sum(len(job["system"]) + len(job["user"]) for job in group)
            likely_tokens = characters / self.MEASURED_CHARS_PER_TOKEN
            self.assertLess(likely_tokens, self.PROVIDER_ENQUEUED_LIMIT)

    def test_chunking_covers_every_job_exactly_once(self):
        """A dropped or duplicated job would silently shrink or double-count a model's runs."""
        chunked = [job["custom_id"] for group in self.runner._chunks(self.jobs) for job in group]
        self.assertEqual(sorted(chunked), sorted(job["custom_id"] for job in self.jobs))
        self.assertEqual(len(chunked), len(set(chunked)))

    def test_a_job_larger_than_the_budget_still_gets_submitted(self):
        """Never silently drop work: an oversized request is sent alone and left to the provider."""
        oversized = [{"custom_id": "big", "system": "s" * 10_000_000, "user": "u"}]
        self.assertEqual(len(self.runner._chunks(oversized)), 1)


if __name__ == "__main__":
    unittest.main()
