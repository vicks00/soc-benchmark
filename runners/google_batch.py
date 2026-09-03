"""Collect Gemini results with the Batch API."""

from __future__ import annotations

import os
from functools import partial

from google import genai

from harness import batch
from harness.config import DEFAULT_PROMPT_ID, MAX_OUTPUT_TOKENS
from harness.schema import gemini_response_schema

TERMINAL = {"JOB_STATE_SUCCEEDED", "JOB_STATE_FAILED", "JOB_STATE_CANCELLED", "JOB_STATE_EXPIRED"}


def _request(job: dict, model: str) -> dict:
    """Thinking is left at each model's default: the Gemini 3 series rejects thinking_budget=0
    outright, and with no output cap there is no budget for thinking to exhaust."""
    config: dict = {
        "system_instruction": job["system"],
        "response_mime_type": "application/json",
        "response_schema": gemini_response_schema(),
    }
    if MAX_OUTPUT_TOKENS is not None:
        config["max_output_tokens"] = MAX_OUTPUT_TOKENS
    return {
        "contents": [{"parts": [{"text": job["user"]}], "role": "user"}],
        "config": config,
    }


def main(
    prompt: str = DEFAULT_PROMPT_ID,
    tiers: list[str] | None = None,
    models: list[str] | None = None,
    candidates: bool = False,
):
    if not os.environ.get("GEMINI_API_KEY"):
        raise SystemExit("GEMINI_API_KEY is not set")
    client = genai.Client()
    total_saved = total_failed = 0
    dead_jobs = 0  # never completed (not malformed)
    for model in batch.select_models("google", models, candidates):
        jobs = batch.build_jobs([model], prompt_id=prompt, tiers=tiers)
        print(f"\n=== {model}: submitting {len(jobs)} requests ===")

        submitted = client.batches.create(model=model, src=[_request(job, model) for job in jobs])
        print(f"  job: {submitted.name}")

        submitted = batch.poll_until_terminal(
            partial(client.batches.get, name=submitted.name),
            lambda state: state.state.name,
            TERMINAL,
            label="state",
        )

        if submitted.state.name != "JOB_STATE_SUCCEEDED":
            print(f"  ended with state={submitted.state.name}; nothing saved for {model}.")
            dead_jobs += batch.record_all(jobs, f"batch state={submitted.state.name}")
            continue

        responses = submitted.dest.inlined_responses or []
        if len(responses) != len(jobs):
            error = (
                f"batch returned {len(responses)} responses for {len(jobs)} requests; "
                "order-based pairing is unsafe"
            )
            print(f"  ERROR: {error}.")
            dead_jobs += batch.record_all(jobs, error)
            continue

        for job, entry in zip(jobs, responses, strict=True):
            if getattr(entry, "error", None):
                batch.save_result(job, "", 0, 0, error=str(entry.error))
                total_failed += 1
                dead_jobs += 1
                continue
            response = entry.response
            usage = getattr(response, "usage_metadata", None)
            batch.save_result(
                job,
                response.text or "",
                getattr(usage, "prompt_token_count", 0) or 0,
                getattr(usage, "candidates_token_count", 0) or 0,
                model_version=getattr(response, "model_version", model),
            )
            total_saved += 1

    batch.finish(total_saved, total_failed, incomplete=dead_jobs)


if __name__ == "__main__":
    main(**batch.runner_arguments(__doc__))
