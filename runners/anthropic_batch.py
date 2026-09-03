"""Collect Claude results with the Message Batches API."""

from __future__ import annotations

import json
import os
from functools import partial

import anthropic

from harness import batch
from harness.config import ANTHROPIC_MAX_TOKENS, DEFAULT_PROMPT_ID
from harness.schema import TOOL_NAME, anthropic_tool


def _request(job: dict) -> dict:
    return {
        "custom_id": job["custom_id"],
        "params": {
            "model": job["model"],
            "max_tokens": ANTHROPIC_MAX_TOKENS,
            "system": job["system"],
            "messages": [{"role": "user", "content": job["user"]}],
            "tools": [anthropic_tool()],
            "tool_choice": {"type": "tool", "name": TOOL_NAME},
        },
    }


def _submission(message) -> str:
    """Serialize Anthropic tool-call input to the same JSON text other providers store."""
    for block in message.content:
        if getattr(block, "type", None) == "tool_use" and block.name == TOOL_NAME:
            return json.dumps(block.input)
    return "".join(block.text for block in message.content if hasattr(block, "text"))


def main(
    prompt: str = DEFAULT_PROMPT_ID,
    tiers: list[str] | None = None,
    models: list[str] | None = None,
    candidates: bool = False,
):
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("ANTHROPIC_API_KEY is not set")
    selected = batch.select_models("anthropic", models, candidates)
    if not selected:
        print("No models selected.")
        return
    client = anthropic.Anthropic()
    jobs = batch.build_jobs(selected, prompt_id=prompt, tiers=tiers)
    by_id = {job["custom_id"]: job for job in jobs}
    print(f"Submitting {len(jobs)} requests across {len(selected)} model(s): {', '.join(selected)}")

    submitted = client.messages.batches.create(requests=[_request(job) for job in jobs])
    print(f"batch id: {submitted.id}")

    batch.poll_until_terminal(
        partial(client.messages.batches.retrieve, submitted.id),
        lambda state: state.processing_status,
        {"ended"},
    )

    saved = failed = 0
    returned: set[str] = set()
    for entry in client.messages.batches.results(submitted.id):
        job = by_id.get(entry.custom_id)
        if job is None:
            continue
        returned.add(entry.custom_id)
        result = entry.result
        if result.type != "succeeded":
            batch.save_result(job, "", 0, 0, error=f"batch result type={result.type}")
            failed += 1
            continue
        message = result.message
        batch.save_result(
            job,
            _submission(message),
            message.usage.input_tokens,
            message.usage.output_tokens,
            model_version=getattr(message, "model", job["model"]),
        )
        saved += 1

    missing = batch.record_missing(by_id, returned)
    batch.finish(saved, failed + missing, incomplete=failed + missing)


if __name__ == "__main__":
    main(**batch.runner_arguments(__doc__))
