"""Collect GPT results with the Batch API."""

from __future__ import annotations

import io
import json
import os
from functools import partial

from openai import OpenAI

from harness import batch
from harness.config import DEFAULT_PROMPT_ID, MAX_OUTPUT_TOKENS
from harness.schema import openai_response_format


def _request(job: dict) -> dict:
    body = {
        "model": job["model"],
        "messages": [
            {"role": "system", "content": job["system"]},
            {"role": "user", "content": job["user"]},
        ],
        "response_format": openai_response_format(),
    }
    if MAX_OUTPUT_TOKENS is not None:
        # Shared budget with reasoning tokens.
        body["max_completion_tokens"] = MAX_OUTPUT_TOKENS
    return {
        "custom_id": job["custom_id"],
        "method": "POST",
        "url": "/v1/chat/completions",
        "body": body,
    }


# ~3.25 chars/token on this telemetry; use 3.0 so estimates stay high.
CHARS_PER_TOKEN = 3.0
# Split batches under org enqueued-token caps (default leaves headroom under ~900k).
ENQUEUED_TOKEN_BUDGET = int(os.environ.get("OPENAI_ENQUEUED_TOKEN_BUDGET", 700_000))


def _chunks(jobs: list[dict]) -> list[list[dict]]:
    batches: list[list[dict]] = []
    current: list[dict] = []
    total = 0
    for job in jobs:
        size = int((len(job["system"]) + len(job["user"])) / CHARS_PER_TOKEN)
        if current and total + size > ENQUEUED_TOKEN_BUDGET:
            batches.append(current)
            current, total = [], 0
        current.append(job)
        total += size
    if current:
        batches.append(current)
    return batches


def _describe(submitted) -> str:
    """Batch-level failures carry no output file, so surface the validation errors themselves."""
    errors = getattr(submitted, "errors", None)
    entries = getattr(errors, "data", None) or []
    seen: dict[str, str] = {}
    for entry in entries:
        seen.setdefault(entry.code or "error", entry.message or "")
    detail = "; ".join(f"{code}: {message}" for code, message in seen.items())
    return f"batch status={submitted.status}" + (f" ({detail})" if detail else "")


def _collect(client, submitted, by_id: dict) -> tuple[int, int, int]:
    """Returns saved, failed, and never-returned counts, kept apart because only the last means the
    provider still owes us work."""
    saved = failed = 0
    returned: set[str] = set()
    for line in client.files.content(submitted.output_file_id).text.splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        job = by_id.get(record.get("custom_id"))
        if job is None:
            continue
        returned.add(record["custom_id"])
        body = (record.get("response") or {}).get("body") or {}
        choices = body.get("choices") or []
        if not choices:
            batch.save_result(job, "", 0, 0, error=f"no choices: {str(record)[:200]}")
            failed += 1
            continue
        usage = body.get("usage", {}) or {}
        batch.save_result(
            job,
            choices[0].get("message", {}).get("content", "") or "",
            usage.get("prompt_tokens", 0),
            usage.get("completion_tokens", 0),
            model_version=body.get("model", job["model"]),
        )
        saved += 1
    missing = batch.record_missing(by_id, returned)
    return saved, failed + missing, failed + missing


def main(
    prompt: str = DEFAULT_PROMPT_ID,
    tiers: list[str] | None = None,
    models: list[str] | None = None,
    candidates: bool = False,
):
    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is not set")
    client = OpenAI()
    total_saved = total_failed = 0
    uncollected = 0  # missing responses (not malformed ones)
    # OpenAI: one model per batch.
    for model in batch.select_models("openai", models, candidates):
        jobs = batch.build_jobs([model], prompt_id=prompt, tiers=tiers)
        groups = _chunks(jobs)
        print(f"\n=== {model}: {len(jobs)} requests in {len(groups)} batch(es) ===")

        for index, group in enumerate(groups, start=1):
            by_id = {job["custom_id"]: job for job in group}
            payload = "\n".join(json.dumps(_request(job)) for job in group)
            upload_buffer = io.BytesIO(payload.encode())
            upload_buffer.name = f"batch_input_{model}_{index}.jsonl"

            upload = client.files.create(file=upload_buffer, purpose="batch")
            submitted = client.batches.create(
                input_file_id=upload.id, endpoint="/v1/chat/completions", completion_window="24h"
            )
            print(f"  [{index}/{len(groups)}] {len(group)} requests, batch {submitted.id}")

            submitted = batch.poll_until_terminal(
                partial(client.batches.retrieve, submitted.id),
                lambda state: state.status,
                {"completed", "failed", "expired", "cancelled"},
                label="    status",
            )

            if submitted.status != "completed":
                reason = _describe(submitted)
                print(f"    {reason}; nothing saved for this batch.")
                uncollected += batch.record_all(group, reason)
                continue

            saved, failed, missing = _collect(client, submitted, by_id)
            print(f"    saved {saved}, failed {failed}")
            total_saved += saved
            total_failed += failed
            uncollected += missing

    batch.finish(total_saved, total_failed, incomplete=uncollected)


if __name__ == "__main__":
    main(**batch.runner_arguments(__doc__))
