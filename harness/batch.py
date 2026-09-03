"""Shared job construction, command line, and result persistence for batch runners."""

from __future__ import annotations

import argparse
import re
import time
from collections.abc import Callable, Iterable

from harness.config import (
    DEFAULT_PROMPT_ID,
    DEFAULT_RUN_TIERS,
    PROMPTS,
    RUNS_PER_CELL,
    SCENARIOS,
    TIERS,
    RunResult,
    build_experiment_manifest,
    build_user_content,
    load_context,
    models_for,
    new_models_for,
    parse_json,
    prompt_for,
    validate_output,
)


def runner_arguments(description: str) -> dict:
    """The command line every runner accepts, so re-running part of a sweep works the same way
    whichever provider fell over."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT_ID, choices=sorted(PROMPTS))
    parser.add_argument("--tiers", nargs="+", choices=TIERS)
    parser.add_argument(
        "--models", nargs="+", help="collect only these models rather than the whole ladder"
    )
    parser.add_argument(
        "--candidates",
        action="store_true",
        help="collect the NEW_MODELS candidates instead of the locked ladder",
    )
    return vars(parser.parse_args())


def select_models(
    provider: str, models: list[str] | None = None, candidates: bool = False
) -> list[str]:
    """Ladder order is preserved regardless of the order models were requested in, so a partial
    re-run collects in the same sequence as the pass it is repairing."""
    available = new_models_for(provider) if candidates else models_for(provider)
    if not models:
        return available
    unknown = sorted(set(models) - set(available))
    if unknown:
        raise SystemExit(
            f"unknown {provider} model(s): {', '.join(unknown)}. "
            f"Available: {', '.join(available) or 'none'}"
        )
    return [model for model in available if model in models]


def finish(saved: int, failed: int, incomplete: int = 0):
    """Every runner ends the same way, and a pass that left runs uncollected exits non-zero so a
    broken sweep cannot be mistaken for a clean one."""
    print(f"\nSaved {saved} results ({failed} failed). Next: python -m harness.scoring")
    if incomplete:
        raise SystemExit(f"{incomplete} run(s) were never collected; re-run this provider")


def make_custom_id(scenario: str, model: str, tier: str, run: int) -> str:
    """Provider-safe id matching ^[A-Za-z0-9_-]{1,64}$.

    Carries only the scenario's numeric prefix, so it does not round-trip: recover the full name
    from the job table.
    """
    num = scenario.split("_")[1] if "_" in scenario else scenario[:4]
    safe_model = re.sub(r"[^A-Za-z0-9_-]+", "-", model).strip("-")
    if not safe_model:
        raise ValueError(f"model id {model!r} has no provider-safe characters")
    return f"s{num}__{safe_model}__{tier}__r{run}"[:64]


def build_jobs(
    models: list[str],
    prompt_id: str = DEFAULT_PROMPT_ID,
    tiers: list[str] | None = None,
) -> list[dict]:
    """One job per (scenario, model, tier, run) for one declared experiment condition."""
    selected_tiers = DEFAULT_RUN_TIERS if tiers is None else tiers
    invalid_tiers = set(selected_tiers) - set(TIERS)
    if invalid_tiers:
        raise ValueError(f"unknown context tiers: {sorted(invalid_tiers)}")
    system_prompt = prompt_for(prompt_id)
    jobs = []
    custom_ids: set[str] = set()
    for scenario_id in SCENARIOS:
        for tier in selected_tiers:
            context = load_context(scenario_id, tier)
            content = build_user_content(context)
            for model in models:
                experiment = build_experiment_manifest(
                    model,
                    tier,
                    context,
                    prompt_id=prompt_id,
                )
                for run in range(RUNS_PER_CELL):
                    custom_id = make_custom_id(scenario_id, model, tier, run)
                    if custom_id in custom_ids:
                        raise ValueError(
                            f"duplicate provider custom_id {custom_id!r}; shorten or rename the model id"
                        )
                    custom_ids.add(custom_id)
                    jobs.append(
                        {
                            "custom_id": custom_id,
                            "scenario": scenario_id,
                            "model": model,
                            "tier": tier,
                            "run": run,
                            "system": system_prompt,
                            "user": content,
                            "experiment": experiment,
                        }
                    )
    return jobs


POLL_INTERVAL_SECONDS = 30


def poll_until_terminal(
    refresh: Callable[[], object],
    status_of: Callable[[object], str],
    terminal: Iterable[str],
    label: str = "status",
    interval: int = POLL_INTERVAL_SECONDS,
):
    """Poll a provider batch until it reports a terminal state, and return the final object."""
    terminal = set(terminal)
    while True:
        batch = refresh()
        status = status_of(batch)
        if status in terminal:
            return batch
        print(f"  {label}={status} ... waiting")
        time.sleep(interval)


def record_all(jobs: Iterable[dict], reason: str) -> int:
    """Persist the same failure for every job in a batch that never produced output."""
    count = 0
    for job in jobs:
        save_result(job, "", 0, 0, error=reason)
        count += 1
    return count


def record_missing(jobs_by_id: dict, returned: set) -> int:
    """Persist a failure for every request the provider never returned."""
    missing = 0
    for custom_id, job in jobs_by_id.items():
        if custom_id not in returned:
            save_result(job, "", 0, 0, error="batch returned no result for request")
            missing += 1
    return missing


def save_result(
    job: dict,
    text: str,
    in_tokens: int,
    out_tokens: int,
    model_version: str = "",
    error: str | None = None,
):
    parsed = parse_json(text) if text else None
    context = load_context(job["scenario"], job["tier"])
    records_by_id = {
        record["record_id"]: record for record in context["telemetry"] if record.get("record_id")
    }
    validation_error = (
        validate_output(
            parsed,
            instrument_version=job["experiment"]["instrument_version"],
            records_by_id=records_by_id,
        )
        if parsed is not None
        else "unparseable response"
    )
    return RunResult(
        scenario=job["scenario"],
        model=job["model"],
        model_version=model_version or job["model"],
        tier=job["tier"],
        run_idx=job["run"],
        output=parsed,
        raw_text=text or "",
        input_tokens=in_tokens,
        output_tokens=out_tokens,
        experiment=job["experiment"],
        error=error or validation_error,
    ).save()
