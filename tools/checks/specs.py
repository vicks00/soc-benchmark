"""Scenario specification schema."""

from __future__ import annotations

import json
from pathlib import Path

from harness.config import SCENARIOS
from tools.checks.report import Report

BASE = Path(__file__).resolve().parent.parent.parent

SPEC_FIELDS = {
    "scenario_id",
    "scenario_family",
    "title",
    "source",
    "environment",
    "alert",
    "select",
    "enrichment",
    "gold",
}
SCENARIO_FAMILIES = {
    "clear_malicious",
    "ambiguous_dual_use",
    "benign_control",
    "customer_context_required",
}
OPTIONAL_SPEC_FIELDS = {"multi_host", "transform"}

SOURCE_FIELDS_BY_KIND = {
    "host": {"kind", "zip", "citation", "upstream_path"},
    "derived": {"kind", "zip", "citation", "upstream_path"},
    "pcap": {"kind", "zip", "citation", "upstream_path", "captures"},
}
SELECTOR_KEYS = {"event_id", "where", "limit", "host"}
SELECTOR_OPERATORS = {
    "eq",
    "ieq",
    "contains",
    "not_contains",
    "startswith",
    "endswith",
    "in",
    "gte",
    "lte",
}


def spec_problems(directory: str, spec: dict) -> list[str]:
    """Every schema problem in one specification, so an author sees them all at once."""
    problems = []
    present = set(spec)
    missing = SPEC_FIELDS - present
    unexpected = present - SPEC_FIELDS - OPTIONAL_SPEC_FIELDS
    if missing:
        problems.append(f"{directory}: spec.json is missing {sorted(missing)}")
    if unexpected:
        problems.append(f"{directory}: spec.json has unexpected fields {sorted(unexpected)}")
    if spec.get("scenario_id") != directory:
        problems.append(
            f"{directory}: scenario_id {spec.get('scenario_id')!r} does not match its directory"
        )
    if spec.get("scenario_family") not in SCENARIO_FAMILIES:
        problems.append(f"{directory}: invalid scenario_family {spec.get('scenario_family')!r}")

    source = spec.get("source", {})
    kind = source.get("kind")
    if kind not in SOURCE_FIELDS_BY_KIND:
        problems.append(f"{directory}: unsupported source kind {kind!r}")
    else:
        source_missing = SOURCE_FIELDS_BY_KIND[kind] - set(source)
        if source_missing:
            problems.append(
                f"{directory}: source is missing {sorted(source_missing)} for kind {kind!r}"
            )
    if kind == "derived" and "transform" not in spec:
        problems.append(f"{directory}: derived scenarios require a transform block")

    select = spec.get("select", {})
    for tier in ("minimal", "curated"):
        if not isinstance(select.get(tier), list) or not select.get(tier):
            problems.append(f"{directory}: select.{tier} must be a non-empty list")
            continue
        for selector in select[tier]:
            unknown = set(selector) - SELECTOR_KEYS
            if unknown:
                problems.append(
                    f"{directory}: select.{tier} selector has unknown keys {sorted(unknown)}"
                )
            for key in selector.get("where", {}):
                _, _, operator = key.partition("__")
                if operator and operator not in SELECTOR_OPERATORS:
                    problems.append(
                        f"{directory}: unknown selector operator {operator!r} in select.{tier}"
                    )
    if kind != "pcap" and not isinstance(select.get("verbose"), dict):
        problems.append(f"{directory}: select.verbose must be an object for kind {kind!r}")
    return problems


def check_spec_schema(report: Report) -> str:
    """Reject a malformed spec.json up front rather than as a KeyError deep inside the build."""
    for spec_path in sorted((BASE / "scenarios").glob("*/spec.json")):
        directory = spec_path.parent.name
        try:
            spec = json.loads(spec_path.read_text())
        except json.JSONDecodeError as error:
            report.fail(f"{directory}: spec.json is not valid JSON: {error}")
            continue
        for problem in spec_problems(directory, spec):
            report.fail(problem)
    return f"{len(SCENARIOS)} scenario specifications match the schema"
