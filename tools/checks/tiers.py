"""Context tier relationships and the invariants specific to constructed control scenarios."""

from __future__ import annotations

import json

from harness.config import SCENARIOS, TIERS, load_context
from tools.checks.report import Report

SUPPORTED_SOURCE_KINDS = {"host", "pcap", "derived"}


def _check_derived_controls(report: Report):
    """Assert the rewrites in scenarios 009 and 010 landed completely on every channel."""
    if "scenario_009_werfault_lsass_crashdump" in SCENARIOS:
        werfault = json.dumps(load_context("scenario_009_werfault_lsass_crashdump", "curated"))
        if (
            "NT AUTHORITY\\\\SYSTEM" not in werfault
            or '"integrity_level": "System"' not in werfault
        ):
            report.fail("scenario_009: WER chain identity/integrity transformation is inconsistent")
        if "t.okafor" in werfault:
            report.fail("scenario_009: interactive source identity survived in the WER chain")

    if "scenario_010_msbuild_ci_build" in SCENARIOS:
        ci_build = json.dumps(load_context("scenario_010_msbuild_ci_build", "verbose")).lower()
        if "agent.worker.exe" not in ci_build or "git.exe" not in ci_build:
            report.fail("scenario_010: CI lineage or source-control provenance is missing")
        if "powershell.exe -enc" in ci_build:
            report.fail("scenario_010: encoded PowerShell residue survived the benign transform")


def check_tiers_and_derived_controls(report: Report) -> str:
    for scenario_id in SCENARIOS:
        spec = json.loads((SCENARIOS[scenario_id]["dir"] / "spec.json").read_text())
        if spec["source"]["kind"] not in SUPPORTED_SOURCE_KINDS:
            report.fail(f"{scenario_id}: unsupported source kind {spec['source']['kind']!r}")
        sizes = {}
        for tier in TIERS:
            context = load_context(scenario_id, tier)
            sizes[tier] = len(context["telemetry"])
            if context.get("context_tier") != tier:
                report.fail(f"{scenario_id}/{tier}: context tier field mismatch")
            if (tier == "curated") != ("enrichment" in context):
                report.fail(f"{scenario_id}/{tier}: enrichment placement is invalid")
        if not sizes["minimal"] <= sizes["curated"] <= sizes["verbose"]:
            report.fail(f"{scenario_id}: context sizes are not monotonic: {sizes}")

    _check_derived_controls(report)
    return "tiers are monotonic and derived controls satisfy cross-channel invariants"
