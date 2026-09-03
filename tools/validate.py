"""Offline benchmark integrity checks. Individual checks live in tools/checks/.

All checks run even after one fails, so a single run reports every problem.
"""

from __future__ import annotations

import argparse
import sys
from functools import partial
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from harness.config import SCENARIOS  # noqa: E402
from tools.checks import (  # noqa: E402
    Report,
    check_balance,
    check_identifier_hygiene,
    check_leakage,
    check_reference_reachability,
    check_references,
    check_reproducible,
    check_scoring_and_manifests,
    check_spec_schema,
    check_tiers_and_derived_controls,
)


def checks(require_captures: bool):
    """The ordered checks, cheapest and most foundational first."""
    return (
        (
            "source integrity and build reproducibility",
            partial(check_reproducible, require_captures=require_captures),
        ),
        ("scenario specification schema", check_spec_schema),
        ("model-payload blinding", check_leakage),
        ("identifier hygiene", check_identifier_hygiene),
        ("telemetry-bounded reference integrity", check_references),
        ("reference observations and entities are reachable", check_reference_reachability),
        ("tier and derived-control integrity", check_tiers_and_derived_controls),
        ("output, scoring and experiment-manifest smoke tests", check_scoring_and_manifests),
        ("suite composition", check_balance),
    )


def main(require_captures: bool = False) -> int:
    print(f"Validating {len(SCENARIOS)} scenarios in {BASE}")
    report = Report()
    for title, run_check in checks(require_captures):
        marker = report.begin(title)
        summary = run_check(report)
        if summary and report.clean_since(marker):
            report.ok(summary)
    return report.summarize()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-captures",
        dest="require_captures",
        action="store_true",
        help="treat absent source captures as a failure instead of skipping the audit",
    )
    raise SystemExit(main(**vars(parser.parse_args())))
