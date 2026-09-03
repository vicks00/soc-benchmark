"""Individual integrity checks run by tools/validate.py.

Each check takes a Report, records any problems it finds on it, and returns the line to print when
it finds none. Returning None means the check reported its own outcome.
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from tools.checks.instrument import check_balance, check_scoring_and_manifests  # noqa: E402
from tools.checks.payloads import check_identifier_hygiene, check_leakage  # noqa: E402
from tools.checks.references import (  # noqa: E402
    check_reference_reachability,
    check_references,
)
from tools.checks.report import Report  # noqa: E402
from tools.checks.sources import check_reproducible  # noqa: E402
from tools.checks.specs import check_spec_schema  # noqa: E402
from tools.checks.tiers import check_tiers_and_derived_controls  # noqa: E402

__all__ = [
    "Report",
    "check_balance",
    "check_identifier_hygiene",
    "check_leakage",
    "check_reference_reachability",
    "check_references",
    "check_reproducible",
    "check_scoring_and_manifests",
    "check_spec_schema",
    "check_tiers_and_derived_controls",
]
