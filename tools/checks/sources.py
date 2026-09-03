"""Source capture integrity and build reproducibility."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

from tools.checks.report import Report

BASE = Path(__file__).resolve().parent.parent.parent


def check_reproducible(report: Report, require_captures: bool = False) -> str | None:
    """Verify the captures still hash as recorded and still rebuild the committed artifacts.

    Skipped when the captures are absent, since they are fetched on demand.
    """
    expected = {}
    for line in (BASE / "datasets" / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        expected[name] = digest
    captures = {path.name: path for path in (BASE / "datasets").glob("*.zip")}

    if not captures:
        message = "source captures absent; run tools/fetch_datasets.sh to audit reproducibility"
        (report.fail if require_captures else report.skip)(message)
        return None

    if captures.keys() != expected.keys():
        report.fail(
            "source capture set differs from SHA256SUMS "
            f"(missing={sorted(expected.keys() - captures.keys())}, "
            f"extra={sorted(captures.keys() - expected.keys())})"
        )
    else:
        mismatches = [
            name
            for name, path in captures.items()
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected[name]
        ]
        if mismatches:
            report.fail(f"source capture checksum mismatch: {mismatches}")
        else:
            report.ok(f"{len(captures)} source capture checksums match")

    result = subprocess.run(
        [sys.executable, str(BASE / "tools" / "build_scenarios.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=BASE,
        check=False,
    )
    if result.returncode:
        drift = [line.strip() for line in result.stdout.splitlines() if "DRIFT" in line]
        report.fail(
            f"committed artifacts differ from a fresh build: {drift or result.stderr[-400:]}"
        )
    else:
        report.ok("committed contexts and references match a fresh build")
    return None
