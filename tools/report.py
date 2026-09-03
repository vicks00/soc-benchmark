"""Render scorecard.json as a single self-contained HTML file.

The output embeds its own data and draws its own charts, so it opens from disk with no server and
no network. It is written beside the sweep it describes, outside the repository.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from harness.config import LEGACY_OUTPUT_DIR, OUTPUT_DIR  # noqa: E402
from tools.report_template import render  # noqa: E402


def latest_scorecard() -> Path | None:
    """Sweep directories are timestamp-named, so the last one sorted is the most recent."""
    scorecards = sorted(
        path
        for root in {OUTPUT_DIR, LEGACY_OUTPUT_DIR}
        if root.exists()
        for path in root.glob("*/scorecard.json")
    )
    return scorecards[-1] if scorecards else None


def out_path(source: Path, requested: str | None) -> Path:
    if requested:
        return Path(requested).expanduser().resolve()
    return source.parent / "report.html"


def main(scorecard: str | None, out: str | None) -> int:
    source = Path(scorecard).expanduser() if scorecard else latest_scorecard()
    if source is None:
        print(f"No scorecard found under {OUTPUT_DIR}. Run `python -m harness.scoring` first.")
        return 1
    if not source.exists():
        print(f"{source} not found. Run `python -m harness.scoring` first.")
        return 1

    data = json.loads(source.read_text())
    if not data.get("summaries"):
        print(f"{source} contains no scored results.")
        return 1

    destination = out_path(source, out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render(data))

    size_kb = destination.stat().st_size / 1024
    print(f"Wrote {destination} ({size_kb:.0f} KB)")
    print(
        f"  {len(data['summaries'])} system configurations, "
        f"{len(data['runs'])} runs, {data['scenario_count']} scenarios"
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scorecard",
        help="scored results to render (default: the most recent sweep's scorecard.json)",
    )
    parser.add_argument(
        "--out",
        help="destination HTML file (default: report.html beside the scorecard)",
    )
    raise SystemExit(main(**vars(parser.parse_args())))
