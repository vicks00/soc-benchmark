"""Render a research-facing methodology and reading guide as a PDF."""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from tools.report import latest_scorecard  # noqa: E402

CHROME_CANDIDATES = (
    Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
)


def _fmt(value, digits: int = 3) -> str:
    return "n/a" if value is None else f"{float(value):.{digits}f}"


def _pct(value) -> str:
    return "n/a" if value is None else f"{float(value) * 100:.1f}%"


def _chrome() -> str | None:
    configured = os.environ.get("CHROME_BIN")
    if configured and Path(configured).exists():
        return configured
    for candidate in CHROME_CANDIDATES:
        if candidate.exists():
            return str(candidate)
    for command in ("google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(command)
        if found:
            return found
    return None


def _model_rows(data: dict) -> str:
    rows = sorted(
        data["summaries"],
        key=lambda item: -(item.get("soc_triage_score", item.get("soc_score")) or -999),
    )
    return "".join(
        f"""<tr>
          <td>{html.escape(item["model"])}</td>
          <td>{_fmt(item.get("soc_triage_score", item.get("soc_score")) * 100, 1)}</td>
          <td>{_fmt(item["classification_score"])}</td>
          <td>{_fmt(item["action_score"])}</td>
          <td>{_fmt(item["evidence_precision"])}</td>
          <td>{_fmt(item["brier"])}</td>
          <td>{item.get("unsafe_close_or_monitor_runs", item.get("unsafe_terminal_actions", 0))}</td>
          <td>{item.get("unsupported_claim_runs", item.get("hallucinated_runs", 0))}</td>
          <td>${item["cost"] / data["scenario_count"]:.3f}</td>
        </tr>"""
        for item in rows
    )


def _scenario_rows(data: dict) -> str:
    return "".join(
        f"""<tr>
          <td>{html.escape(item["scenario"].replace("scenario_", ""))}</td>
          <td>{html.escape(item["family"].replace("_", " "))}</td>
          <td>{html.escape(item["reference_class"])}</td>
          <td>{_fmt(item["classification_range"])}</td>
          <td>{_fmt(item.get("soc_triage_score_range", item.get("soc_score_range")))}</td>
          <td>{item.get("unsafe_close_or_monitor_runs", item.get("unsafe_terminal_actions", 0))}</td>
          <td>{"Yes" if item["winner_changed"] else "No"}</td>
        </tr>"""
        for item in data["suite_health"]["scenario_influence"]
    )


def _alternative_rows(data: dict) -> str:
    rows = []
    for scenario, alternatives in data.get("alternative_catalog", {}).items():
        for item in alternatives:
            rows.append(
                f"""<tr>
                  <td>{html.escape(scenario.replace("scenario_", ""))}</td>
                  <td>{html.escape(item["classification"])}</td>
                  <td>{html.escape(item["recommended_action"])}</td>
                  <td>{html.escape(item["severity"])}</td>
                  <td>{item["credit"]:.2f}</td>
                  <td>{html.escape(item["credit_rationale"] or item["rationale"])}</td>
                </tr>"""
            )
    return "".join(rows)


def render(data: dict) -> str:
    baseline = data["baseline"]
    policy = baseline["policy"]
    profile = data["profiles"][data["default_profile"]]
    weights = ", ".join(
        f"{name.replace('_', ' ')} {weight:g}" for name, weight in profile["weights"].items()
    )
    warnings = "".join(f"<li>{html.escape(item)}</li>" for item in data["suite_health"]["warnings"])
    alternatives = _alternative_rows(data)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SOC Alert Triage Benchmark: Methodology and Reading Guide</title>
<style>
@page {{ size: Letter; margin: 0.62in 0.65in 0.68in; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; color: #172033; font: 9.2pt/1.38 Arial, Helvetica, sans-serif; }}
h1 {{ margin: 0 0 7pt; font-size: 22pt; line-height: 1.06; color: #173f70; }}
h2 {{ margin: 15pt 0 5pt; padding-bottom: 3pt; border-bottom: 1px solid #b8c5d6;
      color: #173f70; font-size: 13pt; }}
h3 {{ margin: 9pt 0 3pt; color: #244f7c; font-size: 10.5pt; }}
p {{ margin: 3pt 0 6pt; }}
ul {{ margin: 3pt 0 7pt 15pt; padding: 0; }}
li {{ margin: 1.5pt 0; }}
.kicker {{ color: #55708e; font-size: 9pt; text-transform: uppercase; letter-spacing: 0.08em; }}
.meta {{ color: #5d6877; margin-bottom: 15pt; }}
.abstract {{ border-left: 4px solid #2c669c; padding: 8pt 11pt; background: #f2f6fa; }}
.finding {{ border: 1px solid #9fb2c8; padding: 7pt 9pt; margin: 7pt 0; background: #f8fafc; }}
.formula {{ font-family: Menlo, Consolas, monospace; background: #eef2f6; padding: 5pt 7pt;
            margin: 4pt 0 7pt; }}
.grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12pt; }}
table {{ width: 100%; border-collapse: collapse; margin: 5pt 0 9pt; font-size: 7.7pt;
         page-break-inside: avoid; }}
th {{ background: #e6edf5; color: #193d65; text-align: left; }}
th, td {{ padding: 3.2pt 4pt; border: 1px solid #b9c4d0; vertical-align: top; }}
td:not(:first-child), th:not(:first-child) {{ text-align: right; }}
.wide td:last-child, .wide th:last-child {{ text-align: left; }}
.page {{ break-before: page; }}
.small {{ font-size: 8pt; color: #5d6877; }}
.footer {{ margin-top: 12pt; padding-top: 5pt; border-top: 1px solid #b8c5d6;
           color: #667384; font-size: 7.5pt; }}
</style>
</head>
<body>
<div class="kicker">Research methodology and report-reading guide</div>
<h1>SOC Alert Triage Benchmark</h1>
<div class="meta">Sweep {html.escape(", ".join(data["sweeps"]))} · collection instrument
{html.escape(data["instrument_version"])} · scoring {html.escape(data["scoring_version"])} · judge
{html.escape(data["judge_version"])}</div>

<div class="abstract">
<strong>Purpose.</strong> This benchmark compares frontier language models on evidence-bounded SOC
alert triage. {len(data["summaries"])} model configurations each assessed
{data["scenario_count"]} frozen alert scenarios three times, producing {len(data["runs"])} runs.
The report combines decision quality, confidence calibration, evidence support, operational safety,
and actual batch cost while retaining every underlying measurement.
</div>

<h2>1. Evaluation design</h2>
<div class="grid">
<div>
<h3>What each model receives</h3>
<p>One security alert and a fixed telemetry context. Organization records, maintenance windows,
authorization data, and follow-up tool results are absent unless they are included in that context.</p>
<h3>What each model returns</h3>
<p>A classification, severity, response action, four-class probability distribution, MITRE
techniques, cited observations, supported inferences, affected entities, investigations, unresolved
questions, and an analyst summary.</p>
</div>
<div>
<h3>Reference standard</h3>
<p>Gold keys describe decisions an evidence-bounded SOC analyst could defend from the delivered
telemetry. Full-credit alternatives are peer-equivalent. Partial alternatives are acceptable but
inferior and receive only their declared share of relief.</p>
<h3>Repeated measurement</h3>
<p>Three runs per model and scenario expose response variability. Score spreads in the report are
across scenarios; leave-one-scenario-out ranges show ranking sensitivity to the small task set.</p>
</div>
</div>

<h2>2. Decision and confidence measurements</h2>
<h3>Alert classification</h3>
<p>Malicious, Suspicious, Benign, and Undetermined use an asymmetric distance matrix. Dangerous
misses receive less credit than adjacent cautious judgments.</p>
<h3>Response action</h3>
<p>Close, Continue Monitoring, Escalate for Investigation, and Contain / Isolate Endpoint are
ordered by intervention. Under-reaction loses 0.34 per step; over-reaction loses 0.17.</p>
<h3>Severity</h3>
<p>Informational through Critical use ordinal utility: exact 1.00, one level away 0.75, and two or
more levels away 0. Mean levels off and undercall counts remain visible separately.</p>
<h3>Confidence error</h3>
<div class="formula">Brier = Σ (reported probability - outcome indicator)²</div>
<p>Zero is perfect. A uniform 25% forecast has Brier 0.75. Confidence skill is
<code>1 - model Brier / 0.75</code>, so uniform forecasting has zero skill and worse forecasting is
negative.</p>

<h2>3. SOC triage score</h2>
<p>The score is a declared utility profile. Cost is excluded and shown separately. Current weights:
{html.escape(weights)}.</p>
<p>The decision baseline is a fixed queue policy: classify every alert as
<strong>{html.escape(policy["classification"])}</strong>, assign
<strong>{html.escape(policy["severity"])}</strong>, and
<strong>{html.escape(policy["recommended_action"])}</strong>.</p>
<div class="formula">lift = (model score - baseline score) / (1 - baseline score)</div>
<p>Baseline lift is zero, perfect decision utility is one, and performance below the fixed policy is
negative. The composite is multiplied by 100 for display.</p>

<div class="page"></div>
<h2>4. Evidence support and safety</h2>
<h3>Supported factual claims</h3>
<p>Version 3.4 requires stable telemetry record citations and exact field/value facts. Exact facts
are checked in code. Remaining semantic claims are judged through constrained Haiku output that
maps candidate IDs to grounded booleans and reference IDs.</p>
<p>This archived sweep was collected under 3.2 and uses its cached v9 free-text grounding judgments.
The report labels collection, scoring, and judge versions separately.</p>
<h3>Unsafe close or monitor</h3>
<p>A run is unsafe when it recommends Close or Continue Monitoring while the reference requires
active escalation or containment. Partial-credit alternatives never expand permission to Close or
Continue Monitoring.</p>
<h3>Recommended review mode</h3>
<ul>
  <li><strong>Candidate for controlled autonomy testing:</strong> no unsafe close/monitor, no false
  alarm, and Brier at or below 0.15.</li>
  <li><strong>Analyst approval required:</strong> safe actions, but calibration or false-alarm
  requirements were not met.</li>
  <li><strong>Drafting only:</strong> at least one unsafe close/monitor recommendation.</li>
</ul>
<p>These modes summarize ten scenarios and do not authorize production deployment.</p>

<h2>5. How to read the HTML report</h2>
<table class="wide">
<tr><th>Section</th><th>Decision question</th></tr>
<tr><td>Decision summary</td><td>Which configuration leads, how many beat the fixed policy, and which
qualify for further controlled-autonomy testing?</td></tr>
<tr><td>Leaderboard</td><td>How do quality, safety, evidence support, calibration, and cost compare?</td></tr>
<tr><td>Where the ranking comes from</td><td>Which scenarios distinguish models and which are already
saturated?</td></tr>
<tr><td>Per-scenario heatmap</td><td>Where does each model fail?</td></tr>
<tr><td>Score against cost</td><td>What quality is available under a budget constraint?</td></tr>
<tr><td>Calibration</td><td>Does a model's stated confidence match observed correctness?</td></tr>
<tr><td>Unsafe close/monitor</td><td>Which model and scenario combinations would stop active handling
too early?</td></tr>
<tr><td>Credited alternatives</td><td>Which runs received relief from an adjudicated second answer,
and at what credit?</td></tr>
<tr><td>Ranking stability</td><td>Does removing one scenario change score or rank?</td></tr>
</table>

<div class="page"></div>
<h2>6. Results snapshot</h2>
<table>
<tr><th>Model</th><th>SOC score</th><th>Class</th><th>Action</th><th>Supported</th>
<th>Brier</th><th>Unsafe</th><th>Unsupported</th><th>Cost/scenario</th></tr>
{_model_rows(data)}
</table>

<h3>Scenario influence</h3>
<table>
<tr><th>Scenario</th><th>Family</th><th>Reference</th><th>Class range</th><th>SOC range</th>
<th>Unsafe</th><th>Winner changes</th></tr>
{_scenario_rows(data)}
</table>

<h3>Suite-health warnings</h3>
<ul>{warnings}</ul>

<h2>7. Credited alternatives and adjudication</h2>
<table class="wide">
<tr><th>Scenario</th><th>Class</th><th>Action</th><th>Severity</th><th>Credit</th>
<th>Adjudication</th></tr>
{alternatives}
</table>

<div class="page"></div>
<h2>8. Limitations and use</h2>
<ul>
  <li>Ten scenarios support gross failure detection and pilot selection, not production
  authorization or close rankings.</li>
  <li>Only one primary reference is Benign. Several scenario families contain fewer than three
  alerts.</li>
  <li>Removing scenario 010 changes the winner, so the leading pair is not stable to every
  single-scenario omission.</li>
  <li>Source captures are public and may be represented in model training data.</li>
  <li>Reference keys have not been independently adjudicated by multiple SOC analysts.</li>
  <li>The completed sweep used a single v9 Haiku grounding judge. Claim-level manual audit remains
  appropriate for published grounding conclusions.</li>
  <li>The benchmark measures single-turn triage over fixed evidence. It does not measure tool use,
  interactive investigation, latency, or environment-specific trust.</li>
</ul>

<div class="finding"><strong>Decision use.</strong> Treat the report as evidence for choosing models
for a larger controlled pilot. Retain human approval for operational actions until a broader,
independently adjudicated scenario set confirms safety and calibration.</div>

<div class="footer">Generated from scorecard.json · sweep
{html.escape(", ".join(data["sweeps"]))} · {html.escape(data["generated"])}</div>
</body>
</html>"""


def main(scorecard: str | None, out: str | None) -> int:
    source = Path(scorecard).expanduser() if scorecard else latest_scorecard()
    if source is None or not source.exists():
        print("No scorecard found. Run `python -m harness.scoring` first.")
        return 1
    data = json.loads(source.read_text())
    destination = Path(out).expanduser().resolve() if out else source.parent / "methodology.pdf"
    chrome = _chrome()
    if chrome is None:
        print("Chrome or Chromium is required to render methodology.pdf. Set CHROME_BIN.")
        return 1
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        source_html = Path(directory) / "methodology.html"
        source_html.write_text(render(data))
        result = subprocess.run(
            [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={destination}",
                source_html.as_uri(),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode or not destination.exists():
        print(result.stderr.strip() or "Chrome failed to render the methodology PDF.")
        return 1
    print(f"Wrote {destination} ({destination.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scorecard", help="scorecard.json to explain")
    parser.add_argument("--out", help="PDF destination (default: methodology.pdf beside scorecard)")
    raise SystemExit(main(**vars(parser.parse_args())))
