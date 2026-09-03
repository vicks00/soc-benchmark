# Local sweeps

Scorecards stay on your machine. They are not part of the public repo.

Live runs write outside the checkout (`BENCHMARK_OUTPUT_DIR` or
`~/Downloads/soc-alert-triage-benchmark/`). You can also drop a copy under
`sweeps/<sweep-id>/` for yourself. That directory is gitignored.

## Typical files

| File | Role |
|---|---|
| `report.html` | Self-contained interactive report |
| `scorecard.json` | Canonical scored artifact |
| `scorecard.md` | Same results as tables |
| `scorecard.csv` | Per scenario × configuration |
| `scorecard_by_model.csv` | Per configuration summary |
| `scorecard_runs.csv` | Per-run metrics |

Do not commit `results/` or these scorecards.
