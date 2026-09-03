# SOC alert triage benchmark

Compares models on SOC alert triage from frozen telemetry.

Each scenario is one alert plus a fixed evidence set. Anything not in that telemetry (org records,
calendars, follow-ups) is out of scope. Gold keys separate observations, inferences, unknowns, and
accepted alternative verdicts.

Scores keep decision quality, grounding, calibration, safety, completion, and cost separate. The
optional `soc-triage` profile combines them for ranking — see [docs/scoring_rubric.md](docs/scoring_rubric.md)
and [docs/limitations.md](docs/limitations.md).

## Setup

Python 3.11+.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m unittest discover
python tools/validate.py
```

Put provider keys in `.env`, then:

```bash
./run_all.sh
```

Validates, runs provider batches, scores, and writes the HTML report. Uses `.venv/bin/python3` when
present. Individual runners support partial / re-runs.

## Output

Live runs write outside the checkout:

```text
~/Downloads/soc-alert-triage-benchmark/
  judge_audit.jsonl
  <sweep-id>/
    results/
    scorecard.*
    report.html
```

Override with `BENCHMARK_OUTPUT_DIR`.

Scorecards are local. Do not commit them. See [`sweeps/README.md`](sweeps/README.md).

## Reading results

Open a local `report.html`, or:

```bash
python tools/report.py --scorecard /path/to/scorecard.json
```

No args → newest scorecard under the output dir. `python tools/paper.py` writes `methodology.pdf`
(needs Chrome/Chromium).

Ranking is opt-in via `WEIGHTING_PROFILES`. CSVs: `scorecard.csv`, `scorecard_runs.csv`,
`scorecard_by_model.csv`.

## Run definition

Model + prompt + decoding on verbose context, 3 runs/scenario, provider default temperature.
Results carry prompt/context hashes so configs are never pooled.

`OUTPUT_SCHEMA` is enforced per provider (OpenAI strict schema, Gemini response schema, Anthropic
forced tool). Citations are checked in code before the grounding judge.

Default scorecards use verbose only. Use `--tiers minimal|curated` and
`--prompt soc-alert-triage-evidence-first` for variants. Scoring filters: `--model`, `--prompt`,
`--tier`, `--experiment`.

## Layout

| Path | Contents |
|---|---|
| `harness/` | prompts, schema, judge, scoring |
| `runners/` | provider batch clients |
| `scenarios/` | `spec.json` + compiled contexts/gold |
| `sweeps/` | local scorecards only (gitignored) |
| `tools/` | build, validate, report, model check |
| `datasets/` | capture provenance (fetched on demand) |
| `docs/` | rubric, limitations, authoring |

Only `context_<tier>.json` reaches the model. Validation rejects answer leaks in those files.

## Changing the instrument

```bash
python tools/build_scenarios.py
python tools/build_scenarios.py --check
```

Bump `INSTRUMENT_VERSION` for prompt/context/gold/schema/scoring changes; bump `JUDGE_VERSION` for
judge changes. See [docs/authoring.md](docs/authoring.md).
