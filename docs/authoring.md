# Adding a scenario

Author `spec.json` only. `context_*.json` and `gold.json` are build outputs — `validate.py` rebuilds
and fails on drift.

## 1. Capture

Put the archive in `datasets/`, add SHA-256 to `datasets/SHA256SUMS`, and list upstream path in
`datasets/README.md`. For OTRF, also update `tools/fetch_datasets.sh`.

Captures are not committed; rebuild with `bash tools/fetch_datasets.sh`.

Build expects NDJSON Windows events (`Channel`, `EventID`, `Hostname`, time). Pcaps via
`source.kind: pcap`. Other shapes need a new kind (step 6).

## 2. `spec.json`

Directory name must match `scenario_id`.

| Field | Purpose |
|---|---|
| `scenario_family` | `clear_malicious`, `ambiguous_dual_use`, `benign_control`, `customer_context_required` |
| `source` | `kind`, `zip`, `citation`, `upstream_path` (+ `captures` for pcap) |
| `environment` | shown to the model |
| `alert` | answer metadata stripped at build |
| `select.minimal` / `curated` | ordered selectors |
| `select.verbose` | window/sampling, not a selector list |
| `enrichment` | curated tier only |
| `gold` | verdict + observations/inferences/entities/investigations/unknowns |

Records get IDs like `R000140`. Put those IDs in gold `record_refs` after a first build.

Alternatives are rare: cite obs/record IDs, set `credit` (default 1), require `credit_rationale` if
`< 1`, and set `terminal_action_allowed`. Partial credit cannot expand Close/Monitor safety.

Selectors: `event_id`, `where`, `limit`, `host`. `where` keys are `field` or `field__op` with
`eq|ieq|contains|not_contains|startswith|endswith|in|gte|lte` (string compare; gte/lte lexical).

`source.kind: derived` needs `transform`; note it in `docs/limitations.md`.

## 3. Anonymization

Map every lab hostname, account, domain, SID prefix, and IP in `tools/environment_map.json`.
Applied last, longest-first, to contexts and gold. Validate fails if map inputs leak or leftover
SIDs/RFC1918 aren't map outputs. Include subnet forms (`172.18.39.0/24` ≠ host).

## 4. Build / validate

```bash
python tools/build_scenarios.py scenario_0NN
python tools/validate.py --require-captures
python -m unittest discover
```

`--check` rebuilds in memory (CI).

## 5. Versions

Bump `INSTRUMENT_VERSION` for prompt/context/gold/schema/scoring. Bump `JUDGE_VERSION` for judge
prompt/model/contract.

## 6. New telemetry shape

Register in `SOURCE_FIELDS_BY_KIND`, branch in `build_scenarios.build`, map fields in
`tools/normalize.py`.
