# Limitations

- **Public telemetry:** OTRF-style captures may be in training data. Anonymization removes lab IDs,
  not contamination risk.
- **Sample size:** Ten scenarios are for development and gross failures, not tight rankings or
  production calibration. One primary Benign. LOSO ranks move when scenario 010 is dropped.
- **Constructed controls:** 009 and 010 are transforms of real captures; gold describes the
  transformed telemetry, which can differ from intent.
- **Reference review:** Single-author, evidence-bounded keys — not multi-analyst adjudicated.
- **Automated judge:** Exact citations checked in code; semantic coverage is one Haiku judge. Audit
  the claim-level JSONL before publishing grounding claims.
- **Sampling:** Verbose high-volume classes are deterministically sampled; required/pinned IDs stay
  complete (coverage metadata is in context).
- **Model drift:** IDs, behavior, pricing change — verify registry before paid runs.
- **Scope:** Single-turn, fixed evidence. No interactive investigation, tools, latency, or
  environment-specific trust.
