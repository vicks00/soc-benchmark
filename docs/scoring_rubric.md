# Scoring rubric

Scores are comparable when instrument, model, prompt, and decoding match (verbose by default;
tier must match for context studies). Manifests store these fields.

No default composite score — ranking is opt-in via [Weighting profiles](#weighting-profiles).

## Decision measurements

Classification, action, severity, and technique are scored separately.

Classification matrix (reference row / predicted column):

|  | Malicious | Suspicious | Undetermined | Benign |
|---|---:|---:|---:|---:|
| Malicious | 1.0 | 0.7 | 0.3 | 0.0 |
| Suspicious | 0.7 | 1.0 | 0.6 | 0.1 |
| Benign | 0.3 | 0.6 | 0.6 | 1.0 |
| Undetermined | 0.5 | 0.7 | 1.0 | 0.5 |

Action: ordered Close → Contain/Isolate; under-reaction costs 2× over-reaction per step.
Severity: exact=1.0, ±1=0.75, ≥2=0. Technique: exact=1.0, parent=0.5.

Also report severity exact rate, MAE, undercall rate, severe undercall (≥2 levels below every
accepted severity).

Full-credit alternatives take the best score across the accepted set. Partial `credit` ∈ [0,1]:

```text
credited = primary + credit × max(0, alt − primary)
```

Never below the primary-only score. Partial alts can improve ordinal severity error/utility but
cannot make severity “exact” or lower undercall safety. Soft Brier targets use mass `c` on the alt
and `1−c` on the primary. `correct` = primary + full-credit alts; `acceptable` includes partial.
Partial alts never expand Close / Continue Monitoring.

## Grounding and coverage

Code checks: cited records exist, exact field claims match, inference links resolve, entity cites
are in context. Then Haiku (v10) judges semantic grounding/coverage via forced tool output.

Reports: evidence precision; observation/inference/entity recall; investigation/unknown coverage;
unsupported factual claims. Keyword fallback is exploratory-only and labeled as such.

## Confidence

Four-class probs must sum to 1. Multiclass Brier (0–2, lower better):

```text
Brier = Σ (p − y)²
```

Best over accepted labels when alternatives exist. Consistency (selected class is a mode) is
separate. Diagnostic only — not folded into decision quality.

SOC profile Brier skill vs uniform (0.75):

```text
skill = 1 − Brier / 0.75
```

## Weighting profiles

Declared in `WEIGHTING_PROFILES`. Add your own.

### Baseline lift

`baseline_relative` profiles use lift vs fixed policy Malicious / High / Escalate for Investigation:

```text
lift = (score − baseline) / (1 − baseline)
```

Raw classification already ~0.87 for always-Malicious here; lift puts baseline at 0. Grounding stays
raw (fixed guess cites nothing).

### `soc-triage`

Report default when ranking: action > classification; brier_skill + evidence_precision; lighter
observation_recall and severity. Technique/other recall stay out of the composite.

### Autonomy tier

| Tier | Earned by |
|---|---|
| Candidate for controlled autonomy testing | No unsafe close/monitor, no false alarm, Brier ≤ 0.15 |
| Analyst approval required | No unsafe close/monitor; other gates missed |
| Drafting only | Closed/downgraded a real alert |

Statement about ten scenarios — not deploy auth.

## Output format

v3.4: observations vs inferences, record citations, controlled entity/investigation/unknown types.
Schema-enforced per provider; probs sum and non-empty strings checked after parse.

## Safety counters

Raw counts: unsafe close/monitor, false alarms, correct closes, unsupported claims, refusals,
timeouts, invalid outputs, missing results. Close / Continue Monitoring are terminal.

## Other

False alarms, correct closes, completion/invalids, tokens/cost. No latency (async batch APIs).
