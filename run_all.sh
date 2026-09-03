#!/usr/bin/env bash
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -x .venv/bin/python3 ]]; then
  PYTHON="$PWD/.venv/bin/python3"
else
  PYTHON="${PYTHON:-python3}"
fi

"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo "ERROR: Python 3.11 or newer is required (found $("$PYTHON" -V 2>&1))" >&2
  echo "       Create .venv and install requirements; see README.md." >&2
  echo "       Python 3.10 and earlier are past end of life." >&2
  exit 1
}

if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi

missing_keys=()
[[ -n "${ANTHROPIC_API_KEY:-}" ]] || missing_keys+=("ANTHROPIC_API_KEY")
[[ -n "${GEMINI_API_KEY:-}" ]] || missing_keys+=("GEMINI_API_KEY")
[[ -n "${OPENAI_API_KEY:-}" ]] || missing_keys+=("OPENAI_API_KEY")
if (( ${#missing_keys[@]} )); then
  echo "ERROR: a full sweep requires: ${missing_keys[*]}" >&2
  echo "       Run an individual provider module when collecting a partial sweep." >&2
  exit 1
fi

export BENCHMARK_SWEEP_ID="${BENCHMARK_SWEEP_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"

echo "==> Validating the instrument (no API calls)"
"$PYTHON" tools/validate.py

echo
echo "==> Checking configured model IDs (no paid generation)"
"$PYTHON" tools/list_models.py

echo
echo "Sweep id: $BENCHMARK_SWEEP_ID"

# Continue on provider failure so partial sweeps are still scoreable.
failed_providers=()

run_provider() {
  local label="$1" module="$2"
  echo; echo "==> $label"
  if ! "$PYTHON" -m "$module"; then
    echo "!!! $label failed; continuing with the remaining providers." >&2
    failed_providers+=("$label")
  fi
}

run_provider Anthropic runners.anthropic_batch
run_provider Google runners.google_batch
run_provider OpenAI runners.openai_batch

echo; echo "==> Scoring"
"$PYTHON" -m harness.scoring --tier verbose --sweep "$BENCHMARK_SWEEP_ID"

echo; echo "==> Report"
"$PYTHON" tools/report.py

echo; echo "==> Methodology paper"
"$PYTHON" tools/paper.py

echo
echo "Done. Everything this pass produced is under:"
echo "  ${BENCHMARK_OUTPUT_DIR:-$HOME/Downloads/soc-alert-triage-benchmark}/$BENCHMARK_SWEEP_ID/"
echo "    results/     raw model output, re-scorable without new API calls"
echo "    scorecard.*  scored results"
echo "    report.html  the rendered report"
echo "    methodology.pdf  methodology and report-reading guide"

if (( ${#failed_providers[@]} )); then
  echo
  echo "WARNING: these providers did not complete: ${failed_providers[*]}" >&2
  echo "Resume this sweep with:" >&2
  for provider in "${failed_providers[@]}"; do
    case "$provider" in
      Anthropic) module="runners.anthropic_batch" ;;
      Google) module="runners.google_batch" ;;
      OpenAI) module="runners.openai_batch" ;;
    esac
    echo "  BENCHMARK_SWEEP_ID=$BENCHMARK_SWEEP_ID \"$PYTHON\" -m $module" >&2
  done
  echo "  \"$PYTHON\" -m harness.scoring --tier verbose --sweep $BENCHMARK_SWEEP_ID" >&2
  echo "  \"$PYTHON\" tools/report.py" >&2
  echo "  \"$PYTHON\" tools/paper.py" >&2
  exit 1
fi
