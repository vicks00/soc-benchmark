"""List provider-visible models and reconcile the configured registry."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness.config import MODEL_TIERS, NEW_MODELS, PRICING


def _anthropic() -> set[str]:
    import anthropic

    return {model.id for model in anthropic.Anthropic().models.list(limit=100).data}


def _google() -> set[str]:
    from google import genai

    # The client is bound to a local before listing: a temporary is garbage collected mid-request
    # and the call dies with "the client has been closed".
    client = genai.Client()
    return {model.name.split("/")[-1] for model in client.models.list()}


def _openai() -> set[str]:
    from openai import OpenAI

    return {model.id for model in OpenAI().models.list().data}


PROVIDERS = (
    ("Anthropic", "ANTHROPIC_API_KEY", _anthropic),
    ("Google (Gemini)", "GEMINI_API_KEY", _google),
    ("OpenAI", "OPENAI_API_KEY", _openai),
)


def visible_models() -> set[str]:
    """Every model id the configured keys can see. A provider that errors is reported and skipped,
    so one bad key still leaves the others checkable."""
    available: set[str] = set()
    for name, key, list_models in PROVIDERS:
        if not os.environ.get(key):
            continue
        print(f"\n=== {name} ===")
        try:
            identifiers = list_models()
        except Exception as error:  # noqa: BLE001
            print(f"  [{name} error] {error}")
            continue
        for identifier in sorted(identifiers):
            print(f"  {identifier}")
        available |= identifiers
    return available


def main() -> int:
    available = visible_models()
    if not available:
        print("No provider keys set; nothing to check.")
        return 0

    configured = [model for provider in MODEL_TIERS.values() for model in provider.values()] + list(
        NEW_MODELS
    )

    print("\n=== Registry reconciliation ===")
    problems = 0
    for model in configured:
        # Providers expose dated snapshot ids, so match either direction against the registry.
        visible = model in available or any(
            candidate.startswith(model) or model.startswith(candidate) for candidate in available
        )
        priced = model in PRICING or any(model.startswith(known) for known in PRICING)
        flags = []
        if not visible:
            flags.append("NOT VISIBLE TO YOUR KEY")
        if not priced:
            flags.append("NO PRICING ENTRY")
        problems += bool(flags)
        print(f"  {'ok  ' if not flags else 'FAIL'} {model:<30} {'; '.join(flags)}")
    print(f"\n{problems} problem(s). Fix harness/config.py before running a paid sweep.")
    # Non-zero so this can gate a sweep rather than only inform one.
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
