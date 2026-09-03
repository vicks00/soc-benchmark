from __future__ import annotations

import copy
import re


def blind_context(context: dict) -> dict:
    """Return a model-safe copy with explicit answer-bearing alert metadata removed."""
    blinded = copy.deepcopy(context)
    alert = blinded.get("alert", {})
    alert.pop("mitre_attack", None)

    rule_name = alert.get("rule_name", "")
    if ":" in rule_name:
        alert["rule_name"] = rule_name.split(":", 1)[1].strip()

    for key in ("rule_id", "rule_name"):
        if key in alert:
            cleaned = re.sub(r"-?\bT\d{4}(?:\.\d{3})?\b", "", str(alert[key]))
            alert[key] = re.sub(r"--+", "-", cleaned).strip("- ").strip()
    return blinded
