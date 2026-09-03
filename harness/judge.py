"""Ground model evidence in telemetry and measure reference-key coverage."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time

from harness.config import (
    INSTRUMENT_VERSION,
    JUDGE_MODEL,
    LEGACY_OUTPUT_DIR,
    OUTPUT_DIR,
    instrument_at_least,
    load_context,
)

# Append-only judgment cache shared across sweeps.
_AUDIT_PATH = OUTPUT_DIR / "judge_audit.jsonl"
_LEGACY_CACHE_PATH = OUTPUT_DIR / "judge_cache.json"
_V9_AUDIT_PATH = LEGACY_OUTPUT_DIR / "judge_audit.jsonl"
_V9_CACHE_PATH = LEGACY_OUTPUT_DIR / "judge_cache.json"

# Bump when judge prompt, model, or contract changes.
JUDGE_VERSION = "v10"
LEGACY_JUDGE_VERSION = "v9"


def is_available() -> bool:
    if _AUDIT_PATH.exists() or _V9_AUDIT_PATH.exists():
        return True
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401

        return True
    except ImportError:
        return False


_judgments: dict[str, dict] | None = None
_legacy_by_output: dict[tuple[str, str], dict] | None = None


def _cached_judgments() -> dict[str, dict]:
    """Every judgment made so far, read from the append-only log exactly once per process."""
    global _judgments
    if _judgments is not None:
        return _judgments

    _judgments = {}
    for cache_path in (_LEGACY_CACHE_PATH, _V9_CACHE_PATH):
        if cache_path.exists():
            with contextlib.suppress(json.JSONDecodeError):
                _judgments.update(json.loads(cache_path.read_text()))
    for audit_path in (_V9_AUDIT_PATH, _AUDIT_PATH):
        if not audit_path.exists():
            continue
        for line in audit_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "key" in entry and "judgment" in entry:
                _judgments[entry["key"]] = entry["judgment"]
    return _judgments


def _legacy_judgments() -> dict[tuple[str, str], dict]:
    """v9 judgments keyed by (scenario, output) — digests changed with later context fields."""
    global _legacy_by_output
    if _legacy_by_output is not None:
        return _legacy_by_output
    _legacy_by_output = {}
    if not _V9_AUDIT_PATH.exists():
        return _legacy_by_output
    for line in _V9_AUDIT_PATH.read_text().splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            entry = json.loads(line)
            if {"scenario", "output", "judgment"} <= set(entry):
                key = (entry["scenario"], json.dumps(entry["output"], sort_keys=True))
                _legacy_by_output[key] = entry["judgment"]
    return _legacy_by_output


def _record(key: str, scenario_id: str, output: dict, judgment: dict):
    _cached_judgments()[key] = judgment
    _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "key": key,
        "judge_version": JUDGE_VERSION,
        "scenario": scenario_id,
        "output": output,
        "judgment": judgment,
    }
    with open(_AUDIT_PATH, "a") as handle:
        handle.write(json.dumps(entry) + "\n")


def _coverage_and_precision(judgment: dict, category: str, gold_count: int):
    section = (judgment or {}).get(category, {})
    covered = set(section.get("gold_covered", []) or [])
    grounded = section.get("model_grounded", []) or []
    recall = min(len(covered) / gold_count, 1.0) if gold_count else 1.0
    precision = (sum(1 for item in grounded if item) / len(grounded)) if grounded else 0.0
    unsupported = any(not item for item in grounded)
    return precision, recall, unsupported


def _recall(covered, gold_items) -> float:
    return min(len(set(covered or [])) / len(gold_items), 1.0) if gold_items else 1.0


def _v9_grounding(scenario_id: str, gold: dict, output: dict):
    """Score an archived free-text evidence submission under the v9 contract."""
    lookup = (scenario_id, json.dumps(output, sort_keys=True))
    judgment = _legacy_judgments().get(lookup)
    if judgment is None:
        raise RuntimeError(
            "archived v9 judgment is absent; the original v9 telemetry contract is unavailable"
        )

    evidence = judgment.get("evidence", {})
    items = evidence.get("model_items", []) or []
    claims = [item for item in items if item.get("claim")]
    precision = (sum(1 for item in claims if item.get("grounded")) / len(claims)) if claims else 1.0
    fabricated = any(item.get("claim") and not item.get("grounded") for item in items)

    entity_precision, entity_recall, unsupported_entity = _coverage_and_precision(
        judgment, "entities", len(gold["entities"])
    )
    _, investigation_recall, _ = _coverage_and_precision(
        judgment, "investigations", len(gold["investigations"])
    )
    _, unknown_recall, _ = _coverage_and_precision(judgment, "unknowns", len(gold["unknowns"]))
    return {
        "evidence_precision": precision,
        "observation_recall": _recall(evidence.get("observations_covered"), gold["observations"]),
        "inference_recall": _recall(evidence.get("inferences_covered"), gold["inferences"]),
        "entity_precision": entity_precision,
        "entity_recall": entity_recall,
        "investigation_recall": investigation_recall,
        "unknown_recall": unknown_recall,
        "unsupported_claim": fabricated or unsupported_entity,
    }


_V10_SYSTEM = """You verify atomic SOC alert-triage claims. Each observation includes the exact
telemetry records it cites. Mark grounded=true only when the observation is fully supported by
those records. Map each candidate item only to reference items it substantively covers. Use the
forced tool and return no prose."""


def _judge_item(candidate_pattern: str, gold_ids: list[str], grounded: bool = False) -> dict:
    properties = {
        "candidate_id": {"type": "string", "pattern": f"^{candidate_pattern}$"},
        "covered_gold_ids": {
            "type": "array",
            "items": {"type": "string", "enum": gold_ids},
        },
    }
    if grounded:
        properties["grounded"] = {"type": "boolean"}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


def _v10_tool(gold: dict) -> dict:
    entity_ids = [f"EN{index + 1}" for index in range(len(gold["entities"]))]
    arrays = {
        "observations": _judge_item(r"E\d+", [item["id"] for item in gold["observations"]], True),
        "inferences": _judge_item(r"I\d+", [item["id"] for item in gold["inferences"]]),
        "entities": _judge_item(r"A\d+", entity_ids),
        "investigations": _judge_item(r"P\d+", [item["id"] for item in gold["investigations"]]),
        "unknowns": _judge_item(r"U\d+", [item["id"] for item in gold["unknowns"]]),
    }
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": list(arrays),
        "properties": {
            name: {"type": "array", "items": item_schema} for name, item_schema in arrays.items()
        },
    }
    return {
        "name": "submit_grounding",
        "description": "Submit grounded-claim decisions and reference coverage.",
        "input_schema": schema,
    }


def _reference_catalog(gold: dict) -> dict:
    return {
        "observations": [
            {"id": item["id"], "description": item["desc"]} for item in gold["observations"]
        ],
        "inferences": [
            {"id": item["id"], "description": item["desc"]} for item in gold["inferences"]
        ],
        "entities": [
            {"id": f"EN{index + 1}", "description": f"{item['type']}: {item['value']}"}
            for index, item in enumerate(gold["entities"])
        ],
        "investigations": [
            {"id": item["id"], "description": item["desc"]} for item in gold["investigations"]
        ],
        "unknowns": [{"id": item["id"], "description": item["desc"]} for item in gold["unknowns"]],
    }


def _cited_submission(scenario_id: str, tier: str, output: dict) -> dict:
    records = {
        record["record_id"]: record
        for record in load_context(scenario_id, tier)["telemetry"]
        if record.get("record_id")
    }
    observations = []
    for item in output["observations"]:
        observations.append(
            {
                **item,
                "cited_records": [records[record_id] for record_id in item["record_refs"]],
            }
        )
    return {
        "observations": observations,
        "inferences": output["inferences"],
        "affected_entities": output["affected_entities"],
        "recommended_investigations": output["recommended_investigations"],
        "requires_verification": output["requires_verification"],
    }


def _v10_prompt(scenario_id: str, tier: str, gold: dict, output: dict) -> str:
    return (
        "REFERENCE CATALOG:\n"
        f"{json.dumps(_reference_catalog(gold), indent=2)}\n\n"
        "CANDIDATE SUBMISSION WITH CITED TELEMETRY:\n"
        f"{json.dumps(_cited_submission(scenario_id, tier, output), indent=2)}"
    )


def _expected_candidate_ids(output: dict) -> dict[str, set[str]]:
    return {
        "observations": {item["id"] for item in output["observations"]},
        "inferences": {item["id"] for item in output["inferences"]},
        "entities": {item["id"] for item in output["affected_entities"]},
        "investigations": {item["id"] for item in output["recommended_investigations"]},
        "unknowns": {item["id"] for item in output["requires_verification"]},
    }


def _allowed_gold_ids(gold: dict) -> dict[str, set[str]]:
    return {
        "observations": {item["id"] for item in gold["observations"]},
        "inferences": {item["id"] for item in gold["inferences"]},
        "entities": {f"EN{index + 1}" for index in range(len(gold["entities"]))},
        "investigations": {item["id"] for item in gold["investigations"]},
        "unknowns": {item["id"] for item in gold["unknowns"]},
    }


def validate_judgment(judgment: object, gold: dict, output: dict) -> str | None:
    expected = _expected_candidate_ids(output)
    allowed = _allowed_gold_ids(gold)
    if not isinstance(judgment, dict) or set(judgment) != set(expected):
        return "judge response fields do not match the v10 contract"
    for category, expected_ids in expected.items():
        items = judgment[category]
        if not isinstance(items, list):
            return f"judge response {category} must be a list"
        candidate_ids = [item.get("candidate_id") for item in items if isinstance(item, dict)]
        if len(candidate_ids) != len(items) or set(candidate_ids) != expected_ids:
            return f"judge response {category} does not align to candidate ids"
        if len(candidate_ids) != len(set(candidate_ids)):
            return f"judge response {category} contains duplicate candidate ids"
        for item in items:
            required = {"candidate_id", "covered_gold_ids"}
            if category == "observations":
                required.add("grounded")
            if set(item) != required:
                return f"judge response {category} item fields do not match the contract"
            covered = item["covered_gold_ids"]
            if not isinstance(covered, list) or not set(covered) <= allowed[category]:
                return f"judge response {category} cites unknown reference ids"
            if category == "observations" and not isinstance(item["grounded"], bool):
                return "judge response observation grounded must be boolean"
    return None


def _v10_key(scenario_id: str, tier: str, gold: dict, output: dict) -> str:
    return hashlib.sha256(
        json.dumps(
            [JUDGE_VERSION, scenario_id, tier, _cited_submission(scenario_id, tier, output), gold],
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _call_v10_judge(scenario_id: str, tier: str, gold: dict, output: dict) -> dict:
    import anthropic

    client = anthropic.Anthropic()
    tool = _v10_tool(gold)
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            response = client.messages.create(
                model=JUDGE_MODEL,
                max_tokens=3000,
                temperature=0,
                system=_V10_SYSTEM,
                messages=[
                    {
                        "role": "user",
                        "content": _v10_prompt(scenario_id, tier, gold, output),
                    }
                ],
                tools=[tool],
                tool_choice={"type": "tool", "name": tool["name"]},
            )
            block = next(
                (
                    item
                    for item in response.content
                    if getattr(item, "type", None) == "tool_use" and item.name == tool["name"]
                ),
                None,
            )
            if block is None:
                raise ValueError("judge did not call the required grounding tool")
            error = validate_judgment(block.input, gold, output)
            if error:
                raise ValueError(error)
            return block.input
        except Exception as error:  # noqa: BLE001
            last_error = error
            if attempt < 4:
                time.sleep(2**attempt * 3)
    raise RuntimeError(f"judge failed after retries: {last_error!r}")


def _programmatic_entity_grounding(scenario_id: str, tier: str, output: dict) -> dict[str, bool]:
    records = {
        record["record_id"]: json.dumps(record).lower()
        for record in load_context(scenario_id, tier)["telemetry"]
        if record.get("record_id")
    }
    return {
        entity["id"]: any(
            entity["value"].lower() in records[record_id] for record_id in entity["record_refs"]
        )
        for entity in output["affected_entities"]
    }


def _v10_grounding(scenario_id: str, tier: str, gold: dict, output: dict) -> dict:
    key = _v10_key(scenario_id, tier, gold, output)
    judgment = _cached_judgments().get(key)
    if judgment is None:
        judgment = _call_v10_judge(scenario_id, tier, gold, output)
        _record(key, scenario_id, output, judgment)
    error = validate_judgment(judgment, gold, output)
    if error:
        raise RuntimeError(f"cached judge response is invalid: {error}")

    by_category = {
        category: {item["candidate_id"]: item for item in items}
        for category, items in judgment.items()
    }
    observation_results = list(by_category["observations"].values())
    grounded_observations = [item["grounded"] for item in observation_results]
    entity_grounding = _programmatic_entity_grounding(scenario_id, tier, output)
    covered = {
        category: set().union(
            *(set(item["covered_gold_ids"]) for item in items),
            set(),
        )
        for category, items in by_category.items()
    }
    return {
        "evidence_precision": (
            sum(grounded_observations) / len(grounded_observations)
            if grounded_observations
            else 1.0
        ),
        "observation_recall": _recall(covered["observations"], gold["observations"]),
        "inference_recall": _recall(covered["inferences"], gold["inferences"]),
        "entity_precision": (
            sum(entity_grounding.values()) / len(entity_grounding) if entity_grounding else 1.0
        ),
        "entity_recall": _recall(covered["entities"], gold["entities"]),
        "investigation_recall": _recall(covered["investigations"], gold["investigations"]),
        "unknown_recall": _recall(covered["unknowns"], gold["unknowns"]),
        "unsupported_claim": any(not grounded for grounded in grounded_observations)
        or any(not grounded for grounded in entity_grounding.values()),
    }


def judge_grounding(
    scenario_id: str,
    tier: str,
    gold: dict,
    output: dict,
    instrument_version: str = INSTRUMENT_VERSION,
):
    """Return grounding and coverage under the protocol that produced the submission."""
    if not instrument_at_least(instrument_version, (3, 4)):
        return _v9_grounding(scenario_id, gold, output)
    return _v10_grounding(scenario_id, tier, gold, output)
