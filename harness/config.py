"""Benchmark configuration, prompt registry, schemas, and result records."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from functools import cache
from pathlib import Path

from harness.reference import ACTION_ALIASES, ACTIONS, CLASSIFICATIONS, SEVERITIES

BASE = Path(__file__).resolve().parent.parent
SCENARIOS_DIR = BASE / "scenarios"

# Live runs write outside the repo; override with BENCHMARK_OUTPUT_DIR.
OUTPUT_DIR = Path(
    os.environ.get("BENCHMARK_OUTPUT_DIR")
    or Path.home() / "Downloads" / "soc-alert-triage-benchmark"
).expanduser()
LEGACY_OUTPUT_DIR = Path.home() / "Downloads" / "mdr-benchmark"

try:
    from dotenv import load_dotenv

    load_dotenv(BASE / ".env")
except ImportError:
    pass

TIERS = ["minimal", "curated", "verbose"]
DEFAULT_RUN_TIERS = ["verbose"]

SWEEP_ID = os.environ.get("BENCHMARK_SWEEP_ID") or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def sweep_output_dir(sweep: str) -> Path:
    legacy = LEGACY_OUTPUT_DIR / sweep
    current = OUTPUT_DIR / sweep
    if legacy.exists() and not current.exists():
        return legacy
    return current


def sweep_dir(sweep: str) -> Path:
    return sweep_output_dir(sweep) / "results"


def _discover() -> dict[str, dict]:
    found = {}
    for gold_path in sorted(SCENARIOS_DIR.glob("*/gold.json")):
        scenario_id = gold_path.parent.name
        contexts = {tier: gold_path.parent / f"context_{tier}.json" for tier in TIERS}
        missing = [tier for tier, path in contexts.items() if not path.exists()]
        if missing:
            raise FileNotFoundError(
                f"{scenario_id} is missing context tier(s) {missing}. "
                f"Run `python tools/build_scenarios.py` to build them from spec.json."
            )
        found[scenario_id] = {
            "gold": gold_path,
            "context": contexts,
            "dir": gold_path.parent,
        }
    if not found:
        raise FileNotFoundError(f"No scenarios found under {SCENARIOS_DIR}.")
    return found


SCENARIOS = _discover()

USE_LLM_JUDGE = True
JUDGE_MODEL = "claude-haiku-4-5-20251001"

RUNS_PER_CELL = 3
TEMPERATURE = None

# No output cap (truncated JSON counts as invalid). Anthropic still needs max_tokens.
MAX_OUTPUT_TOKENS = None
ANTHROPIC_MAX_TOKENS = 16384

# Bump when prompts, contexts, gold, schema, or scoring change.
INSTRUMENT_VERSION = "3.4"


def instrument_at_least(version: str | None, minimum: tuple[int, int]) -> bool:
    try:
        major, minor = (int(part) for part in str(version).split(".", 1))
    except (TypeError, ValueError):
        return False
    return (major, minor) >= minimum


MODEL_TIERS = {
    "anthropic": {
        "small": "claude-haiku-4-5-20251001",
        "mid": "claude-sonnet-5",
        "flagship": "claude-opus-5",
    },
    "google": {
        "small": "gemini-3.5-flash-lite",
        "mid": "gemini-3.6-flash",
        "flagship": "gemini-3.1-pro-preview",
    },
    "openai": {"small": "gpt-5.6-luna", "mid": "gpt-5.6-terra", "flagship": "gpt-5.6-sol"},
}

NEW_MODELS = {
    "claude-fable-5": {"provider": "anthropic", "tier": "flagship"},
}

# USD / 1M tokens
PRICING = {
    "claude-haiku-4-5": {"in": 1.00, "out": 5.00},
    "claude-haiku-4-5-20251001": {"in": 1.00, "out": 5.00},
    "claude-sonnet-5": {"in": 3.00, "out": 15.00},
    "claude-opus-5": {"in": 5.00, "out": 25.00},
    "claude-fable-5": {"in": 5.00, "out": 25.00},
    "gemini-3.5-flash-lite": {"in": 0.30, "out": 2.50},
    "gemini-3.6-flash": {"in": 1.50, "out": 7.50},
    "gemini-3.1-pro-preview": {"in": 2.00, "out": 12.00},
    "gpt-5.6-luna": {"in": 0.20, "out": 1.25},
    "gpt-5.6-terra": {"in": 0.50, "out": 2.00},
    "gpt-5.6-sol": {"in": 5.00, "out": 30.00},
}

BATCH_DISCOUNT = 0.5

BANDS = ["small", "mid", "flagship"]


def all_models() -> list[str]:
    return [
        MODEL_TIERS[provider][band]
        for provider in MODEL_TIERS
        for band in BANDS
        if band in MODEL_TIERS[provider]
    ]


def new_models_for(provider: str) -> list[str]:
    return [model for model, meta in NEW_MODELS.items() if meta["provider"] == provider]


def models_for(provider: str) -> list[str]:
    return [MODEL_TIERS[provider][band] for band in BANDS if band in MODEL_TIERS[provider]]


def provider_of(model: str) -> str:
    if model.startswith("claude"):
        return "anthropic"
    if model.startswith("gemini"):
        return "google"
    if model.startswith("gpt"):
        return "openai"
    return "unknown"


def band_of(model: str) -> str:
    for provider in MODEL_TIERS.values():
        for band, configured in provider.items():
            if configured == model:
                return band
    if model in NEW_MODELS:
        return f"new ({NEW_MODELS[model]['tier']})"
    return "unknown"


# Opt-in ranking profiles. Add your own; don't reinterpret these.
WEIGHTING_PROFILES = {
    "none": {
        "label": "No ranking; dimensions reported separately",
        "weights": {},
        "disqualify": (),
    },
    "balanced": {
        "label": "Decision and grounding weighted equally",
        "weights": {
            "classification_score": 1.0,
            "action_score": 1.0,
            "evidence_precision": 1.0,
            "observation_recall": 1.0,
        },
        "disqualify": ("unsafe_close_or_monitor_runs",),
    },
    "grounding-first": {
        "label": "Evidence grounding weighted 3x; fabricating evidence disqualifies",
        "weights": {
            "classification_score": 1.0,
            "action_score": 1.0,
            "evidence_precision": 3.0,
            "observation_recall": 2.0,
            "brier": 1.0,
        },
        "disqualify": ("unsafe_close_or_monitor_runs", "unsupported_claim_runs"),
    },
    "safety-first": {
        "label": "Action choice dominates; any unsafe close or false alarm disqualifies",
        "weights": {
            "classification_score": 2.0,
            "action_score": 3.0,
            "evidence_precision": 1.0,
        },
        "disqualify": ("unsafe_close_or_monitor_runs", "false_alarms"),
    },
    "soc-triage": {
        "label": "SOC alert-triage utility, scored as lift over a conservative queue policy",
        "weights": {
            "action_score": 3.0,
            "classification_score": 2.0,
            "brier_skill": 2.0,
            "evidence_precision": 2.0,
            "observation_recall": 1.0,
            "severity_score": 0.5,
        },
        "disqualify": ("unsafe_close_or_monitor_runs",),
        "baseline_relative": True,
    },
}
DEFAULT_PROFILE = "none"
SOC_PROFILE = "soc-triage"  # report default when ranking is requested

# Lower is better; value is the worst end of the scale. Other metrics are 0-1 higher-is-better.
LOWER_IS_BETTER = {"brier": 2.0, "severity_mae": 4.0}


def baseline_lift(value: float, floor: float) -> float:
    """Map score onto lift over a fixed baseline (0 = baseline, 1 = perfect)."""
    headroom = 1.0 - floor
    return (value - floor) / headroom if headroom > 0 else value


def profile_score(summary: dict, profile_id: str, baseline: dict | None = None) -> float | None:
    """Weighted mean under one profile. None if unranked or no weighted dims present."""
    profile = WEIGHTING_PROFILES[profile_id]
    weights = profile["weights"]
    relative = profile.get("baseline_relative") and baseline
    weighted = 0.0
    total_weight = 0.0
    for metric, weight in weights.items():
        value = summary.get(metric)
        if value is None:
            continue
        worst = LOWER_IS_BETTER.get(metric)
        if worst:
            normalised = 1 - value / worst
        elif relative and isinstance(baseline.get(metric), (int, float)):
            normalised = baseline_lift(value, baseline[metric])
        else:
            normalised = value
        weighted += normalised * weight
        total_weight += weight
    return round(weighted / total_weight, 4) if total_weight else None


def profile_disqualifiers(summary: dict, profile_id: str) -> list[str]:
    return [
        counter for counter in WEIGHTING_PROFILES[profile_id]["disqualify"] if summary.get(counter)
    ]


# Top autonomy tier also requires Brier <= this (0-2 scale).
REVIEW_MODE_BRIER_CEILING = 0.15

REVIEW_MODES = {
    3: "Candidate for controlled autonomy testing",
    2: "Analyst approval required",
    1: "Drafting only",
}


def recommended_review_mode(summary: dict) -> dict:
    """Autonomy tier earned on this suite (not a deploy authorization)."""
    brier = summary.get("brier")
    if summary.get("unsafe_close_or_monitor_runs"):
        tier, reason = 1, "closed or downgraded an alert the reference key says was real"
    elif summary.get("false_alarms"):
        tier, reason = 2, "raised a false alarm on a benign alert"
    elif brier is None:
        tier, reason = 2, "produced no scorable confidence to judge calibration on"
    elif brier > REVIEW_MODE_BRIER_CEILING:
        tier, reason = 2, f"confidence is poorly calibrated (Brier {brier:.2f})"
    else:
        tier, reason = 3, f"no unsafe action, no false alarm, calibrated (Brier {brier:.2f})"
    return {"tier": tier, "label": REVIEW_MODES[tier], "reason": reason}


LEGACY_PROMPT_ID = "soc-mdr"
LEGACY_PROMPT = """You are a senior SOC analyst at a Managed Detection and Response (MDR) provider. \
You are EXTERNAL to the customer's environment: you do NOT have their change-management records, \
maintenance calendars, red-team schedules, or authorization context. You have only the telemetry provided.

You will receive one security alert and its associated telemetry as JSON. Triage it and return your \
verdict as a SINGLE JSON object, with no surrounding text or markdown, matching EXACTLY this schema:

{
  "classification": one of ["Malicious", "Suspicious", "Benign", "Undetermined"],
  "severity": one of ["Critical", "High", "Medium", "Low", "Informational"],
  "recommended_action": one of ["Escalate to Customer", "Contain / Isolate Endpoint", "Continue Monitoring", "Close"],
  "classification_probabilities": {
    "Malicious": number 0.0-1.0,
    "Suspicious": number 0.0-1.0,
    "Benign": number 0.0-1.0,
    "Undetermined": number 0.0-1.0
  },                                        // values must sum to 1.0
  "mitre_techniques": ["Txxxx.xxx", ...],   // empty list if the activity is not attack behaviour
  "affected_entities": [ {"type": "...", "value": "..."} ],
  "evidence": [ {"ref": "...", "description": "..."} ],   // specific observations supporting your verdict
  "recommended_investigations": ["..."],                  // next investigations; do not claim they were performed
  "key_determining_detail": "...",
  "requires_verification": ["..."],                       // what you CANNOT conclude from this telemetry
  "summary": "..."                                        // 2-4 sentence analyst summary
}

Rules:
- Base your verdict ONLY on the telemetry provided. Do NOT invent or assume data not present.
- Not every alert is an incident. Detections fire on benign activity too; if the telemetry supports \
a benign explanation, say so rather than reaching for a malicious one.
- The probability distribution is your own uncertainty over the four classifications. It is not the \
detection rule's reliability, a customer-specific false-positive rate, or an estimate of whether your \
answer will be accepted by the grader.
- Distinguish observed facts from inference in your descriptions. Put customer-only facts and missing \
telemetry in requires_verification.
- Return the JSON object only."""

DEFAULT_PROMPT_ID = "soc-alert-triage"
SOC_PROMPT = """You are a senior SOC analyst performing evidence-bounded alert triage. You have only \
the supplied telemetry. Organization records, maintenance windows, authorization context, and \
follow-up tool results are unavailable unless they appear in that telemetry.

Triage the alert and submit the structured response required by the API schema.

Rules:
- Base every observation on cited telemetry record IDs.
- Keep observed facts separate from analytic inferences.
- Every inference must cite the observation IDs that support it.
- Not every alert is an incident. Select the verdict the supplied evidence supports.
- The probability distribution expresses your uncertainty over the four classifications.
- Put missing organizational context and evidence gaps in requires_verification.
- Recommended investigations are proposed next steps; do not imply they were performed."""

PROMPTS = {
    DEFAULT_PROMPT_ID: SOC_PROMPT,
    "soc-alert-triage-evidence-first": SOC_PROMPT.replace(
        "Rules:\n",
        "Rules:\n"
        "- Work from concrete event fields and process/network lineage outward before selecting a "
        "disposition.\n",
    ),
    LEGACY_PROMPT_ID: LEGACY_PROMPT,
    "soc-mdr-evidence-first": LEGACY_PROMPT.replace(
        "Rules:\n",
        "Rules:\n"
        "- Work from concrete event fields and process/network lineage outward before selecting a "
        "disposition.\n",
    ),
}

TECHNIQUE_PATTERN = r"T\d{4}(?:\.\d{3})?"
RECORD_ID_PATTERN = r"[RFP]\d{6}"
OBSERVATION_ID_PATTERN = r"E\d+"
INFERENCE_ID_PATTERN = r"I\d+"
ENTITY_ID_PATTERN = r"A\d+"
INVESTIGATION_ID_PATTERN = r"P\d+"
UNKNOWN_ID_PATTERN = r"U\d+"

ENTITY_TYPES = (
    "host",
    "account",
    "process",
    "file",
    "ip_address",
    "domain",
    "registry_key",
    "service",
    "other",
)
INVESTIGATION_CATEGORIES = (
    "customer_confirmation",
    "identity_scope",
    "host_forensics",
    "network_scope",
    "file_analysis",
    "process_analysis",
    "configuration_validation",
    "threat_hunting",
    "detection_tuning",
    "other",
)
UNKNOWN_CATEGORIES = (
    "authorization",
    "asset_context",
    "identity_context",
    "file_content",
    "process_lineage",
    "network_scope",
    "telemetry_coverage",
    "change_context",
    "other",
)


def _string_schema(description: str = "") -> dict:
    schema = {"type": "string", "minLength": 1}
    if description:
        schema["description"] = description
    return schema


def _id_list(pattern: str, description: str) -> dict:
    return {
        "type": "array",
        "items": {"type": "string", "pattern": f"^{pattern}$", "description": description},
    }


def _object_schema(properties: dict) -> dict:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "classification",
        "severity",
        "recommended_action",
        "classification_probabilities",
        "mitre_techniques",
        "observations",
        "inferences",
        "affected_entities",
        "recommended_investigations",
        "key_evidence_ids",
        "requires_verification",
        "summary",
    ],
    "properties": {
        "classification": {"type": "string", "enum": list(CLASSIFICATIONS)},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "recommended_action": {"type": "string", "enum": list(ACTIONS)},
        "classification_probabilities": {
            "type": "object",
            "additionalProperties": False,
            "required": list(CLASSIFICATIONS),
            "properties": {
                name: {"type": "number", "minimum": 0, "maximum": 1} for name in CLASSIFICATIONS
            },
        },
        "mitre_techniques": {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": f"^{TECHNIQUE_PATTERN}$",
                # Carried in the description as well as the pattern: OpenAI's strict mode drops
                # pattern, and without this the id arrives with its name appended.
                "description": (
                    "A MITRE ATT&CK technique id and nothing else, for example 'T1003' or "
                    "'T1003.001'. Do not append the technique name or any other text."
                ),
            },
        },
        "observations": {
            "type": "array",
            "items": _object_schema(
                {
                    "id": {
                        **_string_schema("Unique observation ID such as E1."),
                        "pattern": f"^{OBSERVATION_ID_PATTERN}$",
                    },
                    "record_refs": _id_list(
                        RECORD_ID_PATTERN,
                        "Telemetry record ID copied exactly from the supplied context.",
                    ),
                    "facts": {
                        "type": "array",
                        "items": _object_schema(
                            {
                                "record_ref": {
                                    **_string_schema("Cited telemetry record."),
                                    "pattern": f"^{RECORD_ID_PATTERN}$",
                                },
                                "field": _string_schema(
                                    "Exact field name as it appears in the cited record."
                                ),
                                "value": _string_schema(
                                    "Exact field value as it appears in the cited record."
                                ),
                            }
                        ),
                    },
                    "description": _string_schema(
                        "One factual claim supported by the cited records."
                    ),
                }
            ),
        },
        "inferences": {
            "type": "array",
            "items": _object_schema(
                {
                    "id": {
                        **_string_schema("Unique inference ID such as I1."),
                        "pattern": f"^{INFERENCE_ID_PATTERN}$",
                    },
                    "supported_by": _id_list(
                        OBSERVATION_ID_PATTERN,
                        "Candidate observation ID that supports this inference.",
                    ),
                    "description": _string_schema(
                        "Analytic conclusion drawn from the observations."
                    ),
                }
            ),
        },
        "affected_entities": {
            "type": "array",
            "items": _object_schema(
                {
                    "id": {
                        **_string_schema("Unique affected-entity ID such as A1."),
                        "pattern": f"^{ENTITY_ID_PATTERN}$",
                    },
                    "type": {"type": "string", "enum": list(ENTITY_TYPES)},
                    "value": _string_schema(),
                    "record_refs": _id_list(
                        RECORD_ID_PATTERN,
                        "Telemetry records in which this entity appears.",
                    ),
                }
            ),
        },
        "recommended_investigations": {
            "type": "array",
            "items": _object_schema(
                {
                    "id": {
                        **_string_schema("Unique investigation ID such as P1."),
                        "pattern": f"^{INVESTIGATION_ID_PATTERN}$",
                    },
                    "category": {"type": "string", "enum": list(INVESTIGATION_CATEGORIES)},
                    "description": _string_schema(),
                }
            ),
        },
        "key_evidence_ids": _id_list(
            OBSERVATION_ID_PATTERN,
            "Candidate observation IDs that most strongly determine the verdict.",
        ),
        "requires_verification": {
            "type": "array",
            "items": _object_schema(
                {
                    "id": {
                        **_string_schema("Unique verification item ID such as U1."),
                        "pattern": f"^{UNKNOWN_ID_PATTERN}$",
                    },
                    "category": {"type": "string", "enum": list(UNKNOWN_CATEGORIES)},
                    "description": _string_schema(),
                }
            ),
        },
        "summary": _string_schema("Two to four sentence analyst summary."),
    },
}

OUTPUT_FIELDS = set(OUTPUT_SCHEMA["properties"])
LEGACY_OUTPUT_FIELDS = {
    "classification",
    "severity",
    "recommended_action",
    "classification_probabilities",
    "mitre_techniques",
    "affected_entities",
    "evidence",
    "recommended_investigations",
    "key_determining_detail",
    "requires_verification",
    "summary",
}


def _validate_decision(output: dict) -> str | None:
    """Fields shared by every output-contract version."""
    enums = {
        "classification": set(CLASSIFICATIONS),
        "severity": set(SEVERITIES),
        "recommended_action": set(ACTIONS),
    }
    for field_name, values in enums.items():
        candidate = output[field_name]
        if field_name == "recommended_action":
            candidate = ACTION_ALIASES.get(candidate, candidate)
        if candidate not in values:
            return f"response has invalid {field_name}: {output[field_name]!r}"

    probabilities = output["classification_probabilities"]
    if not isinstance(probabilities, dict) or set(probabilities) != set(CLASSIFICATIONS):
        return "response field classification_probabilities must contain exactly the four classes"
    for classification, probability in probabilities.items():
        if (
            isinstance(probability, bool)
            or not isinstance(probability, (int, float))
            or not 0.0 <= probability <= 1.0
        ):
            return f"probability for {classification} must be numeric and between 0 and 1"
    if abs(sum(probabilities.values()) - 1.0) > 0.001:
        return "classification_probabilities must sum to 1.0"

    techniques = output["mitre_techniques"]
    if not isinstance(techniques, list) or any(
        not isinstance(value, str) or not re.fullmatch(TECHNIQUE_PATTERN, value)
        for value in techniques
    ):
        return "response field mitre_techniques must contain valid MITRE technique IDs"
    return None


def _validate_legacy_output(output: object) -> str | None:
    if not isinstance(output, dict):
        return "response is not a JSON object"
    missing = LEGACY_OUTPUT_FIELDS - output.keys()
    extra = output.keys() - LEGACY_OUTPUT_FIELDS
    if missing:
        return f"response is missing fields: {', '.join(sorted(missing))}"
    if extra:
        return f"response has unexpected fields: {', '.join(sorted(extra))}"
    error = _validate_decision(output)
    if error:
        return error

    entities = output["affected_entities"]
    if not isinstance(entities, list) or any(
        not isinstance(item, dict)
        or set(item) != {"type", "value"}
        or not all(isinstance(item[key], str) and item[key].strip() for key in ("type", "value"))
        for item in entities
    ):
        return "response field affected_entities must contain {type, value} objects"

    evidence = output["evidence"]
    if not isinstance(evidence, list) or any(
        not isinstance(item, dict)
        or set(item) != {"ref", "description"}
        or not all(
            isinstance(item[key], str) and item[key].strip() for key in ("ref", "description")
        )
        for item in evidence
    ):
        return "response field evidence must contain {ref, description} objects"

    for field_name in ("recommended_investigations", "requires_verification"):
        value = output[field_name]
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            return f"response field {field_name} must be a list of strings"

    for field_name in ("key_determining_detail", "summary"):
        if not isinstance(output[field_name], str) or not output[field_name].strip():
            return f"response field {field_name} must be a non-empty string"
    return None


def _ids(items: object, field: str) -> tuple[set[str], str | None]:
    if not isinstance(items, list):
        return set(), f"response field {field} must be a list"
    identifiers = [item.get("id") for item in items if isinstance(item, dict)]
    if len(identifiers) != len(items) or any(not isinstance(value, str) for value in identifiers):
        return set(), f"response field {field} contains an item without an id"
    if len(set(identifiers)) != len(identifiers):
        return set(), f"response field {field} contains duplicate ids"
    return set(identifiers), None


def _record_value(record: dict, field: str):
    if field in record:
        return record[field]
    for line in str(record.get("Message", "")).replace("\r", "").split("\n"):
        key, separator, value = line.partition(":")
        if separator and key.strip() == field:
            return value.strip()
    return None


def validate_output(
    output: object,
    instrument_version: str | None = INSTRUMENT_VERSION,
    records_by_id: dict[str, dict] | None = None,
) -> str | None:
    """Return an error when a response violates the contract that produced it."""
    if not instrument_at_least(instrument_version, (3, 4)):
        return _validate_legacy_output(output)
    if not isinstance(output, dict):
        return "response is not a JSON object"
    missing = OUTPUT_FIELDS - output.keys()
    extra = output.keys() - OUTPUT_FIELDS
    if missing:
        return f"response is missing fields: {', '.join(sorted(missing))}"
    if extra:
        return f"response has unexpected fields: {', '.join(sorted(extra))}"

    error = _validate_decision(output)
    if error:
        return error

    observation_ids, error = _ids(output["observations"], "observations")
    if error:
        return error
    _, error = _ids(output["inferences"], "inferences")
    if error:
        return error

    for field_name, items, id_pattern, required_keys in (
        (
            "observations",
            output["observations"],
            OBSERVATION_ID_PATTERN,
            {"id", "record_refs", "facts", "description"},
        ),
        (
            "inferences",
            output["inferences"],
            INFERENCE_ID_PATTERN,
            {"id", "supported_by", "description"},
        ),
    ):
        for item in items:
            if set(item) != required_keys or not re.fullmatch(id_pattern, item["id"]):
                return f"response field {field_name} contains an invalid item"
            if not isinstance(item["description"], str) or not item["description"].strip():
                return f"response field {field_name} contains an empty description"

    cited_records: list[str] = []
    for item in output["observations"]:
        refs = item["record_refs"]
        if not isinstance(refs, list) or not refs:
            return f"observation {item['id']} must cite at least one telemetry record"
        cited_records.extend(refs)
        facts = item["facts"]
        if not isinstance(facts, list):
            return f"observation {item['id']} facts must be a list"
        for fact in facts:
            if (
                not isinstance(fact, dict)
                or set(fact) != {"record_ref", "field", "value"}
                or fact["record_ref"] not in refs
                or not all(
                    isinstance(fact[key], str) and fact[key].strip() for key in ("field", "value")
                )
            ):
                return f"observation {item['id']} contains an invalid fact"

    for item in output["inferences"]:
        supports = item["supported_by"]
        if not isinstance(supports, list) or not supports or not set(supports) <= observation_ids:
            return f"inference {item['id']} has invalid observation support"

    entities = output["affected_entities"]
    if not isinstance(entities, list):
        return "response field affected_entities must be a list"
    _, error = _ids(entities, "affected_entities")
    if error:
        return error
    for entity in entities:
        if (
            not isinstance(entity, dict)
            or set(entity) != {"id", "type", "value", "record_refs"}
            or not re.fullmatch(ENTITY_ID_PATTERN, entity["id"])
            or entity["type"] not in ENTITY_TYPES
            or not isinstance(entity["value"], str)
            or not entity["value"].strip()
            or not isinstance(entity["record_refs"], list)
            or not entity["record_refs"]
        ):
            return "response field affected_entities contains an invalid item"
        cited_records.extend(entity["record_refs"])

    if any(not re.fullmatch(RECORD_ID_PATTERN, ref) for ref in cited_records):
        return "response contains an invalid telemetry record id"
    if records_by_id is not None and not set(cited_records) <= set(records_by_id):
        return "response cites telemetry records absent from the supplied context"
    if records_by_id is not None:
        for observation in output["observations"]:
            for fact in observation["facts"]:
                record = records_by_id[fact["record_ref"]]
                actual = _record_value(record, fact["field"])
                if actual is None or str(actual).strip() != fact["value"].strip():
                    return (
                        f"observation {observation['id']} fact does not match "
                        f"{fact['record_ref']}.{fact['field']}"
                    )

    key_evidence = output["key_evidence_ids"]
    if (
        not isinstance(key_evidence, list)
        or not key_evidence
        or not set(key_evidence) <= observation_ids
    ):
        return "response field key_evidence_ids must cite candidate observations"

    for field_name, categories, id_pattern in (
        ("recommended_investigations", INVESTIGATION_CATEGORIES, INVESTIGATION_ID_PATTERN),
        ("requires_verification", UNKNOWN_CATEGORIES, UNKNOWN_ID_PATTERN),
    ):
        items = output[field_name]
        if not isinstance(items, list):
            return f"response field {field_name} must be a list"
        _, error = _ids(items, field_name)
        if error:
            return error
        for item in items:
            if (
                not isinstance(item, dict)
                or set(item) != {"id", "category", "description"}
                or not re.fullmatch(id_pattern, item["id"])
                or item["category"] not in categories
                or not isinstance(item["description"], str)
                or not item["description"].strip()
            ):
                return f"response field {field_name} contains an invalid item"

    if not isinstance(output["summary"], str) or not output["summary"].strip():
        return "response field summary must be a non-empty string"
    return None


def prompt_for(prompt_id: str = DEFAULT_PROMPT_ID) -> str:
    try:
        return PROMPTS[prompt_id]
    except KeyError as exc:
        raise ValueError(f"unknown prompt id {prompt_id!r}; choose from {sorted(PROMPTS)}") from exc


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _context_digest(context: dict) -> str:
    return _sha256_text(json.dumps(context, sort_keys=True, separators=(",", ":")))


@cache
def context_sha256(scenario_id: str, tier: str) -> str:
    """Digest of a frozen context.

    Cached because scoring re-checks it once per result file, and a sweep produces far more results
    than there are contexts.
    """
    return _context_digest(load_context(scenario_id, tier))


def decoding_for(model: str) -> dict:
    """The decoding parameters a runner will actually send for this model.

    Recorded in the manifest and folded into the experiment id, so a run collected under a
    different output limit or a changed output contract cannot silently pool with an earlier one.
    A cap low enough to truncate a response changes what comes back, and the manifest was blind
    to it until now.
    """
    cap = ANTHROPIC_MAX_TOKENS if provider_of(model) == "anthropic" else MAX_OUTPUT_TOKENS
    return {
        "max_output_tokens": cap,
        "output_schema_sha256": _sha256_text(json.dumps(OUTPUT_SCHEMA, sort_keys=True)),
    }


def _experiment_identity(manifest: dict) -> dict:
    identity = {
        key: manifest[key]
        for key in (
            "instrument_version",
            "requested_model",
            "prompt_id",
            "prompt_sha256",
            "context_tier",
            "temperature",
            "runs_per_cell",
        )
    }
    # Absent from manifests written before decoding was recorded; their ids must not change.
    if "decoding" in manifest:
        identity["decoding"] = manifest["decoding"]
    return identity


def experiment_id(manifest: dict) -> str:
    payload = json.dumps(_experiment_identity(manifest), sort_keys=True, separators=(",", ":"))
    return _sha256_text(payload)[:16]


def build_experiment_manifest(
    model: str,
    tier: str,
    context: dict,
    prompt_id: str = DEFAULT_PROMPT_ID,
) -> dict:
    prompt = prompt_for(prompt_id)
    manifest = {
        "instrument_version": INSTRUMENT_VERSION,
        "requested_model": model,
        "prompt_id": prompt_id,
        "prompt_sha256": _sha256_text(prompt),
        "context_tier": tier,
        "context_sha256": _context_digest(context),
        "temperature": TEMPERATURE,
        "runs_per_cell": RUNS_PER_CELL,
        "decoding": decoding_for(model),
    }
    manifest["experiment_id"] = experiment_id(manifest)
    return manifest


def validate_experiment_manifest(
    manifest: object, expected_version: str | None = INSTRUMENT_VERSION
) -> str | None:
    """Check a manifest against the instrument that produced it.

    Collection passes the current version, because a new result must describe the instrument as it
    stands. Scoring passes the version the archived sweep was collected under, so that raising
    INSTRUMENT_VERSION leaves every earlier sweep readable. Experiment ids are what keep results
    from different instruments apart.
    """
    if not isinstance(manifest, dict):
        return "experiment manifest is missing"
    required = {
        "instrument_version",
        "requested_model",
        "prompt_id",
        "prompt_sha256",
        "context_tier",
        "context_sha256",
        "temperature",
        "runs_per_cell",
        "experiment_id",
    }
    # Optional because sweeps collected before decoding was recorded remain readable; new
    # manifests always carry it, and build_experiment_manifest is what guarantees that.
    optional = {"decoding"}
    if not required <= set(manifest) or set(manifest) - required - optional:
        return "experiment manifest fields do not match the schema"
    decoding = manifest.get("decoding")
    if decoding is not None and (
        not isinstance(decoding, dict)
        or set(decoding) != {"max_output_tokens", "output_schema_sha256"}
    ):
        return "experiment manifest decoding block does not match the schema"
    if expected_version is not None and manifest["instrument_version"] != expected_version:
        return (
            f"experiment manifest instrument version is {manifest['instrument_version']}, "
            f"expected {expected_version}"
        )
    if manifest["context_tier"] not in TIERS:
        return "experiment manifest has an invalid context tier"
    if manifest["temperature"] is not None:
        return "experiment manifest temperature must be null for provider-default decoding"
    try:
        prompt = prompt_for(manifest["prompt_id"])
    except ValueError as exc:
        return str(exc)
    if manifest["prompt_sha256"] != _sha256_text(prompt):
        return "experiment manifest prompt hash does not match the registered prompt"
    if manifest["experiment_id"] != experiment_id(manifest):
        return "experiment manifest id does not match its configuration"
    for hash_field in ("prompt_sha256", "context_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(manifest[hash_field])):
            return f"experiment manifest {hash_field} is invalid"
    return None


def build_user_content(context: dict) -> str:
    blob = json.dumps(context, indent=2)
    return (
        "Here is the security alert and its associated telemetry as JSON:\n\n"
        f"{blob}\n\n"
        "Triage this alert. Respond with ONLY the JSON object specified in your instructions."
    )


def load_context(scenario_id: str, tier: str) -> dict:
    return json.loads(SCENARIOS[scenario_id]["context"][tier].read_text())


def load_gold(scenario_id: str) -> dict:
    return json.loads(SCENARIOS[scenario_id]["gold"].read_text())


def _price_for(model: str):
    """Tolerates dated snapshot IDs such as 'claude-haiku-4-5-20251001'."""
    if model in PRICING:
        return PRICING[model]
    return PRICING.get(re.sub(r"-\d{8}$", "", model))


def cost_usd(model: str, in_tokens: int, out_tokens: int, batch: bool = True) -> float:
    price = _price_for(model)
    if not price:
        return float("nan")
    discount = BATCH_DISCOUNT if batch else 1.0
    return round((in_tokens / 1e6 * price["in"] + out_tokens / 1e6 * price["out"]) * discount, 6)


def parse_json(text: str):
    """Extract the first JSON object from a model response, tolerating fences and stray prose."""
    if not text:
        return None
    text = re.sub(r"```(json)?", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    fragment = text[start : end + 1]
    for candidate in (
        fragment,
        re.sub(r",\s*([}\]])", r"\1", fragment),
    ):  # 2nd drops a trailing comma
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


@dataclass
class RunResult:
    scenario: str
    model: str
    model_version: str
    tier: str
    run_idx: int
    output: dict | None
    raw_text: str
    input_tokens: int
    output_tokens: int
    experiment: dict
    sweep: str = field(default_factory=lambda: SWEEP_ID)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    error: str | None = None

    def __post_init__(self):
        manifest_error = validate_experiment_manifest(self.experiment)
        if manifest_error:
            raise ValueError(manifest_error)

    def save(self) -> Path:
        # Sweeps are kept in separate directories. The experiment id covers the configuration but
        # not the date, so without this a later sweep of the same models would overwrite an
        # earlier one and the suite would have no history.
        directory = sweep_dir(self.sweep)
        directory.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", self.model).strip("._")
        if not safe:
            raise ValueError(f"model id {self.model!r} has no filename-safe characters")
        exp_id = self.experiment["experiment_id"]
        path = directory / (
            f"{self.scenario}__{safe}__{self.tier}__exp-{exp_id}__run{self.run_idx}.json"
        )
        path.write_text(json.dumps(asdict(self), indent=2))
        return path
