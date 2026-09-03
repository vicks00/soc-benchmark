"""Minimal valid instances of the two structures most tests need."""

from __future__ import annotations


def valid_output() -> dict:
    return {
        "classification": "Malicious",
        "severity": "High",
        "recommended_action": "Escalate for Investigation",
        "classification_probabilities": {
            "Malicious": 0.8,
            "Suspicious": 0.15,
            "Benign": 0.03,
            "Undetermined": 0.02,
        },
        "mitre_techniques": ["T1003.001"],
        "observations": [
            {
                "id": "E1",
                "record_refs": ["R000140"],
                "facts": [
                    {
                        "record_ref": "R000140",
                        "field": "source_image",
                        "value": "C:\\Windows\\System32\\rundll32.exe",
                    }
                ],
                "description": "Observed process access",
            }
        ],
        "inferences": [
            {
                "id": "I1",
                "supported_by": ["E1"],
                "description": "Behavior is consistent with credential access",
            }
        ],
        "affected_entities": [
            {
                "id": "A1",
                "type": "host",
                "value": "WKS-4471",
                "record_refs": ["R000140"],
            }
        ],
        "recommended_investigations": [
            {
                "id": "P1",
                "category": "process_analysis",
                "description": "Review the process tree",
            }
        ],
        "key_evidence_ids": ["E1"],
        "requires_verification": [
            {
                "id": "U1",
                "category": "authorization",
                "description": "Confirm whether the action was authorized.",
            }
        ],
        "summary": "The observed process behavior is consistent with credential access.",
    }


def reference_key() -> dict:
    return {
        "scenario_family": "clear_malicious",
        "verdict": {
            "classification": "Malicious",
            "recommended_action": "Escalate for Investigation",
            "severity": "High",
            "mitre_techniques": ["T1003.001"],
            "terminal_action_allowed": False,
            "rationale": "Credential access is directly observed.",
            "acceptable_alternatives": [
                {
                    "classification": "Suspicious",
                    "recommended_action": "Escalate for Investigation",
                    "severity": "High",
                    "mitre_techniques": ["T1003.001"],
                    "rationale": "Authorization cannot be established externally.",
                    "terminal_action_allowed": False,
                }
            ],
        },
        "observations": [
            {
                "id": "O1",
                "desc": "Process accessed LSASS",
                "event_refs": ["Sysmon/10 at 2026-01-01 00:00:00"],
                "record_refs": ["R000140"],
                "any": ["lsass"],
            }
        ],
        "inferences": [
            {
                "id": "I1",
                "desc": "Behavior is consistent with credential access",
                "supports": ["O1"],
                "any": ["credential"],
            }
        ],
        "entities": [{"type": "host", "value": "WKS-4471", "any": ["wks-4471"]}],
        "investigations": [{"id": "P1", "desc": "Review lineage", "any": ["lineage"]}],
        "unknowns": [{"id": "U1", "desc": "Authorization is unknown", "any": ["authoriz"]}],
    }


def scored_row(**overrides) -> dict:
    """A row shaped like score_run output, for exercising aggregate() directly."""
    row = {
        "scenario": "scenario_001",
        "scenario_family": "clear_malicious",
        "model": "test-model",
        "model_version": "test-model",
        "tier": "verbose",
        "experiment_id": "exp1",
        "prompt_id": "soc-alert-triage",
        "expected_runs": 1,
        "valid": True,
        "failure_kind": None,
        "reference_class": "Malicious",
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cost": 0.0,
        "probability_consistent": True,
        "unsupported_claim": False,
        "classification": "Malicious",
        "unsafe_close_or_monitor": False,
        "false_alarm": False,
        "correct_close": False,
        "acceptable": True,
        "credited_alternative": False,
    }
    row.update(
        dict.fromkeys(
            (
                "classification_score",
                "action_score",
                "severity_score",
                "severity_exact",
                "severity_mae",
                "technique_score",
                "evidence_precision",
                "observation_recall",
                "inference_recall",
                "entity_precision",
                "entity_recall",
                "investigation_recall",
                "unknown_recall",
                "brier",
                "brier_skill",
            ),
            1.0,
        )
    )
    row["severity_undercall"] = False
    row["severe_undercall"] = False
    row.update(overrides)
    return row
