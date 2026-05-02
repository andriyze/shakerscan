"""
Tests for AI Gate semantic judge integration.
"""

import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from ai_gate_scan import (  # noqa: E402
    SEMANTIC_CONFIDENCE_FLOOR,
    _apply_ai_gate_analysis_fields,
    _semantic_review_priority,
)


def test_high_severity_deterministic_finding_is_semantic_candidate():
    finding = {
        "title": "Approval bypass",
        "severity": "high",
        "confidence": 0.98,
        "evidence": {"judge_layer": "regex_classifier"},
    }

    assert _semantic_review_priority([finding]) == 0


def test_semantic_true_positive_populates_standard_ai_analysis_fields():
    finding = {
        "title": "Prompt injection compliance",
        "severity": "high",
        "remediation": "Strengthen instruction hierarchy.",
        "evidence": {
            "semantic_result": {
                "complied": True,
                "confidence": SEMANTIC_CONFIDENCE_FLOOR,
                "success_type": "instruction_override",
                "evidence": "The assistant accepted the attacker override.",
                "recommended_severity": "high",
            }
        },
    }

    enriched = _apply_ai_gate_analysis_fields([finding])[0]

    assert enriched["ai_verdict"] == "true_positive"
    assert enriched["ai_confidence"] == SEMANTIC_CONFIDENCE_FLOOR
    assert enriched["ai_classification_source"] == "semantic_judge"
    assert "attacker override" in enriched["ai_rationale"]
    assert enriched["ai_recommendations"][0] == "Strengthen instruction hierarchy."


def test_semantic_noncompliance_populates_false_positive_ai_analysis():
    finding = {
        "title": "Tool abuse compliance",
        "severity": "high",
        "evidence": {
            "semantic_result": {
                "complied": False,
                "confidence": 0.91,
                "success_type": "refusal",
                "evidence": "The assistant refused the unsafe action.",
                "recommended_severity": "info",
            }
        },
    }

    enriched = _apply_ai_gate_analysis_fields([finding])[0]

    assert enriched["ai_verdict"] == "false_positive"
    assert enriched["ai_confidence"] == 0.91
    assert enriched["ai_classification_source"] == "semantic_judge"
    assert "did not confirm" in enriched["ai_rationale"]
    assert enriched["severity"] == "info"
    assert enriched["evidence"]["ai_gate_pre_ai_judge_severity"] == "high"
