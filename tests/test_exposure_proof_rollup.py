"""Exposure must count the same proof states as the finding list and detail."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))

from exposure.proof_rollup import active_finding_proof_counts  # noqa: E402


def test_scan_proof_survives_inconclusive_retest_in_exposure_count():
    proof = {
        "schema_version": "proof-contract/v2",
        "contract_id": "scan.exposure.verify_batch.sensitive_exposure_proof",
        "contract_version": "1.0.0",
        "reexecution": {"required": False, "performed": True, "verifier_build": "exposure.verify_batch"},
        "predicate": {"satisfied": True, "missing": []},
        "verdict": "verified", "promotable": True,
    }
    rows = [
        {"target_id": "target-1", "status": "active", "severity": "high",
         "evidence": json.dumps({"proof_contract_v2": proof}),
         "last_verification_verdict": "inconclusive", "latest_retest_mode": "deterministic"},
        {"target_id": "target-1", "status": "active", "severity": "high",
         "evidence": "{}", "last_verification_verdict": "inconclusive",
         "latest_retest_mode": "deterministic"},
        {"target_id": "target-1", "status": "active", "severity": "high",
         "evidence": "{}", "last_verification_verdict": "exploited",
         "latest_retest_mode": "ai_driven"},
        {"target_id": "target-1", "status": "resolved", "severity": "high",
         "evidence": json.dumps({"proof_contract_v2": proof})},
    ]
    assert active_finding_proof_counts(rows)[("target", "target-1")] == {
        "verified": 1, "needs_verification": 2, "investigator_verified": 0,
    }
