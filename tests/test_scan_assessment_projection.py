"""Exercise finalizer -> merge -> serialized list -> browser presentation."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from api.scan.assessment import finalize_parallel_assessment, project_scan_assessment_row
from tests.test_scan1_review_regressions import redirect_report


def test_redirect_only_result_with_header_findings_is_ungraded_before_hashing():
    report = redirect_report(missing=("permissions-policy",))
    assert report["findings"] and report["http"]["posture_observed"]
    assert report["reachability"]["status"] == "reachable"
    assert "error" not in report
    assert all(report["result"][key] is None for key in ("score", "grade", "risk_score", "risk_grade"))
    material = dict(report)
    digest = material.pop("report_digest")
    assert hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest() == digest


def test_completed_empty_child_cannot_restore_unexamined_parent_grade():
    child = redirect_report()
    merged = copy.deepcopy(child)
    # The legacy union scorer may recompute these even with no application evidence.
    merged["result"].update(score=100, grade="A*", risk_score=100, risk_grade="A")
    empty = {"schema_version": child["schema_version"], "target": child["target"],
             "reachability": {"status": "not_examined"},
             "result": {"risk_assessment_state": "unknown", "application_observed": None}}
    assert finalize_parallel_assessment(merged, [child, empty]) is False
    persisted = json.loads(json.dumps(merged))
    assert persisted["result"]["grade"] is None
    row = project_scan_assessment_row({"score": 100, "grade": "A*", "run_kind": "web_dast",
        "risk_assessment_state": persisted["result"]["risk_assessment_state"],
        "application_observed": json.dumps(persisted["result"]["application_observed"])})
    assert row["score"] is None and row["grade"] is None
    assert row["application_observed"] is False


def test_real_same_target_child_observation_is_not_erased_by_redirect_backbone():
    redirect = redirect_report()
    observed = redirect_report(followup="https://app.example.test/health")
    merged = copy.deepcopy(redirect)
    merged["result"].update(score=90, grade="A*", risk_score=90, risk_grade="A")
    assert finalize_parallel_assessment(merged, [redirect, observed]) is False
    assert merged["result"]["application_observed"] is True
    assert merged["result"]["score"] == 90
    assert merged["result"]["grade_reliable"] is False  # no invented full-coverage claim


def test_unrelated_origin_cannot_rescue_application_observation():
    redirect = redirect_report()
    unrelated = redirect_report(followup="https://app.example.test/health")
    unrelated["target"] = "https://other.example.test"
    merged = copy.deepcopy(redirect)
    assert finalize_parallel_assessment(merged, [redirect, unrelated]) is False
    assert merged["result"]["application_observed"] is False
    assert merged["result"]["score"] is None


def test_list_projection_does_not_mutate_or_rescore_historical_evidence():
    row = {"grade": "A*", "score": 100, "risk_assessment_state": "not_examined",
           "result": {"result": {"grade": "A*", "score": 100}}}
    result = project_scan_assessment_row(row)
    assert row["grade"] == "A*" and result["grade"] is None
    assert result["result"] == row["result"]
    legacy = {"grade": "B", "score": 85}
    assert project_scan_assessment_row(legacy) == legacy
    device = {"grade": "A", "score": 100, "run_kind": "device_posture",
              "risk_assessment_state": "not_examined"}
    assert project_scan_assessment_row(device)["score"] == 100


@pytest.mark.skipif(shutil.which("node") is None, reason="Node runtime unavailable")
def test_serialized_finalizer_report_is_ungraded_by_actual_ui_helpers():
    root = Path(__file__).resolve().parents[1]
    grade = (root / "ui/src/lib/deviceScanPresentation.mjs").as_uri()
    summary = (root / "ui/src/lib/scanDetailPresentation.mjs").as_uri()
    script = f'''
        import fs from 'node:fs';
        import assert from 'node:assert/strict';
        import {{deviceScorePresentation}} from {json.dumps(grade)};
        import {{scanResultPresentation}} from {json.dumps(summary)};
        const report = JSON.parse(fs.readFileSync(0, 'utf8'));
        const row = {{grade: 'A*', score: 100, result: report}};
        const presentation = deviceScorePresentation(row);
        assert.equal(presentation.status, 'not_examined');
        assert.equal(presentation.grade, null);
        assert.equal(presentation.score, null);
        const headline = scanResultPresentation(row, {{band: 'weak'}});
        assert.equal(headline.notExamined, true);
        assert.equal(headline.observedRiskScore, null);
    '''
    subprocess.run([shutil.which("node"), "--input-type=module", "-e", script],
                   input=json.dumps(redirect_report()), text=True, check=True, capture_output=True)
