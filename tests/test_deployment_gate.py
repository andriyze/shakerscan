"""Deploy gate: a DAST deploy decision must reflect the TARGET's unresolved risk, not
just the current scan's findings. Pure-function tests of build_deployment_decision
(no DB) — covers the target_active_findings merge + dedup that was previously
live-verified only."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
import api  # noqa: E402


def _scan(findings, status="completed", run_kind="web_dast", scan_type="smart"):
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "status": status, "scan_type": scan_type, "run_kind": run_kind,
        "result": {"findings": findings}, "score": 93, "grade": "A",
        "options": {"environment": "staging"},
    }


def _crit(fid, fp, title="SQL Injection"):
    return {"id": fid, "fingerprint": fp, "title": title, "severity": "critical"}


def test_clean_scan_blocks_on_target_active_criticals():
    # This scan found nothing blockable, but the target has an unresolved critical.
    decision = api.build_deployment_decision(_scan([]), target_active_findings=[_crit("f1", "fp1")])
    assert decision["decision"] == "block"
    assert decision["blocking_findings"], "target-active critical must appear as blocking"
    assert any(f.get("from_target_active") for f in decision["blocking_findings"])


def test_no_target_active_clean_scan_allows():
    decision = api.build_deployment_decision(_scan([]), target_active_findings=[])
    assert decision["decision"] == "allow"


def test_target_active_deduped_against_this_scan_finding():
    # Same fingerprint found by THIS scan and present as target-active -> counted once.
    scan = _scan([_crit("f1", "fp1")])
    decision = api.build_deployment_decision(scan, target_active_findings=[_crit("f1", "fp1")])
    fps = [f.get("fingerprint") for f in decision["blocking_findings"]]
    assert fps.count("fp1") == 1
    assert decision["decision"] == "block"


def test_target_active_only_marks_provenance():
    # A target-active finding NOT found by this scan is flagged from_target_active.
    decision = api.build_deployment_decision(_scan([]), target_active_findings=[_crit("f9", "fp9")])
    match = [f for f in decision["blocking_findings"] if f.get("fingerprint") == "fp9"]
    assert match and match[0].get("from_target_active") is True
