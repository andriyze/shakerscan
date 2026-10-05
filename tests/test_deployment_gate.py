"""Deploy gate: a DAST deploy decision must reflect the TARGET's unresolved risk, not
just the current scan's findings. Pure-function tests of build_deployment_decision
(no DB) — covers the target_active_findings merge + dedup that was previously
live-verified only."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
import api  # noqa: E402
from scan.finding_identity import canonical_finding_fingerprint  # noqa: E402


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


_EXPOSURE = {"title": "Sensitive exposure", "severity": "high", "tool": "probe", "url": "http://app/.env"}


def _persisted(fid, fingerprint, *, scan_id, last_seen_scan_id):
    active = {**_crit(fid, fingerprint, _EXPOSURE["title"]), **{k: _EXPOSURE[k] for k in ("severity", "tool", "url")}}
    row = {"id": fid, "fingerprint": fingerprint, "severity": "high",
           "scan_id": scan_id, "last_seen_scan_id": last_seen_scan_id}
    return active, row


def test_reobserved_persisted_finding_does_not_duplicate_an_unfingerprinted_report():
    scan = _scan([dict(_EXPOSURE)])
    active, row = _persisted("f1", canonical_finding_fingerprint(_EXPOSURE), scan_id="old-scan",
                             last_seen_scan_id=scan["id"])
    history = {"rows": [row], "total": 1, "complete": True}
    decision = api.build_deployment_decision(scan, target_active_findings=[active], target_history=history)
    assert decision["decision"] == "block"
    assert len(decision["blocking_findings"]) == 1
    assert decision["carried_over"]["count"] == 0
    assert not decision["blocking_findings"][0].get("from_target_active")
    assert decision["blocking_findings"][0]["id"] == "f1"


def test_an_earlier_scan_is_not_double_counted_after_a_later_scan_takes_the_row_over():
    """findings.scan_id and last_seen_scan_id move to the newest scan that re-observed a row.
    Viewing the earlier scan's decision must still count its report row and the persisted row
    once (live: 17 blockers for 9 findings on the first of two Juice Shop scans)."""
    scan = _scan([dict(_EXPOSURE)])
    active, row = _persisted("f1", canonical_finding_fingerprint(_EXPOSURE), scan_id="later-scan",
                             last_seen_scan_id="later-scan")
    history = {"rows": [row], "total": 1, "complete": True}
    decision = api.build_deployment_decision(scan, target_active_findings=[active], target_history=history)
    assert len(decision["blocking_findings"]) == 1
    assert decision["carried_over"]["count"] == 0


def test_an_exception_on_the_persisted_finding_covers_the_scan_that_reported_it():
    scan = _scan([dict(_EXPOSURE)])
    active, row = _persisted("f1", canonical_finding_fingerprint(_EXPOSURE), scan_id=scan["id"],
                             last_seen_scan_id=scan["id"])
    exception = {"id": "e1", "finding_id": "f1", "status": "active", "policy_id": None,
                 "target_id": "t1", "owner": "o", "approver": "a", "reason": "r",
                 "compensating_controls": "c", "expires_at": "2099-01-01T00:00:00+00:00"}
    decision = api.build_deployment_decision(
        scan, target_active_findings=[active], target_history={"rows": [row], "total": 1, "complete": True},
        db_exceptions=[exception],
    )
    assert decision["blocking_findings"] == []
    assert [item["id"] for item in decision["applied_exceptions"]] == ["f1"]
    assert decision["decision"] == "needs_approval"


def test_same_display_text_with_a_different_fingerprint_remains_a_separate_blocker():
    scan = _scan([dict(_EXPOSURE)])
    active, row = _persisted("f1", "t:another-finding", scan_id="old-scan", last_seen_scan_id="old-scan")
    history = {"rows": [row], "total": 1, "complete": True}
    decision = api.build_deployment_decision(scan, target_active_findings=[active], target_history=history)
    assert len(decision["blocking_findings"]) == 2
    assert decision["blocking_findings"][1]["from_target_active"] is True
    assert decision["carried_over"]["count"] == 1


def test_one_report_row_cannot_hide_two_active_rows():
    scan = _scan([dict(_EXPOSURE)])
    first, first_row = _persisted("f1", canonical_finding_fingerprint(_EXPOSURE), scan_id="old-scan",
                                  last_seen_scan_id=scan["id"])
    second, second_row = _persisted("f2", "t:f2", scan_id="old-scan", last_seen_scan_id=scan["id"])
    history = {"rows": [first_row, second_row], "total": 2, "complete": True}
    decision = api.build_deployment_decision(scan, target_active_findings=[first, second], target_history=history)
    assert [item["id"] for item in decision["blocking_findings"]] == ["f1", "f2"]
    assert decision["decision"] == "block"


def test_decision_carries_the_target_history_summary_over_all_severities():
    scan = _scan([{"id": "f1", "fingerprint": "fp1", "title": "Seen", "severity": "low"}])
    history = {"rows": [
        {"severity": "medium", "scan_id": "old", "last_seen_scan_id": "old", "fingerprint": "fp-med", "status": "active"},
        {"severity": "low", "scan_id": "old", "last_seen_scan_id": "old", "fingerprint": "fp1", "status": "active"},
    ], "total": 2, "complete": True}
    decision = api.build_deployment_decision(scan, target_active_findings=[], target_history=history)
    assert decision["carried_over"] == {
        "count": 1, "material": 1, "highest": "medium", "complete": True,
        "total_active": 2, "unloaded_active": 0,
    }
    # The gate itself is unchanged: a medium does not block under the default profile.
    assert decision["decision"] == "allow"


def test_decision_marks_an_incomplete_history_instead_of_claiming_an_all_clear():
    history = {"rows": [], "total": 12, "complete": False}
    decision = api.build_deployment_decision(_scan([]), target_active_findings=[], target_history=history)
    assert decision["carried_over"]["complete"] is False
    assert decision["carried_over"]["unloaded_active"] == 12


def test_an_exception_bound_to_its_row_still_applies_after_the_row_is_rekeyed():
    """Endpoint findings gained a |service= qualifier and their rows were re-keyed. Reconciliation
    binds the old exception to the row's id; the earlier fingerprint alone is not authority (see the
    next test), so the row id is what keeps the exception applying."""
    import hashlib

    from findings import pre_service_templated_finding_identity

    finding = {"id": "r1", "title": "SQL Injection", "severity": "critical", "tool": "sqlmap",
               "cwe": "CWE-89", "url": "https://app.example.test/search?q=1",
               "evidence": {"method": "GET", "param": "q"}}
    finding["fingerprint"] = canonical_finding_fingerprint(finding)
    earlier = "t:" + hashlib.sha256(pre_service_templated_finding_identity(finding).encode()).hexdigest()[:16]
    assert earlier != finding["fingerprint"]
    exception = {"id": "e1", "finding_id": "r1", "fingerprint": earlier, "status": "active", "approver": "a",
                 "expires_at": "2099-01-01T00:00:00+00:00"}
    remaining, applied = api._apply_policy_exceptions([finding], [exception])
    assert remaining == [] and [item["id"] for item in applied] == ["r1"]
    unrelated = {**exception, "finding_id": "other-row", "fingerprint": "t:0000000000000000"}
    remaining, applied = api._apply_policy_exceptions([finding], [unrelated])
    assert [item["id"] for item in remaining] == ["r1"] and applied == []


def test_legacy_exception_aliases_never_expand_across_services_routes_or_checks():
    import hashlib
    from findings import pre_service_templated_finding_identity, pre_check_templated_finding_identity
    base = {"id": "first", "title": "SQL Injection", "severity": "critical", "tool": "sqlmap",
            "cwe": "CWE-89", "url": "https://app.example.test/search?q=1", "evidence": {"method": "GET", "param": "q"}}
    dom = {**base, "cwe": "CWE-79", "evidence": {"param": "q", "client_route": "/search?q=1"}}
    tls = {**base, "cwe": "CWE-295", "url": "https://app.example.test/", "evidence": {"check": "untrusted"}}
    pairs = [
        (base, {**base, "id": "second", "url": "https://app.example.test:8443/search?q=1"}, pre_service_templated_finding_identity),
        (dom, {**dom, "id": "second", "evidence": {"param": "q", "client_route": "/profile?q=1"}}, pre_service_templated_finding_identity),
        (tls, {**tls, "id": "second", "evidence": {"check": "expired"}}, pre_check_templated_finding_identity),
    ]
    for first, second, historical in pairs:
        first["fingerprint"] = canonical_finding_fingerprint(first)
        second["fingerprint"] = canonical_finding_fingerprint(second)
        assert first["fingerprint"] != second["fingerprint"]
        alias = "t:" + hashlib.sha256(historical(first).encode()).hexdigest()[:16]
        exception = {"id": "exception", "fingerprint": alias, "status": "active", "approver": "operator",
                     "expires_at": "2099-01-01T00:00:00Z"}
        remaining, applied = api._apply_policy_exceptions([first, second], [exception])
        assert remaining == [first, second] and applied == []
        remaining, applied = api._apply_policy_exceptions([first, second], [{**exception, "finding_id": "first"}])
        assert remaining == [second] and applied == [first]


def test_migrated_exact_exception_covers_a_report_without_a_database_row_id():
    finding = {"title": "SQL Injection", "severity": "critical", "tool": "sqlmap", "cwe": "CWE-89",
               "url": "https://app.example.test/search?q=1", "evidence": {"method": "GET", "param": "q"}}
    exception = {"id": "exception", "finding_id": "persisted-row", "status": "active", "approver": "operator",
                 "fingerprint": canonical_finding_fingerprint(finding), "expires_at": "2099-01-01T00:00:00Z"}
    decision = api.build_deployment_decision(_scan([finding]), db_exceptions=[exception])
    assert decision["blocking_findings"] == []
    assert len(decision["applied_exceptions"]) == 1
    assert decision["decision"] == "needs_approval"
    other_service = {**finding, "url": "https://app.example.test:8443/search?q=1"}
    decision = api.build_deployment_decision(_scan([other_service]), db_exceptions=[exception])
    assert len(decision["blocking_findings"]) == 1
    assert decision["applied_exceptions"] == []


def test_a_projected_row_never_gains_a_broader_recomputed_fingerprint():
    full = {"title": "Certificate is untrusted", "severity": "high", "tool": "tls.inspect", "cwe": "CWE-295",
            "url": "https://app.example.test/", "evidence": {"check": "certificate_untrusted"}}
    projected = {k: v for k, v in full.items() if k != "evidence"}
    projected["fingerprint"] = canonical_finding_fingerprint(full)
    broader = canonical_finding_fingerprint(projected)
    assert broader != projected["fingerprint"]
    exception = {"id": "exception", "status": "active", "approver": "operator", "fingerprint": broader,
                 "expires_at": "2099-01-01T00:00:00Z"}
    remaining, applied = api._apply_policy_exceptions([projected], [exception])
    assert remaining == [projected] and applied == []


def test_an_exception_on_the_canonical_fingerprint_covers_a_finding_reported_without_one():
    """Rows that never stored a fingerprint (non-DAST producers) are matched by their canonical
    identity. Comparing the empty stored value could never match, so an approved exception kept
    blocking the deployment."""
    finding = {"title": "SQL Injection", "severity": "critical", "tool": "sqlmap", "cwe": "CWE-89",
               "url": "https://app.example.test/search?q=1", "evidence": {"method": "GET", "param": "q"}}
    exception = {"id": "exception", "status": "active", "approver": "operator",
                 "fingerprint": canonical_finding_fingerprint(finding), "expires_at": "2099-01-01T00:00:00Z"}
    remaining, applied = api._apply_policy_exceptions([finding], [exception])
    assert remaining == [] and applied == [finding]
    other_service = {**finding, "url": "https://app.example.test:8443/search?q=1"}
    remaining, applied = api._apply_policy_exceptions([other_service], [exception])
    assert remaining == [other_service] and applied == []
