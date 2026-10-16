"""Exposure noise control, verify availability and the Hunt candidate rows."""

from datetime import datetime, timezone
import uuid

from api.exposure.service_rows import (
    attach_verification,
    candidate_verification,
    hunt_candidate_rows,
    listener_groups,
    severity_counts,
    verify_bound,
)

TARGET = {"id": str(uuid.uuid4()), "kind": "web", "locator": "https://app.example.test/"}


def _service(sid, port=443, *, product="Apache httpd", version="2.4.49", presence="observed_open",
             candidates=(), findings=(), stale=False, seen="2026-10-15T00:00:00+00:00",
             origin="https://app.example.test", transport="tcp"):
    return {
        "id": sid, "transport": transport, "port": port, "service": "https", "product": product,
        "version": version, "presence": presence, "binding_status": "observation_only",
        "application_origin": origin, "identity_stale": stale, "last_seen_at": seen,
        "cve_candidates": list(candidates), "findings": list(findings),
    }


def _candidate(cve, severity="high", kev=False, epss=None, cvss=None, check=None):
    return {"id": cve, "severity": severity, "known_exploited": {"date_added": "2021-11-03"} if kev else None,
            "epss": {"score": epss, "percentile": 0.9} if epss is not None else None, "cvss_score": cvss,
            "match_type": "exact_cpe_version_range",
            "checks": [{"kind": "nuclei_template", "id": check}] if check else []}


def test_one_row_per_listener_product_version_with_members_and_fresh_identity_once():
    rows = listener_groups([
        _service("a", stale=True, seen="2026-10-01T00:00:00+00:00",
                 candidates=[_candidate("CVE-2021-41773", "critical", kev=True)]),
        _service("b", origin=None, seen="2026-10-15T00:00:00+00:00",
                 candidates=[_candidate("CVE-2021-41773", "critical", kev=True)]),
        _service("c", port=161, transport="udp", product=None, version=None, presence="inconclusive"),
        _service("d", port=22, product="OpenSSH", version="8.9"),
    ])
    first = rows[0]
    assert first["service_ids"] == ["a", "b"] and first["primary_service_id"] == "b"
    assert (first["candidate_count"], first["known_exploited"], first["max_severity"]) == (1, 1, "critical")
    assert first["identity_stale"] is False      # one fresh member is a fresh identity
    quiet = [row for row in rows if row["quiet"]]
    assert [row["port"] for row in quiet] == [161] and rows[-1]["port"] == 161
    assert severity_counts(rows) == {"critical": 1, "high": 0, "medium": 0, "low": 0, "none": 2, "quiet": 1}


def test_rows_are_ordered_by_consequence_not_port():
    rows = listener_groups([
        _service("low", port=21, product="vsftpd", version="3.0.3", candidates=[_candidate("CVE-1", "low")]),
        _service("crit", port=8443, product="Jetty", version="9.4", candidates=[_candidate("CVE-2", "critical")]),
        _service("finding", port=80, product="nginx", version="1.2",
                 findings=[{"id": "f1", "severity": "medium"}]),
    ])
    assert [row["primary_service_id"] for row in rows] == ["crit", "finding", "low"]


def test_verify_is_offered_only_on_the_target_origin_with_a_named_check():
    candidate = _candidate("CVE-2021-41773", check="CVE-2021-41773")
    on_origin = candidate_verification(TARGET, _service("a"), candidate, {})
    assert on_origin["status"] == "available"
    assert on_origin["request"] == {
        "target": TARGET["locator"], "budget_profile": "fast", "verify_templates": ["cve-2021-41773"],
        "policy": {"active_testing": True, "preset": "custom", "include_families": ["nuclei_active"]},
    }
    other_port = candidate_verification(TARGET, _service("b", port=8443, origin="https://app.example.test:8443"),
                                        candidate, {})
    assert (other_port["status"], other_port["request"]) == ("unavailable", None)
    assert other_port["unavailable_reason"] == "listener_is_not_the_target_origin"
    assert verify_bound({**TARGET, "kind": "device"}, _service("c")) == "device_services_verify_in_the_device_workflow"
    assert verify_bound(TARGET, _service("d", presence="inconclusive")) == "refresh_evidence_first"
    assert candidate_verification(TARGET, _service("e"), _candidate("CVE-9"), {})["status"] == "no_check"


def test_a_running_verify_scan_is_pending_and_never_reads_as_clean():
    scan = uuid.uuid4()
    records = {"scans": [{"id": scan, "status": "running", "created_at": datetime.now(timezone.utc),
                          "completed_at": None, "target_url": TARGET["locator"],
                          "verify_templates": ["cve-2021-41773"]}],
               "actions": {}, "findings": []}
    state = candidate_verification(TARGET, _service("a"), _candidate("C", check="CVE-2021-41773"), records)
    assert state["status"] == "pending" and state["scan_id"] == str(scan)
    records["scans"][0]["status"] = "completed"   # completed, but the step never reported success
    assert candidate_verification(TARGET, _service("a"), _candidate("C", check="CVE-2021-41773"),
                                  records)["status"] == "inconclusive"


def test_hunt_rows_put_known_exploited_and_likely_first_with_the_check_state():
    services = [
        _service("s1", candidates=[_candidate("CVE-2", "critical", cvss=9.8, epss=0.2),
                                   _candidate("CVE-3", "medium", kev=True, epss=0.01, check="cve-3")]),
        _service("s2", port=22, product="OpenSSH‮", version="8.9",
                 candidates=[_candidate("CVE-1", "high", epss=0.9)]),
    ]
    attach_verification(TARGET, services, {})
    rows = hunt_candidate_rows(services)
    assert [row["cve"] for row in rows] == ["CVE-3", "CVE-1", "CVE-2"]
    assert rows[0]["known_exploited"] is True and rows[0]["checks"] == ["cve-3"]
    assert rows[0]["verification"] == "available" and rows[0]["applicability"] == "candidate"
    assert rows[1]["product"] == "OpenSSH"       # control characters stripped from banner labels
    assert rows[2]["verification"] == "no_check"


def _scan_records(requested, steps, status="completed", target_url=TARGET["locator"]):
    scan = uuid.uuid4()
    return scan, {"scans": [{"id": scan, "status": status, "created_at": datetime.now(timezone.utc),
                             "completed_at": datetime.now(timezone.utc), "target_url": target_url,
                             "verify_templates": requested}],
                  "actions": {str(scan): steps}, "findings": []}


def _step(ran, excluded=None, unreliable=None, status="success", reason=None):
    return {"status": status, "reason_code": reason, "verify_selection": {
        "requested": sorted(set(ran) | set(excluded or {})), "ran": list(ran),
        "excluded": dict(excluded or {}), "negative_unreliable": dict(unreliable or {})}}


def test_not_matched_only_when_every_check_was_requested_and_ran_reliably():
    two = {"id": "CVE-X", "severity": "high", "checks": [
        {"kind": "nuclei_template", "id": "a"}, {"kind": "nuclei_template", "id": "b"}]}

    def state(requested, steps):
        _scan, records = _scan_records(requested, steps)
        return candidate_verification(TARGET, _service("s"), two, records)

    assert state(["a", "b"], [_step(["a", "b"]), _step(["a", "b"])])["status"] == "check_not_matched"
    partial = state(["a", "b"], [_step(["a"], {"b": "needs_oob_interaction"})])
    assert (partial["status"], partial["reason"]) == ("inconclusive", "needs_oob_interaction")
    assert "not_every_check_requested" in state(["a"], [_step(["a"])])["reason"]
    assert state(["a", "b"], [_step(["a", "b"], unreliable={"b": "needs_redirects"})])["reason"] == "needs_redirects"
    assert state(["a", "b"], [{"status": "success", "reason_code": None}])["reason"] == "selection_not_recorded"
    assert state(["a", "b"], [_step(["a", "b"]), _step([], status="skipped", reason="verify_checks_excluded")
                              ])["status"] == "inconclusive"
    assert state(["a", "b"], [])["reason"] == "no_active_template_step"


def test_an_exploit_class_check_is_not_offered_as_a_one_click_verify():
    candidate = {"id": "CVE-Y", "severity": "critical",
                 "checks": [{"kind": "nuclei_template", "id": "cve-y", "safety": "exploit"}]}
    state = candidate_verification(TARGET, _service("s"), candidate, {})
    assert (state["status"], state["request"]) == ("unavailable", None)
    assert state["unavailable_reason"] == "exploit_class_needs_exploit_tier"


def test_a_verify_scan_is_credited_only_to_the_listener_on_its_own_origin():
    candidate = _candidate("CVE-X", check="cve-x")
    scan, records = _scan_records(["cve-x"], [_step(["cve-x"])])
    on_origin = _service("a", origin="https://app.example.test", candidates=[_candidate("CVE-X", check="cve-x")])
    other_port = _service("b", port=8443, origin="https://app.example.test:8443",
                          candidates=[_candidate("CVE-X", check="cve-x")])
    attach_verification(TARGET, [on_origin, other_port], records)
    assert on_origin["cve_candidates"][0]["verification"]["status"] == "check_not_matched"
    off = other_port["cve_candidates"][0]
    assert (off["verification"]["status"], off["verification"]["unavailable_reason"]) == (
        "unavailable", "listener_is_not_the_target_origin")
    assert "scan_id" not in off["verification"] and "local_validation" not in off

    # A match at :443 is never credited to :8443 either.
    records["findings"] = [{"id": uuid.uuid4(), "template_id": "cve-x", "scan_id": scan, "status": "open"}]
    assert candidate_verification(TARGET, other_port, candidate, records)["status"] == "unavailable"
    assert candidate_verification(TARGET, _service("c"), candidate, records)["status"] == "check_matched"

    # A Scan of another origin of the same target says nothing about this listener.
    _scan, elsewhere = _scan_records(["cve-x"], [_step(["cve-x"])], target_url="https://app.example.test:8443/")
    assert candidate_verification(TARGET, _service("d"), candidate, elsewhere)["status"] == "available"
