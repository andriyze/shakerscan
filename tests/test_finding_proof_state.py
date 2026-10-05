"""Single proof-state per finding so list and detail agree (docs §7).

An unproven High/Critical must render as "suspected" (a lead), and a
deterministically-proven finding as verified — both driven by ONE server-derived
field so the findings list and detail page can never disagree.
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *a, **k):
            pass

        def add_middleware(self, *a, **k):
            return None

        def _decorator(self, *a, **k):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = _decorator

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.Header = lambda default=None, **k: default
    fastapi_mod.HTTPException = type("_HTTPExc", (Exception,), {})
    fastapi_mod.Query = lambda default=None, **k: default
    fastapi_mod.Request = type("_Req", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi"] = fastapi_mod
    cors_mod = types.ModuleType("fastapi.middleware.cors")
    cors_mod.CORSMiddleware = type("_CORS", (), {})
    sys.modules["fastapi.middleware"] = types.ModuleType("fastapi.middleware")
    sys.modules["fastapi.middleware.cors"] = cors_mod
    responses_mod = types.ModuleType("fastapi.responses")
    responses_mod.Response = type("_Resp", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi.responses"] = responses_mod

from tests.api_import_stubs import install_fastapi_exception_stubs  # noqa: E402

install_fastapi_exception_stubs()
import api as api_module  # noqa: E402

pf = api_module.finding_proof_fields

from scan.finding_identity import canonical_finding_fingerprint  # noqa: E402  (the worker's persistence key)
from finding_service_identity import finding_provenance_key  # noqa: E402


def test_deterministic_exploited_retest_is_verified():
    r = pf({
        "severity": "high",
        "last_verification_verdict": "exploited",
        "latest_retest_mode": "deterministic",
    })
    assert r["is_verified"] is True
    assert r["is_suspected"] is False
    assert r["proof_state"] == "verified"


def test_ai_exploited_verdict_never_becomes_deterministic_proof():
    r = pf({
        "severity": "critical",
        "last_verification_verdict": "exploited",
        "latest_retest_mode": "ai_driven",
    })
    assert r["is_verified"] is False
    assert r["is_suspected"] is True
    assert r["proof_state"] == "suspected"


def test_scan_time_generic_verified_flag_is_suspected():
    r = pf({"severity": "critical", "verified": True})
    assert r["is_verified"] is False
    assert r["is_suspected"] is True
    assert r["proof_state"] == "suspected"


def test_scan_time_typed_proof_is_verified():
    r = pf({"severity": "critical", "proof_of_exploitation": True})
    assert r["is_verified"] is True
    assert r["is_suspected"] is False
    assert r["proof_state"] == "verified"


def test_failed_browser_proof_is_not_verified():
    r = pf({"severity": "critical", "verified": True, "browser_proof": {"proven": False}})
    assert r["is_verified"] is False
    assert r["proof_state"] == "suspected"


def test_proven_browser_proof_is_verified():
    r = pf({"severity": "high", "browser_proof": {
        "proven": True,
        "confidence": 0.99,
        "proof_producer": "shakerscan",
        "evidence_type": "dom_execution",
        "technique": "headless_xss_dialog",
    }})
    assert r["is_verified"] is True
    assert r["proof_state"] == "verified"


def test_unproven_high_is_suspected():
    r = pf({"severity": "high", "last_verification_verdict": "inconclusive"})
    assert r["is_verified"] is False
    assert r["is_suspected"] is True
    assert r["proof_state"] == "suspected"


def test_unproven_critical_is_suspected():
    r = pf({"severity": "critical"})
    assert r["is_suspected"] is True
    assert r["proof_state"] == "suspected"


def test_unproven_medium_is_not_suspected():
    # Severity alone does not invent a candidate state for medium/low rows.
    r = pf({"severity": "medium"})
    assert r["is_suspected"] is False
    assert r["proof_state"] == "unverified"


def test_explicit_medium_template_candidate_remains_suspected():
    r = pf({
        "severity": "medium",
        "evidence": {
            "proof_state": "candidate",
            "triage": {
                "suspected": True,
                "needs_verification": True,
            },
        },
    })
    assert r["is_verified"] is False
    assert r["is_suspected"] is True
    assert r["proof_state"] == "suspected"


def test_json_encoded_persisted_candidate_evidence_is_not_downgraded():
    r = pf({
        "severity": "info",
        "evidence": (
            '{"proof_state":"candidate","triage":'
            '{"suspected":true,"needs_verification":false}}'
        ),
    })
    assert r["is_verified"] is False
    assert r["is_suspected"] is True
    assert r["proof_state"] == "suspected"


def test_blocked_verdict_high_is_suspected_not_verified():
    # blocked_by_security is not deterministic proof of exploitation.
    r = pf({"severity": "high", "last_verification_verdict": "blocked_by_security"})
    assert r["is_verified"] is False
    assert r["proof_state"] == "suspected"


# --- The scan detail speaks the same proof vocabulary -------------------------------------------

def _exposure_report_finding(**overrides):
    """A scan report finding exactly as the exposure prover writes it (honey /id_rsa, host renamed)."""
    import json
    path = os.path.join(os.path.dirname(__file__), "fixtures", "scan_report_exposure_finding.json")
    with open(path, encoding="utf-8") as handle:
        finding = json.load(handle)
    finding.update(overrides)
    return finding


def _project(report_findings, persisted_rows):
    # Wired exactly as GET /scans/{id} wires it.
    report = {"findings": report_findings}
    rows = api_module.project_scan_finding_proof(
        report, persisted_rows, project=pf, identities=api_module.finding_identity_keys,
    )
    return report["findings"], rows


def _stored_row(fingerprint, **fields):
    """A persisted row with no durable proof of its own: only this run's proof can verify it."""
    return {"id": fingerprint, "fingerprint": fingerprint, "severity": "critical", "evidence": None,
            "latest_retest_mode": None, "last_verification_verdict": None, **fields}


def test_scan_report_findings_carry_the_findings_api_proof_vocabulary():
    """The scanner writes 'exploited'; the scan page read only 'verified' and showed proven
    critical exposures as '0 proven, need verification'."""
    candidate = {"severity": "medium", "title": "Git Configuration - Detect",
                 "url": "https://honey.example.test/.git/config", "tool": "nuclei",
                 "proof_state": "candidate", "suspected": True, "needs_verification": True}
    (proven, lead), _ = _project([_exposure_report_finding(), candidate], [])
    assert (proven["proof_state"], proven["is_verified"], proven["scan_time_proof_state"]) == ("verified", True, "exploited")
    assert (lead["proof_state"], lead["is_suspected"], lead["scan_time_proof_state"]) == ("suspected", True, "candidate")


def test_a_persisted_row_is_proven_by_this_runs_proof_and_keeps_a_retest_proof():
    raw = _exposure_report_finding()
    # Keyed the way the worker persists it, not by a helper of this module.
    row_for_raw = {"id": "a", "fingerprint": canonical_finding_fingerprint(raw), "severity": "critical",
                   "url": raw["url"], "evidence": None, "latest_retest_mode": None,
                   "last_verification_verdict": "exploited"}
    retested = {"id": "b", "fingerprint": "elsewhere", "severity": "high", "evidence": "{}",
                "latest_retest_mode": "deterministic", "last_verification_verdict": "exploited"}
    unproven = {"id": "c", "fingerprint": "other", "severity": "high", "evidence": None,
                "latest_retest_mode": "ai_only", "last_verification_verdict": "exploited"}
    _, rows = _project([raw], [row_for_raw, retested, unproven])
    assert [row["proof_state"] for row in rows] == ["verified", "verified", "suspected"]
    # The projection inputs are not part of the scan detail.
    assert all("evidence" not in row and "latest_retest_mode" not in row for row in rows)


# --- A report finding finds its row by the identity persistence stores it under -----------------

def test_the_exposure_row_is_keyed_canonically_not_by_the_old_api_hash():
    raw = _exposure_report_finding()
    # The audit's example: the persisted row is templated; the old API helper was not.
    assert api_module.finding_identity_keys(raw) == (
        "t:87298f037581f42d", "t:c2f2ffb786643d9c", "b9a1f522b80ef3d9",
    )
    assert api_module.generate_finding_fingerprint(raw) == "t:87298f037581f42d"
    (proven,), (row,) = _project([raw], [_stored_row(canonical_finding_fingerprint(raw), url=raw["url"])])
    assert (proven["proof_state"], row["proof_state"]) == ("verified", "verified")


def test_rows_collapsed_across_object_ids_and_query_values_are_proven_by_any_variant():
    bola = {"title": "Broken object level authorization", "tool": "authz", "cwe": "CWE-639",
            "url": "https://app.example.test/api/orders/46", "proof_of_exploitation": True,
            "proof_state": "exploited", "verified": True, "severity": "high"}
    sqli = {"title": "SQL injection", "tool": "sqlmap", "cwe": "CWE-89",
            "url": "https://app.example.test/search?q=zzz", "proof_of_exploitation": True,
            "proof_state": "exploited", "verified": True, "severity": "critical"}
    # The worker stored each row from another object id / query value of the same endpoint.
    stored = [_stored_row(canonical_finding_fingerprint({**bola, "url": "https://app.example.test/api/orders/12"}),
                          url="https://app.example.test/api/orders/12"),
              _stored_row(canonical_finding_fingerprint({**sqli, "url": "https://app.example.test/search?q=1%27"}),
                          url="https://app.example.test/search?q=1%27")]
    reports, rows = _project([bola, sqli], stored)
    assert [finding["proof_state"] for finding in reports] == ["verified", "verified"]
    assert [row["proof_state"] for row in rows] == ["verified", "verified"]


def test_a_row_stored_under_the_old_identity_is_still_found():
    raw = _exposure_report_finding()
    scanner_id = {**raw, "id": "exposure:id_rsa"}
    # Rows persisted before endpoint identities were templated: the hash, and the scanner ID.
    _, rows = _project([raw], [_stored_row("b9a1f522b80ef3d9", url=raw["url"])])
    assert rows[0]["proof_state"] == "verified"
    _, rows = _project([scanner_id], [_stored_row("exposure:id_rsa", url=raw["url"])])
    assert rows[0]["proof_state"] == "verified"


def test_only_this_runs_proof_lifts_a_row_never_a_lead_or_another_finding():
    # A lead with no proof: its row must not be lifted by another finding's proof.
    lead = {"severity": "medium", "title": "Directory listing", "tool": "nuclei",
            "url": "https://honey.example.test/backup/", "proof_state": "candidate",
            "suspected": True, "needs_verification": True}
    raw = _exposure_report_finding()
    other = _stored_row(canonical_finding_fingerprint({**raw, "url": "https://honey.example.test/.env"}))
    reports, rows = _project([lead, raw], [_stored_row(canonical_finding_fingerprint(lead)), other])
    assert [finding["proof_state"] for finding in reports] == ["suspected", "verified"]
    # Neither the lead's row nor a row for a different path is verified by the proven finding.
    assert [row["is_verified"] for row in rows] == [False, False]


def test_scan_time_overrides_reach_the_canonically_keyed_row():
    raw = _exposure_report_finding()
    overrides = api_module._scan_result_verification_overrides({"findings": [raw]})
    assert set(overrides) == {
        (key, finding_provenance_key(raw))
        for key in ("t:87298f037581f42d", "t:c2f2ffb786643d9c", "b9a1f522b80ef3d9")
    }
    assert overrides[("t:87298f037581f42d", finding_provenance_key(raw))]["last_verification_verdict"] == "exploited"


def test_scan_time_overrides_keep_both_services_that_share_a_legacy_key():
    from scan.finding_verification_overrides import matching_verification_override

    primary = _exposure_report_finding()
    alternate = _exposure_report_finding(url="https://honey.example.test:8443/id_rsa")
    overrides = api_module._scan_result_verification_overrides({"findings": [primary, alternate]})
    legacy_key = "t:c2f2ffb786643d9c"
    for url in (primary["url"], alternate["url"]):
        fields = matching_verification_override(overrides, _stored_row(legacy_key, url=url))
        assert fields["last_verification_verdict"] == "exploited"
    assert matching_verification_override(
        overrides, _stored_row(legacy_key, url="https://honey.example.test:9443/id_rsa"),
    ) == {}
    assert matching_verification_override(overrides, _stored_row(legacy_key)) == {}


def test_legacy_report_proof_does_not_cross_service_or_fill_missing_provenance():
    raw = _exposure_report_finding()
    rows = [
        _stored_row("t:c2f2ffb786643d9c", url="https://honey.example.test:8443/id_rsa"),
        _stored_row("t:c2f2ffb786643d9c", url="http://honey.example.test/id_rsa"),
        _stored_row("t:c2f2ffb786643d9c"),
        _stored_row("t:c2f2ffb786643d9c", url="https://honey.example.test:443/id_rsa"),
    ]
    _, projected = _project([raw], rows)
    assert [row["is_verified"] for row in projected] == [False, False, False, True]


def test_legacy_dom_proof_projection_and_overrides_require_the_same_client_route():
    import hashlib
    from findings import pre_service_templated_finding_identity
    from scan.finding_verification_overrides import matching_verification_override

    finding = {
        "url": "https://app.example.test/", "tool": "dalfox", "cwe": "CWE-79",
        "title": "Verified cross-site scripting", "severity": "high",
        "proof_of_exploitation": True, "proof_state": "exploited",
        "evidence": {"method": "GET", "param": "q", "client_route": "/search?q=proof"},
    }
    legacy = "t:" + hashlib.sha256(pre_service_templated_finding_identity(finding).encode()).hexdigest()[:16]
    rows = [
        _stored_row(legacy, url=finding["url"], evidence={"client_route": route})
        for route in ("/profile?q=", "/search?name=", None, "/search?q=another-value")
    ]
    overrides = api_module._scan_result_verification_overrides({"findings": [finding]})
    assert [bool(matching_verification_override(overrides, row)) for row in rows] == [False, False, False, True]
    _, projected = _project([finding], rows)
    assert [row["is_verified"] for row in projected] == [False, False, False, True]
