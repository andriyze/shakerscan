"""R4: durable policy + exception registry feeding the deployment decision.

These exercise build_deployment_decision's injected DB records (the live API
lifecycle — create/cover/revoke/re-block — is verified separately against the DB).
Runs where the API deps are available (the scanner runtime image).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import api as api_module  # noqa: E402

FUTURE = "2099-01-01T00:00:00+00:00"
PAST = "2000-01-01T00:00:00+00:00"


def _scan_with_high_finding():
    return {
        "id": "s1", "status": "completed", "scan_type": "smart", "run_kind": "web_dast",
        "result": {"findings": [{"id": "f-high", "severity": "high", "title": "x"}]},
    }


def test_active_db_exception_covers_blocking_finding():
    scan = _scan_with_high_finding()
    base = api_module.build_deployment_decision(scan)
    assert any(f["id"] == "f-high" for f in base["blocking_findings"])

    exc = [{"finding_id": "f-high", "status": "active", "approver": "sec", "expires_at": FUTURE}]
    covered = api_module.build_deployment_decision(scan, db_exceptions=exc)
    assert not covered["blocking_findings"]
    assert any(f["id"] == "f-high" for f in covered["applied_exceptions"])


def test_revoked_expired_or_unapproved_exception_does_not_cover():
    scan = _scan_with_high_finding()
    cases = [
        [{"finding_id": "f-high", "status": "revoked", "approver": "sec", "expires_at": FUTURE}],
        [{"finding_id": "f-high", "status": "active", "approver": "sec", "expires_at": PAST}],
        [{"finding_id": "f-high", "status": "active", "expires_at": FUTURE}],  # no approver/owner
    ]
    for exc in cases:
        d = api_module.build_deployment_decision(scan, db_exceptions=exc)
        assert any(f["id"] == "f-high" for f in d["blocking_findings"]), exc
        assert not d["applied_exceptions"], exc


def test_db_policy_profile_overrides_block_threshold():
    scan = {
        "id": "s2", "status": "completed", "scan_type": "smart", "run_kind": "web_dast",
        "result": {"findings": [{"id": "f-high", "severity": "high", "title": "x"}]},
        "options": json.dumps({"environment": "staging"}),
    }
    # builtin staging blocks on high
    builtin = api_module.build_deployment_decision(scan)
    assert any(f["id"] == "f-high" for f in builtin["blocking_findings"])
    # a durable DB profile raises the threshold to critical -> high no longer blocks
    db_profiles = {"staging": {
        "name": "custom-staging", "environment": "staging",
        "minimum_block_severity": "critical", "expires_days": 7, "id": "staging",
    }}
    overridden = api_module.build_deployment_decision(scan, db_policy_profiles=db_profiles)
    assert not overridden["blocking_findings"]
    assert overridden["policy_profile"] == "staging"


def test_profile_disallowing_active_exceptions_keeps_block():
    # A profile with allow_active_exceptions=False must ignore active exceptions.
    scan = {
        "id": "s3", "status": "completed", "scan_type": "smart", "run_kind": "web_dast",
        "result": {"findings": [{"id": "f-high", "severity": "high", "title": "x"}]},
        "options": json.dumps({"environment": "staging"}),
    }
    exc = [{"finding_id": "f-high", "status": "active", "approver": "sec", "expires_at": FUTURE}]
    db_profiles = {"staging": {
        "name": "no-exceptions-staging", "environment": "staging",
        "minimum_block_severity": "high", "expires_days": 7, "id": "staging",
        "allow_active_exceptions": False,
    }}
    d = api_module.build_deployment_decision(scan, db_policy_profiles=db_profiles, db_exceptions=exc)
    assert any(f["id"] == "f-high" for f in d["blocking_findings"])
    assert not d["applied_exceptions"]
    assert d["exceptions_disabled_by_profile"] is True

    # Same profile but exceptions allowed -> the exception covers the finding.
    db_profiles["staging"]["allow_active_exceptions"] = True
    covered = api_module.build_deployment_decision(scan, db_policy_profiles=db_profiles, db_exceptions=exc)
    assert not covered["blocking_findings"]
    assert any(f["id"] == "f-high" for f in covered["applied_exceptions"])
    assert covered["exceptions_disabled_by_profile"] is False


def test_fingerprint_only_exception_covers_blocking_finding():
    # An exception keyed only on fingerprint (no finding_id) must cover a finding
    # carrying that fingerprint, even when the row ids differ.
    scan = {
        "id": "s4", "status": "completed", "scan_type": "smart", "run_kind": "web_dast",
        "result": {"findings": [{"id": "f-xyz", "fingerprint": "fp-abc", "severity": "high", "title": "x"}]},
    }
    base = api_module.build_deployment_decision(scan)
    assert any(f.get("fingerprint") == "fp-abc" for f in base["blocking_findings"])

    exc = [{"finding_id": None, "fingerprint": "fp-abc", "status": "active", "approver": "sec", "expires_at": FUTURE}]
    covered = api_module.build_deployment_decision(scan, db_exceptions=exc)
    assert not covered["blocking_findings"]
    assert any(f.get("fingerprint") == "fp-abc" for f in covered["applied_exceptions"])

    # A non-matching fingerprint must not cover it.
    other = [{"fingerprint": "fp-other", "status": "active", "approver": "sec", "expires_at": FUTURE}]
    not_covered = api_module.build_deployment_decision(scan, db_exceptions=other)
    assert any(f.get("fingerprint") == "fp-abc" for f in not_covered["blocking_findings"])
    assert not not_covered["applied_exceptions"]
