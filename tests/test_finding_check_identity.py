"""Distinct checks that share a CWE keep their own finding row.

The finding identity used the CWE alone as the class of an endpoint finding. Several checks share a
CWE -- five TLS certificate checks are CWE-295, every missing baseline header is CWE-693 -- and they
carry the origin as their URL, so on one origin they shared one persisted row whose title flipped
on every scan. A finding that names its check now has the check in its class; one that names none
keys exactly as before, and the same check on another object id or payload still collapses.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import os
import sys
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from findings import pre_check_templated_finding_identity, templated_finding_identity  # noqa: E402

from api.scan import finalizer  # noqa: E402
from api.scan.finding_identity import canonical_finding_fingerprint, finding_identity_keys  # noqa: E402
from api.scan.finding_reconciliation import reconcile_legacy_finding_row  # noqa: E402

ORIGIN = "https://fixture.test:18443/"
TARGET = uuid.UUID("00000000-0000-4000-8000-000000000888")


def _tls(title, check, cwe="CWE-295"):
    return {"url": ORIGIN, "tool": "tls.inspect", "cwe": cwe, "title": title,
            "evidence": {"check": check, "origin": ORIGIN}}


UNTRUSTED = _tls("TLS certificate chain is not trusted", "tls_certificate_untrusted")
EXPIRING = _tls("TLS certificate expires within 30 days", "tls_certificate_expiring")


def _fingerprint(identity):
    return "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16]


def test_checks_sharing_a_cwe_on_one_origin_get_their_own_identity():
    assert templated_finding_identity(UNTRUSTED) != templated_finding_identity(EXPIRING)
    assert canonical_finding_fingerprint(UNTRUSTED) != canonical_finding_fingerprint(EXPIRING)
    # Both were stored under the CWE-only key, which stays computable to carry that row across.
    assert pre_check_templated_finding_identity(UNTRUSTED) == "CWE-295|GET|/|"
    assert pre_check_templated_finding_identity(EXPIRING) == "CWE-295|GET|/|"


def test_template_matchers_sharing_a_cwe_on_one_url_do_not_merge():
    def nuclei(matcher):
        return {"url": "http://h/", "tool": "nuclei", "cwe": "CWE-200", "title": f"exposed {matcher}",
                "evidence": {"template_id": "exposed-panels", "matcher_name": matcher}}
    assert templated_finding_identity(nuclei("grafana")) != templated_finding_identity(nuclei("kibana"))


def test_the_same_check_still_collapses_across_object_ids_and_payloads():
    def sqli(path, payload):
        return {"url": f"http://h{path}?q={payload}", "cwe": "CWE-89", "title": f"SQLi {payload}",
                "evidence": {"template_id": "sqli-error-based", "matcher_name": "mysql"}}
    assert templated_finding_identity(sqli("/orders/1", "1' OR 1=1")) == \
        templated_finding_identity(sqli("/orders/46", "sleep(5)"))


@pytest.mark.parametrize("finding", [
    # A CWE finding naming no check: the BOLA and SQLi collapse keys are unchanged.
    {"url": "http://h/orders/7", "cwe": "CWE-639"},
    # A CWE-less finding: it already keyed on its template or title.
    {"url": "http://h/", "title": "Directory listing enabled", "evidence": {"check": "listing"}},
    {"url": "http://h/", "evidence": {"template_id": "t", "matcher_name": "m"}},
])
def test_findings_whose_key_did_not_change_have_no_earlier_key(finding):
    assert pre_check_templated_finding_identity(finding) is None


def test_a_cwe_finding_without_a_check_adds_its_service_to_the_route_key():
    assert templated_finding_identity({"url": "http://h/orders/7", "cwe": "CWE-639"}) == \
        "CWE-639|GET|/orders/{id}||service=http://h:80"


def test_the_finalizer_names_the_check_of_every_tls_issue_and_missing_header(monkeypatch):
    monkeypatch.setattr(finalizer, "_receipt", lambda result: {"receipt_id": "r", "capability_name": result.capability_name})
    tls = finalizer._findings_for_action(SimpleNamespace(capability_name="tls.inspect"), [{
        "kind": "tls_protocol", "origin": ORIGIN, "protocol": "TLSv1.2", "port": 18443,
        "certificate_trust": "untrusted", "certificate_expiring_within_30_days": True,
        "certificate_hostname_matches": False, "certificate_expired": False,
    }])
    assert {finding["title"] for finding in tls} == {
        "TLS certificate chain is not trusted", "TLS certificate expires within 30 days",
        "TLS certificate hostname mismatch",
    }
    # Three CWE-295 issues on one origin: three rows, not one.
    assert len({canonical_finding_fingerprint(finding) for finding in tls}) == 3
    assert all(finding["evidence"]["check"].startswith("tls_") for finding in tls)
    baseline = finalizer._findings_for_action(SimpleNamespace(capability_name="http.request", action_id="baseline.http"), [{
        "kind": "http_observation",
        "request": {"origin": ORIGIN},
        "response": {"status": 200, "selected_headers": {"server": "x"}},
    }])
    missing = {finding["evidence"]["header"] for finding in baseline}
    assert {"content-security-policy", "referrer-policy", "permissions-policy", "strict-transport-security"} <= missing
    # Every missing header is CWE-693 on the same origin: one row each.
    assert len({canonical_finding_fingerprint(finding) for finding in baseline}) == len(baseline)


def test_report_findings_still_find_rows_stored_under_the_earlier_key():
    keys = finding_identity_keys(UNTRUSTED)
    assert keys[0] == canonical_finding_fingerprint(UNTRUSTED)
    assert _fingerprint("CWE-295|GET|/|") in keys


class _Rows:
    """Rows by fingerprint; moving a row re-keys it, as the UPDATE does."""

    def __init__(self, rows):
        self.rows = rows

    async def fetchrow(self, query, target_id, fingerprint):
        return self.rows.get(fingerprint)

    @asynccontextmanager
    async def transaction(self):
        yield

    async def execute(self, query, fingerprint, row_id):
        old = next(key for key, row in self.rows.items() if row["id"] == row_id)
        self.rows[fingerprint] = self.rows.pop(old)
        return "UPDATE 1"


@pytest.mark.parametrize("order", [(UNTRUSTED, EXPIRING), (EXPIRING, UNTRUSTED)])
def test_the_collapsed_row_is_adopted_by_exactly_one_split_finding_with_its_triage(order):
    """The old row carried the title last written to it. That check takes it over with its
    triage; the other check opens its own row instead of inheriting a disposition."""
    collapsed = {"id": uuid.uuid4(), "status": "accepted_risk", "resurfaced_count": 2,
                 "title": UNTRUSTED["title"], "tool": "tls.inspect", "cwe": "CWE-295",
                 "url": ORIGIN, "evidence": None}
    conn = _Rows({_fingerprint("CWE-295|GET|/|"): collapsed})
    adopted = {}
    for finding in order:
        fingerprint = canonical_finding_fingerprint(finding)
        adopted[finding["title"]] = asyncio.run(reconcile_legacy_finding_row(
            conn, target_uuid=TARGET, fingerprint=fingerprint, finding=finding,
        ))
    assert adopted[UNTRUSTED["title"]] is collapsed and collapsed["status"] == "accepted_risk"
    assert adopted[EXPIRING["title"]] is None
    assert list(conn.rows) == [canonical_finding_fingerprint(UNTRUSTED)]
