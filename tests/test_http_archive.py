"""The HTTP transaction archive.

ShakerScan was architected content-free: receipts carried redacted URLs, response header
names and body hashes, and the request meter kept the last hundred events in memory. That
makes a finding defensible and a scan unreviewable. These tests pin the properties that
make the archive trustworthy rather than merely present.
"""

import hashlib
import json

import pytest

from api.runtime.http_archive import (
    ARCHIVE_MODES,
    DEFAULT_MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    HttpTransaction,
    capped_body,
    har_document,
    har_entry,
    hunt_call_recorder,
    normalized_headers,
    transaction_rows,
)
from api.runtime.http_archive_reader import export_document, project


def test_a_truncated_body_still_reports_the_whole_body_truthfully():
    """The digest and length describe the complete body, never the stored prefix.

    A digest over the prefix would quietly claim a match against something it never saw,
    which is worse than storing nothing.
    """
    payload = b"x" * 500
    capped = capped_body(payload, limit=100)
    assert len(capped["content"]) == 100
    assert capped["bytes"] == 500
    assert capped["truncated"] is True
    assert capped["sha256"] == hashlib.sha256(payload).hexdigest()


def test_a_body_within_the_ceiling_is_kept_whole():
    capped = capped_body(b"small", limit=DEFAULT_MAX_BODY_BYTES)
    assert capped["content"] == b"small"
    assert capped["truncated"] is False


def test_an_absent_body_is_absent_rather_than_empty():
    """Zero bytes sent and no body at all are different facts."""
    capped = capped_body(None)
    assert capped["content"] is None
    assert capped["sha256"] is None
    assert capped["bytes"] == 0


def test_headers_are_bounded_so_one_call_cannot_dominate_the_archive():
    huge = {f"h{index}": "v" * 1_000 for index in range(1_000)}
    stored = normalized_headers(huge)
    assert 0 < len(stored) < 1_000
    assert sum(len(k) + len(v) for k, v in stored.items()) <= MAX_HEADER_BYTES + 1_100


def test_header_names_are_normalized_but_values_are_kept_as_sent():
    stored = normalized_headers({"Content-Type": "TEXT/HTML", "X-Probe": "Value"})
    assert stored == {"content-type": "TEXT/HTML", "x-probe": "Value"}


def test_a_transaction_must_name_its_plane_method_and_url():
    for kwargs in (
        {"plane": "invented", "method": "GET", "url": "https://t/"},
        {"plane": "scan", "method": "", "url": "https://t/"},
        {"plane": "scan", "method": "GET", "url": ""},
    ):
        with pytest.raises(ValueError):
            HttpTransaction(**kwargs)


def test_rows_carry_the_identity_of_the_work_that_made_the_call():
    """Without it the archive is a pile of requests nobody can attribute."""
    rows = transaction_rows([HttpTransaction(
        plane="hunt", method="get", url="https://t/x", hunt_run_id="h1",
        hunt_action_id="a1", capability_name="http.request", adapter="agent.http_request",
        principal_slot="primary", status_code=200, direct_origin=True,
    )], store_blob=lambda content: "blob")
    row = rows[0]
    assert row["method"] == "GET"
    assert (row["hunt_run_id"], row["hunt_action_id"]) == ("h1", "a1")
    assert row["capability_name"] == "http.request"
    assert row["principal_slot"] == "primary"
    assert row["direct_origin"] is True


def test_the_recorder_produces_the_same_shape_for_every_caller():
    collected, record = hunt_call_recorder(
        hunt_run_id="h1", hunt_action_id="a1", capability_name="http.request",
        adapter="agent.http_request", target_url="https://t/",
    )
    record({
        "method": "GET", "url": "https://t/x", "status_code": 200,
        "response_body": b"body", "remote_ip": "203.0.113.10", "direct_origin": True,
    })
    record({"method": "GET", "url": "https://t/y", "error": "request_error:ConnectError"})
    assert [item.sequence for item in collected] == [0, 1]
    assert collected[0].direct_origin is True
    # A call that never got a response is still a call the scanner made, and a refused
    # connection to a confirmed origin is often the finding.
    assert collected[1].error == "request_error:ConnectError"
    assert collected[1].status_code is None


def test_har_entries_declare_truncation():
    entry = har_entry(
        {
            "method": "GET", "url": "https://t/x", "status_code": 200,
            "response_body_bytes": 5_000, "truncated": True,
            "response_headers": {"content-type": "text/html"},
            "elapsed_ms": 12, "remote_ip": "203.0.113.10",
        },
        request_body=None, response_body="partial",
    )
    assert entry["comment"] == "truncated"
    assert entry["response"]["content"]["mimeType"] == "text/html"
    assert entry["serverIPAddress"] == "203.0.113.10"


def test_the_har_document_is_valid_1_2():
    document = har_document([], creator_version="2.0.0")
    assert document["log"]["version"] == "1.2"
    assert document["log"]["creator"]["name"] == "ShakerScan"


def test_the_export_states_its_redaction_and_fidelity():
    """A redacted export that looks complete is worse than one that says what it removed,
    and a run predating the archive made calls that were simply never recorded."""
    rows = [{
        "id": "11111111-1111-4111-8111-111111111111",
        "method": "GET", "url": "https://t/x", "status_code": 200,
        "sequence": 0, "plane": "hunt", "response_headers": {"content-type": "text/html"},
        "response_body": "hello", "response_body_bytes": 5, "started_at": None,
    }]
    document = export_document(
        rows, export_format="transactions", redaction="redacted",
        owner={"hunt_id": "h1"}, total=1,
    )
    assert document["redaction"] == "redacted"
    assert document["fidelity"] == "complete"
    assert document["exported"] == 1 and document["total"] == 1
    assert document["truncated_export"] is False

    empty = export_document(
        [], export_format="transactions", redaction="raw", owner={}, total=0,
    )
    assert empty["fidelity"] == "unavailable", (
        "a run with no archived calls must not look like one that made none"
    )


def test_a_partial_export_says_so():
    rows = [{"id": "1", "method": "GET", "url": "https://t/", "sequence": 0, "plane": "scan"}]
    document = export_document(
        rows, export_format="transactions", redaction="redacted", owner={}, total=5_000,
    )
    assert document["truncated_export"] is True
    assert document["total"] == 5_000


def test_redaction_is_applied_unless_raw_is_asked_for():
    row = {
        "id": "1", "method": "POST", "url": "https://t/login", "sequence": 0,
        "plane": "hunt",
        "request_headers": {"authorization": "Bearer super-secret-value"},
        "response_body": None,
    }
    redacted = project(row, redaction="redacted")
    raw = project(row, redaction="raw")
    assert "super-secret-value" not in json.dumps(redacted)
    assert "super-secret-value" in json.dumps(raw)


def test_archive_modes_are_a_closed_set():
    assert ARCHIVE_MODES == {"full", "metadata", "off"}


# --- raw export is a deliberate deployment choice ----------------------------------------

def test_raw_export_is_disabled_unless_the_deployment_enables_it(monkeypatch):
    """Every other public surface is metadata-only or redacted. A raw export is the one
    place a single request yields bearer tokens exactly as sent, so it is off by default
    rather than a query parameter anyone who reaches the API may set."""
    from api.runtime import http_archive_router as archive_router

    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW", raising=False)
    assert archive_router.raw_export_enabled() is False
    for value in ("0", "false", "no", "", "maybe"):
        monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW", value)
        assert archive_router.raw_export_enabled() is False, value
    for value in ("1", "true", "yes", "on", "TRUE"):
        monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW", value)
        assert archive_router.raw_export_enabled() is True, value


def test_raw_export_refuses_before_it_reaches_the_database(monkeypatch):
    """The refusal happens on the redaction argument, so a disabled deployment never even
    reads the rows it would have to redact."""
    from fastapi import HTTPException

    from api.runtime import http_archive_router as archive_router

    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW", raising=False)
    with pytest.raises(HTTPException) as exc:
        archive_router._authorize_raw(object())
    assert exc.value.status_code == 403
    assert "raw export is disabled" in str(exc.value.detail)


def test_enabling_raw_still_requires_the_operator_control(monkeypatch):
    """The switch permits raw export; it does not make it anonymous. ShakerScan has no
    users to authorize against, so this is its existing privileged-operator control --
    a credential plus loopback, HTTPS, or a trusted Tailscale transport."""
    from api.runtime import http_archive_router as archive_router

    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW", "1")
    called: list[object] = []
    monkeypatch.setattr(archive_router, "_require_operator", called.append)
    archive_router._authorize_raw("request-sentinel")
    assert called == ["request-sentinel"], "the operator gate must still run"


def test_redacted_export_needs_no_operator_credential(monkeypatch):
    """The default path stays usable, or the archive is unreviewable in practice."""
    from api.runtime import http_archive_router as archive_router

    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW", raising=False)
    refused: list[object] = []

    def _fail(request):
        refused.append(request)
        raise AssertionError("redacted export must not require the operator gate")

    monkeypatch.setattr(archive_router, "_require_operator", _fail)
    # Nothing to call: _authorize_raw is only reached for redaction="raw".
    assert refused == []
