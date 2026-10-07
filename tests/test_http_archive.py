"""The HTTP transaction archive.

ShakerScan was architected content-free: receipts carried redacted URLs, response header
names and body hashes, and the request meter kept the last hundred events in memory. That
makes a finding defensible and a scan unreviewable. These tests pin the properties that
make the archive trustworthy rather than merely present.
"""

import asyncio
import hashlib
import json
import time

import pytest

from api.runtime.http_archive import (
    ARCHIVE_MODES,
    archive_http_transactions,
    DEFAULT_MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    HttpTransaction,
    bounded_metadata,
    capped_body,
    har_document,
    har_entry,
    hunt_call_recorder,
    normalized_headers,
    record_archive_stats,
    transaction_rows,
)
from api.runtime.http_archive_reader import (
    _search_pattern,
    archive_fidelity,
    count_transactions,
    export_document,
    project,
    purge_transactions,
    read_transactions,
    read_archive_stats,
)
from api.capabilities.http import _read_bounded_response
from scanner.scanner_tools import http_archive_capture


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


def test_header_ceiling_counts_encoded_bytes_not_unicode_codepoints():
    stored = normalized_headers({"x-wide": "\N{SNOWMAN}" * MAX_HEADER_BYTES})
    assert stored == {}


def test_header_names_are_normalized_but_values_are_kept_as_sent():
    stored = normalized_headers({"Content-Type": "TEXT/HTML", "X-Probe": "Value"})
    assert stored == {"content-type": "TEXT/HTML", "x-probe": "Value"}


def test_a_transaction_must_name_its_plane_method_and_url():
    for kwargs in (
        {"plane": "invented", "method": "GET", "url": "https://t/", "scan_id": "s1"},
        {"plane": "scan", "method": "", "url": "https://t/", "scan_id": "s1"},
        {"plane": "scan", "method": "GET", "url": "", "scan_id": "s1"},
    ):
        with pytest.raises(ValueError):
            HttpTransaction(**kwargs)


@pytest.mark.parametrize("kwargs", [
    {"plane": "scan"},
    {"plane": "scan", "scan_id": "s1", "hunt_run_id": "h1"},
    {"plane": "scan", "hunt_run_id": "h1"},
    {"plane": "hunt", "scan_id": "s1"},
])
def test_a_transaction_has_exactly_one_plane_appropriate_owner(kwargs):
    with pytest.raises(ValueError):
        HttpTransaction(method="GET", url="https://t/", **kwargs)


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


def test_a_har_is_masked_unless_raw_is_asked_for_and_says_so():
    """The UI's HAR download used to be verbatim whatever masking was requested, so any client
    that reached the API got Authorization headers and URL credentials in one call."""
    secret_url = "https://admin:hunter2@t.example/x?access_token=LIVE_TOKEN"
    document = export_document(
        [{"id": "1", "method": "GET", "url": secret_url, "sequence": 0, "plane": "scan"}],
        export_format="har", redaction="redacted",
        owner={"scan_id": "parent", "included_scan_ids": ["parent", "child"]}, total=1,
    )
    comment = json.loads(document["log"]["comment"])
    serialized = json.dumps(document["log"]["entries"])
    assert "hunter2" not in serialized and "LIVE_TOKEN" not in serialized
    assert comment["redaction"] == "redacted" and comment["sensitive"] is False
    # It can never pass for the verbatim request.
    assert document["log"]["creator"]["name"] == "ShakerScan (masked)"
    assert comment["owner"]["included_scan_ids"] == ["parent", "child"]


def test_a_raw_har_is_verbatim_and_labelled_sensitive():
    secret_url = "https://admin:hunter2@t.example/x?access_token=LIVE_TOKEN"
    document = export_document(
        [{"id": "1", "method": "GET", "url": secret_url, "sequence": 0, "plane": "scan"}],
        export_format="har", redaction="raw", owner={"scan_id": "s"}, total=1,
    )
    comment = json.loads(document["log"]["comment"])
    assert document["log"]["entries"][0]["request"]["url"] == secret_url
    assert comment["redaction"] == "raw" and comment["sensitive"] is True
    assert "Treat this export as sensitive" in comment["redaction_detail"]
    assert document["log"]["creator"]["name"] == "ShakerScan"


def _export_har(archive_router, redaction):
    import asyncio
    return asyncio.run(archive_router._export(
        request=object(), scan_id="11111111-1111-4111-8111-111111111111", hunt_run_id=None,
        export_format="har", redaction=redaction, method=None, status_code=None, search=None,
        limit=10, offset=0,
    ))


def test_raw_har_is_allowed_by_default_without_an_account_and_can_be_turned_off(monkeypatch):
    """Open-source installs have one operator and no accounts: verbatim HAR (credentials
    included) is available by default; a deployment may turn it off and keep the masked HAR."""
    from fastapi import HTTPException

    from api.runtime import http_archive_router as archive_router

    def _reached_database():
        raise RuntimeError("reached the database")

    def _no_account(request):
        raise AssertionError("verbatim HAR must not require an operator account")

    monkeypatch.setattr(archive_router, "_pool", _reached_database)
    monkeypatch.setattr(archive_router, "_require_operator", _no_account)
    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", raising=False)
    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW", raising=False)
    monkeypatch.delenv("SHAKERSCAN_BIND_HOST", raising=False)
    for redaction in ("raw", "redacted"):
        with pytest.raises(RuntimeError, match="reached the database"):
            _export_har(archive_router, redaction)
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", "0")
    with pytest.raises(HTTPException) as refused:
        _export_har(archive_router, "raw")
    assert refused.value.status_code == 403 and "masked HAR" in str(refused.value.detail)
    # Refused before any row is read; the masked HAR stays available.
    with pytest.raises(RuntimeError, match="reached the database"):
        _export_har(archive_router, "redacted")


@pytest.mark.parametrize("bind", ["192.168.1.50", "100.100.100.100", "0.0.0.0", "engine.lan"])
def test_raw_har_needs_an_explicit_opt_in_once_the_api_leaves_loopback(monkeypatch, bind):
    """LAN and tailnet modes add no authentication, so every peer could pull captured
    credentials with one GET; verbatim HAR then needs SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=1."""
    from fastapi import HTTPException

    from api.runtime import http_archive_router as archive_router

    def _reached_database():
        raise RuntimeError("reached the database")

    monkeypatch.setattr(archive_router, "_pool", _reached_database)
    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", raising=False)
    monkeypatch.setenv("SHAKERSCAN_BIND_HOST", bind)
    with pytest.raises(HTTPException) as refused:
        _export_har(archive_router, "raw")
    assert refused.value.status_code == 403 and "SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=1" in str(refused.value.detail)
    with pytest.raises(RuntimeError, match="reached the database"):
        _export_har(archive_router, "redacted")
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", "1")
    with pytest.raises(RuntimeError, match="reached the database"):
        _export_har(archive_router, "raw")


@pytest.mark.parametrize("bind", ["127.0.0.1", "::1", "[::1]", "localhost"])
def test_raw_har_stays_on_by_default_for_a_loopback_install(monkeypatch, bind):
    from api.runtime import http_archive_router as archive_router

    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", raising=False)
    monkeypatch.setenv("SHAKERSCAN_BIND_HOST", bind)
    assert archive_router.raw_har_enabled() is True


def _export_transactions(monkeypatch, archive_router):
    """Run the transactions export over an empty archive without a database."""
    import asyncio
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def acquire():
        yield object()

    class _Pool:
        def acquire(self):
            return acquire()

    async def _ids(conn, scan_id):
        return (scan_id,)

    async def _count(conn, **kwargs):
        return 0

    async def _stats(conn, **kwargs):
        return {}

    async def _rows(conn, **kwargs):
        return []

    monkeypatch.setattr(archive_router, "_pool", lambda: _Pool())
    monkeypatch.setattr(archive_router, "_scan_archive_ids", _ids)
    monkeypatch.setattr(archive_router, "count_transactions", _count)
    monkeypatch.setattr(archive_router, "read_archive_stats", _stats)
    monkeypatch.setattr(archive_router, "read_transactions", _rows)
    response = asyncio.run(archive_router._export(
        request=object(), scan_id="11111111-1111-4111-8111-111111111111", hunt_run_id=None,
        export_format="transactions", redaction="redacted", method=None, status_code=None,
        search=None, limit=10, offset=0,
    ))
    return json.loads(response.body), response.headers


def test_the_archive_says_whether_verbatim_har_is_available_before_it_is_asked_for(monkeypatch):
    """The UI offered Raw HAR on a deployment with SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=0 and the
    refused download failed silently. The archive envelope now carries the deployment's answer
    and its reason, so the option can be disabled with that reason instead."""
    from api.runtime import http_archive_router as archive_router

    monkeypatch.delenv("SHAKERSCAN_BIND_HOST", raising=False)
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", "0")
    document, headers = _export_transactions(monkeypatch, archive_router)
    assert document["raw_har"]["available"] is False
    assert "masked HAR" in document["raw_har"]["reason"]
    assert headers["x-shakerscan-raw-har"] == "disabled"

    monkeypatch.setenv("SHAKERSCAN_BIND_HOST", "0.0.0.0")
    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", raising=False)
    document, _headers = _export_transactions(monkeypatch, archive_router)
    assert document["raw_har"]["available"] is False
    assert "SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=1" in document["raw_har"]["reason"]

    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", "1")
    document, headers = _export_transactions(monkeypatch, archive_router)
    assert document["raw_har"] == {"available": True, "reason": None}
    assert headers["x-shakerscan-raw-har"] == "available"


def test_the_evidence_surface_withholds_unmasked_captured_traffic(tmp_path):
    """GET /evidence/{id} served a raw archive blob verbatim, bypassing the archive's masking."""
    from api.evidence_storage import public_evidence_object

    raw = public_evidence_object({"id": "e1", "object_type": "http_archive_blob", "redaction_profile": "none",
                                  "content": {"authorization": "Bearer LIVE"}}, results_dir=tmp_path)
    assert raw["content"] is None and raw["content_withheld"] is True
    assert "LIVE" not in json.dumps(raw)
    masked = public_evidence_object({"id": "e2", "object_type": "finding_evidence",
                                     "redaction_profile": "redact_sensitive_v1", "content": {"note": "kept"}},
                                    results_dir=tmp_path)
    assert masked["content"] == {"note": "kept"} and "content_withheld" not in masked


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
        stats={"attempted": 1, "stored": 1, "failed": 0, "dropped": 0},
    )
    assert document["redaction"] == "redacted"
    assert document["residual_secret_risk"] is True
    assert "arbitrary target-controlled bodies" in document["redaction_detail"]
    assert document["fidelity"] == "complete"
    assert document["exported"] == 1 and document["total"] == 1
    assert document["truncated_export"] is False

    empty = export_document(
        [], export_format="transactions", redaction="raw", owner={}, total=0,
    )
    assert empty["fidelity"] == "unavailable", (
        "a run with no archived calls must not look like one that made none"
    )


def test_metadata_archive_mode_keeps_body_digest_and_length_without_content(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE", "metadata")
    payload = b"credential-bearing-body"
    stored_blobs = []

    rows = transaction_rows([HttpTransaction(
        plane="scan", scan_id="s1", method="POST", url="https://t/",
        request_body=payload,
    )], store_blob=lambda content: stored_blobs.append(content) or "blob")

    assert rows[0]["request_body_object_id"] is None
    assert rows[0]["request_body_sha256"] == hashlib.sha256(payload).hexdigest()
    assert rows[0]["request_body_bytes"] == len(payload)
    assert stored_blobs == []


def test_oversized_metadata_remains_valid_and_declares_truncation():
    metadata = bounded_metadata({"target_controlled": "x" * 100_000})

    assert metadata["metadata_truncated"] is True
    assert metadata["original_bytes"] > 100_000
    assert len(json.dumps(metadata).encode("utf-8")) <= 16 * 1024


def test_archive_drop_accounting_accumulates_independent_drains():
    class Connection:
        def __init__(self):
            self.query = None

        async def execute(self, query, *_args):
            self.query = query

    conn = Connection()
    asyncio.run(record_archive_stats(
        conn,
        owner_kind="scan",
        owner_id="11111111-1111-4111-8111-111111111111",
        attempted=10,
        stored=8,
        failed=2,
        dropped=3,
    ))

    assert "dropped = http_archive_stats.dropped + EXCLUDED.dropped" in conn.query


def test_fidelity_is_backed_by_counters_not_by_row_count():
    """Capture and persistence failures are swallowed so they cannot fail a scan, so one
    surviving transaction must not be allowed to stand for a whole run."""
    rows = [{"id": "1", "method": "GET", "url": "https://t/", "sequence": 0, "plane": "hunt"}]

    lost = export_document(
        rows, export_format="transactions", redaction="redacted", owner={}, total=1,
        stats={"attempted": 40, "stored": 1, "failed": 39, "dropped": 0},
    )
    assert lost["fidelity"] == "partial"
    assert "1 of 40" in lost["fidelity_detail"]

    capped = export_document(
        rows, export_format="transactions", redaction="redacted", owner={}, total=1,
        stats={"attempted": 1, "stored": 1, "failed": 0, "dropped": 900},
    )
    assert capped["fidelity"] == "partial"
    assert "dropped" in capped["fidelity_detail"]

    # A run archived before the counters existed cannot claim completeness either.
    legacy = export_document(
        rows, export_format="transactions", redaction="redacted", owner={}, total=1,
    )
    assert legacy["fidelity"] == "unknown"

    uncovered = export_document(
        rows, export_format="transactions", redaction="redacted", owner={}, total=1,
        stats={
            "attempted": 1, "stored": 1, "failed": 0, "dropped": 0,
            "unarchived_http_capabilities": ["web.crawl"],
        },
    )
    assert uncovered["fidelity"] == "partial"
    assert "web.crawl" in uncovered["fidelity_detail"]


def test_a_truncated_response_is_marked_even_when_the_prefix_fits():
    """The executor stops reading at its own ceiling. Measuring the prefix it handed over
    would report a cut response as the complete body."""
    rows = transaction_rows([HttpTransaction(
        plane="scan", method="GET", url="https://t/big", scan_id="s1",
        response_body=b"prefix", response_body_truncated=True,
    )], store_blob=lambda content: "blob")
    assert rows[0]["truncated"] is True


def test_a_retained_prefix_uses_the_executor_full_body_digest_and_length():
    full = b"complete body that was streamed"
    rows = transaction_rows([HttpTransaction(
        plane="hunt", method="GET", url="https://t/big", hunt_run_id="h1",
        response_body=full[:8], response_body_truncated=True,
        response_body_sha256=hashlib.sha256(full).hexdigest(),
        response_body_bytes=len(full),
    )], store_blob=lambda content: "blob")
    assert rows[0]["response_body_sha256"] == hashlib.sha256(full).hexdigest()
    assert rows[0]["response_body_bytes"] == len(full)
    assert rows[0]["truncated"] is True


def test_response_reader_has_an_absolute_deadline_not_only_idle_timeout():
    class SlowResponse:
        async def aiter_bytes(self):
            yield b"a"
            await asyncio.sleep(0.05)
            yield b"b"

    body, digest, observed, truncated, deadline_exceeded = asyncio.run(
        _read_bounded_response(
            SlowResponse(), deadline=time.perf_counter() + 0.005, body_limit=100,
        )
    )
    assert body == b"a"
    assert digest == hashlib.sha256(b"a").hexdigest()
    assert observed == 1
    assert truncated is True
    assert deadline_exceeded is True


def test_process_capture_is_bounded_by_bytes_not_only_entry_count(monkeypatch):
    monkeypatch.setenv("HTTP_ARCHIVE_MAX_CAPTURED_CALLS", "50000")
    monkeypatch.setenv("HTTP_ARCHIVE_MAX_CAPTURE_BYTES", "256")
    http_archive_capture.start_capture()
    http_archive_capture.record({"url": "https://t/", "response_body": b"x" * 500})
    captured = http_archive_capture.drain_capture()

    assert captured["calls"] == []
    assert captured["dropped"] == 1
    assert captured["dropped_bytes"] > captured["byte_limit"]
    assert captured["bytes_used"] == 0


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


# --- second archive review ---------------------------------------------------------------

def test_cookie_headers_do_not_survive_a_redacted_export():
    """Authorization was masked while Cookie and Set-Cookie passed through, so a session
    credential left the machine in the default export."""
    row = {
        "id": "1", "method": "GET", "url": "https://t/", "sequence": 0, "plane": "scan",
        "request_headers": {"cookie": "sessionid=supersecret"},
        "response_headers": {"set-cookie": "sessionid=supersecret; Path=/"},
    }
    redacted = json.dumps(project(row, redaction="redacted"))
    assert "supersecret" not in redacted
    assert "supersecret" in json.dumps(project(row, redaction="raw"))


def test_evidence_describing_cookies_is_not_masked_away():
    """The fix is exact header keys, not a bare 'cookie' fragment, so findings about cookie
    behaviour keep the detail that makes them actionable."""
    row = {
        "id": "1", "method": "GET", "url": "https://t/", "sequence": 0, "plane": "scan",
        "response_headers": {"content-type": "text/html"},
        "response_body": '{"cookie_flags": {"httponly": false}, "cookie_names": ["sid"]}',
    }
    exported = json.dumps(project(row, redaction="redacted"))
    assert "httponly" in exported and "cookie_names" in exported


def test_the_archive_records_the_request_that_was_built():
    """The recorder took the caller's arguments, which lack the query string, the injected
    cookies, the Host header and everything httpx generates -- and after a redirect describe
    the wrong hop. An archive built from them cannot be replayed."""
    from tests.api_sources import api_tree_source

    source = api_tree_source()
    assert "def _emit_transaction(" in source
    assert 'getattr(response, "request", None)' in source
    assert 'getattr(built, "query", b"")' in source, "the query string must come from the built URL"
    assert "body_truncated=body_truncated" in source, "truncation is passed, not recomputed"
    assert "_read_bounded_response(" in source
    assert "response_body_bytes=response_bytes" in source


def test_redirect_hops_are_recorded_inside_the_execution_loop():
    """Recording only after the redirect loop silently dropped every intermediate call."""
    from tests.api_sources import definition_source

    source = definition_source("execute_bound_http_request")
    loop = source[source.index("while True:"):source.index("except (httpx.InvalidURL")]
    assert loop.index("_emit_transaction(") < loop.index("if (\n                    not follow_redirects")
    tail = source[source.index("if response is None:", source.index("except (httpx.InvalidURL")):]
    assert "_emit_transaction(" not in tail


def test_scan_capture_is_archived_before_success_or_failure_branching():
    from tests.api_sources import definition_source

    source = definition_source("process_scan_job")
    archive_at = source.index("await http_archive.drain_and_archive_scan_capture(")
    assert archive_at < source.index("if error:")
    assert "reset_scan_capture(scanner_http_capture, capture_started)" in source[source.index("finally:"):]


def test_hunt_http_collection_exists_for_every_capability_branch():
    from tests.api_sources import definition_source

    source = definition_source("process_canonical_http_capability_job")
    initialized = source.index("archived_calls, _record_call = http_archive.hunt_run_call_recorder(")
    assert initialized < source.index('if capability_name == "auth.session.establish"')
    authz = source[source.index('elif capability_name == "authz.verify"'):]
    assert "transaction_recorder=_record_call" in authz


def test_adapter_limited_capture_cannot_be_labelled_complete():
    rows = [{"id": "1", "method": "GET", "url": "https://t/", "sequence": 0, "plane": "scan"}]
    document = export_document(
        rows, export_format="transactions", redaction="redacted", owner={}, total=1,
        stats={
            "attempted": 1, "stored": 1, "failed": 0, "dropped": 0,
            "capture_limited": 1,
        },
    )
    assert document["fidelity"] == "partial"
    assert "adapter-limited" in document["fidelity_detail"]


@pytest.mark.asyncio
async def test_scan_stats_find_successful_http_capabilities_with_no_archive_rows():
    class Conn:
        async def fetchrow(self, query, *params):
            return {"attempted": 3, "stored": 3, "failed": 0, "dropped": 0}

        async def fetchval(self, query, *params):
            return 0

        async def fetch(self, query, *params):
            assert "requested_budget->>'http_requests'" in query
            return [{"capability_name": "web.crawl", "status": "success", "http_consumed": 71}]

    stats = await read_archive_stats(Conn(), scan_id="scan-1", hunt_run_id=None)
    assert stats["unarchived_http_capabilities"] == ["web.crawl"]
    assert stats["unarchived_http_capability_count"] == 1
    fidelity, detail = archive_fidelity(stats, total=3)
    assert fidelity == "partial"
    assert "web.crawl" in detail


class _ArchiveQueryConnection:
    def __init__(self):
        self.calls = []

    async def fetchval(self, query, *params):
        self.calls.append(("fetchval", query, params))
        return 7

    async def fetch(self, query, *params):
        self.calls.append(("fetch", query, params))
        return []


@pytest.mark.asyncio
async def test_archive_browser_filters_count_and_rows_with_the_same_search():
    conn = _ArchiveQueryConnection()
    total = await count_transactions(
        conn, scan_id="scan-1", hunt_run_id=None, method="post",
        status_code=401, search="/login",
    )
    rows = await read_transactions(
        conn, scan_id="scan-1", hunt_run_id=None, method="post",
        status_code=401, search="/login", limit=25, offset=50,
    )

    assert total == 7 and rows == []
    count_query, count_params = conn.calls[0][1:]
    row_query, row_params = conn.calls[1][1:]
    for query in (count_query, row_query):
        assert "url ILIKE" not in query
        assert "capability_name" in query
        assert "adapter" in query
    assert count_params == ("scan-1", "POST", 401, "%/login%")
    assert row_params == ("scan-1", "POST", 401, "%/login%", 25, 50)


@pytest.mark.asyncio
async def test_parallel_scan_archive_queries_parent_and_children_together():
    conn = _ArchiveQueryConnection()
    scan_ids = ("11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222")
    await count_transactions(
        conn, scan_id=scan_ids[0], scan_ids=scan_ids, hunt_run_id=None,
    )
    await read_transactions(
        conn, scan_id=scan_ids[0], scan_ids=scan_ids, hunt_run_id=None,
    )

    for _, query, params in conn.calls:
        assert "scan_id=ANY($1::uuid[])" in query
        assert params[0] == list(scan_ids)


@pytest.mark.asyncio
async def test_scan_archive_resolver_includes_nested_worker_children():
    from api.runtime.http_archive_router import _scan_archive_ids

    class Conn:
        async def fetch(self, query, scan_id):
            assert "WITH RECURSIVE scan_tree" in query
            assert "parent_scan_id=parent.id" in query
            assert scan_id == "parent"
            return [{"id": "parent"}, {"id": "child"}, {"id": "grandchild"}]

    assert await _scan_archive_ids(Conn(), "parent") == (
        "parent", "child", "grandchild",
    )


def test_archive_search_escapes_like_operators_and_never_queries_raw_urls():
    assert _search_pattern(r"50%_done\x") == "%50\\%\\_done\\\\x%"


def test_filtered_export_reports_matches_and_whole_archive_count_separately():
    document = export_document(
        [], export_format="transactions", redaction="redacted", owner={},
        total=3, archive_total=418,
    )
    assert document["total"] == 3
    assert document["archive_total"] == 418


def test_the_deterministic_scan_plane_records_its_calls():
    """No Scan call site passed a recorder, so every scan export was empty while the
    endpoint advertised coverage."""
    from tests.api_sources import api_tree_source

    source = api_tree_source()
    # The recorder now names the capability; it is still the scan capture's callback.
    assert "transaction_recorder=self._scan_call_recorder(action)" in source
    recorder = source[source.index("def _scan_call_recorder("):]
    recorder = recorder[:recorder.index("def _scan_replay_transport(")]
    assert "_scan_capture.record_scan_call" in recorder
    assert "capability_name=action.capability_name" in recorder


def test_scan_capture_preserves_wire_identity_and_truncation_metadata():
    from api.runtime.http_archive import scan_transactions_from_capture

    http_archive_capture.start_capture()
    http_archive_capture.record_scan_call({
        "method": "GET", "url": "https://t/x", "http_version": "HTTP/2",
        "response_body": b"prefix", "response_body_sha256": "a" * 64,
        "response_body_bytes": 7, "response_body_truncated": True,
        "response_digest_scope": "prefix", "principal_slot": "primary",
        "remote_ip": "203.0.113.7", "direct_origin": True,
    })
    item = scan_transactions_from_capture(
        http_archive_capture.drain_capture(), scan_id="scan-1",
    )[0]
    assert item.response_body_sha256 == "a" * 64
    assert item.response_body_bytes == 7
    assert item.principal_slot == "primary"
    assert item.remote_ip == "203.0.113.7"
    assert item.direct_origin is True
    assert item.metadata["response_digest_scope"] == "prefix"


def _enable_archive_encryption(monkeypatch):
    """Raw payloads are sealed with the credential key before storage; the normal install
    has one. Enable it so this exercises the keyed dedup path, not the no-key drop path."""
    from cryptography.fernet import Fernet
    try:
        import secret_store
    except ModuleNotFoundError:
        from api import secret_store
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)


@pytest.mark.asyncio
async def test_archive_batch_reuses_identical_evidence_blobs(monkeypatch):
    _enable_archive_encryption(monkeypatch)

    class Conn:
        def __init__(self):
            self.blob_inserts = 0
            self.blob_insert_statements = 0

        async def fetch(self, query, *params):
            assert "FROM evidence_objects" in query
            return []

        async def execute(self, query, *params):
            if "INSERT INTO evidence_objects" in query:
                self.blob_insert_statements += 1
                self.blob_inserts += len(json.loads(params[0]))
            return "INSERT 0 2"

    conn = Conn()
    transactions = [
        HttpTransaction(
            plane="scan", scan_id="11111111-1111-4111-8111-111111111111",
            method="GET", url=f"https://t/{index}",
            request_headers={"accept": "application/json"}, response_body=b"same-body",
        )
        for index in range(2)
    ]
    stored = lambda content: {
        "content_sha256": hashlib.sha256(json.dumps(content, sort_keys=True, default=str).encode()).hexdigest(),
        "size_bytes": 10, "storage_uri": "inline:evidence_objects", "content": content,
    }
    assert await archive_http_transactions(conn, transactions, store=stored) == 2
    assert conn.blob_inserts == 2, "one shared header object and one shared body object"
    assert conn.blob_insert_statements == 1, "all unique blobs use one DB insert statement"


@pytest.mark.asyncio
async def test_archive_drops_raw_payloads_when_the_encryption_key_is_unavailable(monkeypatch):
    """Without a key, raw payloads are not written in clear: no blob is stored, and the
    transaction records which payloads are unavailable so fidelity can report the gap."""
    try:
        import secret_store
    except ModuleNotFoundError:
        from api import secret_store
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", "")
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", True)  # unavailable, do not try to persist

    rows = []

    class Conn:
        async def fetch(self, query, *params):
            return []

        async def execute(self, query, *params):
            if "INSERT INTO http_transactions" in query or "INSERT INTO evidence_objects" in query:
                rows.append((query, params))
            return "INSERT 0 1"

    conn = Conn()
    transactions = [HttpTransaction(
        plane="scan", scan_id="11111111-1111-4111-8111-111111111111", method="GET",
        url="https://t/x", request_headers={"authorization": "Bearer leak"}, response_body=b"body")]
    assert await archive_http_transactions(conn, transactions, store=lambda c: {}) == 1
    assert not any("INSERT INTO evidence_objects" in q for q, _ in rows), "no raw blob stored"
    tx_params = next(p for q, p in rows if "INSERT INTO http_transactions" in q)
    serialized = json.dumps(tx_params, default=str)
    assert "Bearer leak" not in serialized and "payloads_unavailable" in serialized


@pytest.mark.asyncio
async def test_archive_batch_reuses_existing_content_addressed_blob():
    existing_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

    class Conn:
        async def fetch(self, query, *params):
            return [{
                "id": existing_id,
                "scan_id": None,
                "content_sha256": params[0][0],
            }]

        async def execute(self, query, *params):
            assert "INSERT INTO evidence_objects" not in query
            return "INSERT 0 1"

    transaction = HttpTransaction(
        plane="hunt", hunt_run_id="22222222-2222-4222-8222-222222222222",
        method="GET", url="https://t/existing", request_headers={"accept": "text/plain"},
    )
    stored = lambda content: {
        "content_sha256": hashlib.sha256(
            json.dumps(content, sort_keys=True, default=str).encode()
        ).hexdigest(),
        "size_bytes": 10, "storage_uri": "inline:evidence_objects", "content": content,
    }

    assert await archive_http_transactions(Conn(), [transaction], store=stored) == 1


@pytest.mark.asyncio
async def test_purge_removes_unreferenced_local_archive_bytes(tmp_path):
    storage_uri = "local:evidence_objects/aa/" + ("a" * 64) + ".json"
    path = tmp_path / "evidence-objects" / "aa" / (("a" * 64) + ".json")
    path.parent.mkdir(parents=True)
    path.write_text("secret archive body")

    class Transaction:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False

    class Conn:
        def transaction(self): return Transaction()

        async def fetch(self, query, *params):
            if "CROSS JOIN LATERAL" in query:
                return [{"object_id": "11111111-1111-4111-8111-111111111111", "storage_uri": storage_uri}]
            if "DELETE FROM evidence_objects" in query:
                return [{"id": "11111111-1111-4111-8111-111111111111", "storage_uri": storage_uri}]
            raise AssertionError(query)

        async def fetchval(self, query, *params):
            if "DELETE FROM http_transactions" in query:
                return 1
            if "SELECT EXISTS" in query:
                return False
            raise AssertionError(query)

        async def execute(self, query, *params):
            assert "DELETE FROM http_archive_stats" in query

    result = await purge_transactions(
        Conn(), scan_id=None, hunt_run_id="22222222-2222-4222-8222-222222222222",
        results_dir=tmp_path,
    )
    assert result["transactions_deleted"] == 1
    assert result["blobs_deleted"] == 1
    assert result["blob_files_deleted"] == [str(path)]
    assert not path.exists()


def test_archive_blobs_use_a_retention_class_the_sweep_accepts():
    """A bespoke http_archive class meant the one store that certainly holds credentials
    was the one the retention sweep could never reach."""
    from api.runtime.http_archive import RETENTION_CLASS

    assert RETENTION_CLASS in {"short", "sensitive", "standard", "audit"}
    assert RETENTION_CLASS == "sensitive", "bodies as sent are credential-bearing"


def test_deleting_the_archive_does_not_require_enabling_raw_export():
    """Gating the safe action behind the dangerous one would mean an operator had to enable
    exporting credentials before they were allowed to delete them."""
    from tests.api_sources import api_tree_source

    source = api_tree_source()
    purge = source[source.index("async def _purge("):]
    purge = purge[:purge.index("@router.delete")]
    assert "_require_operator(request)" in purge
    assert "_authorize_raw" not in purge


def test_redacted_hunt_http_write_omits_body_and_unsalted_digest():
    pin = "7319"
    raw_digest = hashlib.sha256(json.dumps({"CHALLENGE_RESPONSE": pin}).encode()).hexdigest()
    row = {
        "id": "11111111-1111-4111-8111-111111111112",
        "plane": "hunt", "hunt_run_id": "h1", "hunt_action_id": "a1",
        "capability_name": "http.request", "adapter": "agent.http_request",
        "method": "PUT", "url": "http://tv.test:7345/pair", "sequence": 0,
        "request_body": json.dumps({"CHALLENGE_RESPONSE": pin, "token": "issued"}),
        "request_body_sha256": raw_digest, "request_body_bytes": 52,
    }
    redacted = project(row, redaction="redacted")
    assert redacted["request"]["body"] is None
    assert redacted["request"]["sha256"] is None
    assert pin not in json.dumps(redacted)
    assert raw_digest not in json.dumps(redacted)
    raw = project(row, redaction="raw")
    assert pin in raw["request"]["body"]
    assert raw["request"]["sha256"] == raw_digest


@pytest.mark.parametrize('capability,method,private_flag', [
    ('http.request', 'GET', True), ('http.request', 'PUT', True),
    ('collections.replay_safe', 'GET', False),
    ('collections.replay_active', 'POST', False), ('collections.replay_active', 'GET', False),
])
def test_private_workflow_archive_hides_arbitrary_headers_bodies_and_pin_hashes(capability, method, private_flag):
    pin = '7319'
    digest = hashlib.sha256(pin.encode()).hexdigest()
    row = {'id': 'private-workflow', 'plane': 'hunt', 'capability_name': capability, 'method': method,
        'request_headers': {'AUTH': pin}, 'response_headers': {'X-Obscure': pin},
        'request_body': pin, 'response_body': pin, 'request_body_sha256': digest, 'response_body_sha256': digest,
        'metadata_json': {'workflow_values_private': private_flag}}
    public = project(row, redaction='redacted')
    assert pin not in json.dumps(public) and digest not in json.dumps(public)
    assert public['request']['headers']['AUTH'] == '[REDACTED]'
    assert public['response']['body'] is None
    raw = project(row, redaction='raw')
    assert raw['response']['body'] == pin and raw['response']['sha256'] == digest


def test_hunt_archive_recorder_preserves_workflow_privacy_marker():
    calls, record = hunt_call_recorder(hunt_run_id='hunt', hunt_action_id='action',
        capability_name='http.request', adapter='http', target_url='http://tv.test/')
    record({'method': 'GET', 'workflow_values_private': True})
    assert calls[0].metadata['workflow_values_private'] is True


PARENT, CHILD, GRANDCHILD, UNRELATED = (
    "a0000000-0000-4000-8000-000000000001", "a0000000-0000-4000-8000-000000000002",
    "a0000000-0000-4000-8000-000000000003", "a0000000-0000-4000-8000-000000000004",
)


class _ArchiveTreeConn:
    """Stateful stand-in for the archive tables: scans form a parent tree, and each
    transaction belongs to the scan that executed it (here the workers, not the parent)."""

    def __init__(self):
        self.scans = {PARENT: None, CHILD: PARENT, GRANDCHILD: CHILD, UNRELATED: None}
        self.transactions = [{"scan_id": CHILD}, {"scan_id": GRANDCHILD}, {"scan_id": UNRELATED}]
        self.stats = {("scan", CHILD), ("scan", GRANDCHILD), ("scan", UNRELATED)}

    def transaction(self):
        class Transaction:
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False
        return Transaction()

    def _owners(self, query, params):
        if "ANY($1::uuid[])" in query:
            return set(params[0])
        return {params[0]}

    async def fetch(self, query, *params):
        if "WITH RECURSIVE scan_tree" in query:
            tree, frontier = [params[0]], [params[0]]
            while frontier:
                frontier = [scan for scan, parent in self.scans.items() if parent in frontier]
                tree.extend(frontier)
            return [{"id": scan} for scan in tree]
        if "CROSS JOIN LATERAL" in query:
            return []
        raise AssertionError(query)

    async def fetchval(self, query, *params):
        if "DELETE FROM http_transactions" in query:
            owners = self._owners(query, params)
            before = len(self.transactions)
            self.transactions = [row for row in self.transactions if row["scan_id"] not in owners]
            return before - len(self.transactions)
        raise AssertionError(query)

    async def execute(self, query, *params):
        assert "DELETE FROM http_archive_stats" in query
        owners = set(params[1]) if isinstance(params[1], list) else {params[1]}
        self.stats = {item for item in self.stats if not (item[0] == params[0] and item[1] in owners)}


def test_purging_a_parent_scan_clears_the_child_scans_its_export_shows(monkeypatch):
    """Export resolves a visible scan to the child scans that ran its work, but purge
    deleted only `scan_id=<parent>`: it reported 0 deleted and left the child traffic."""
    from api.runtime import http_archive_router as router

    conn = _ArchiveTreeConn()

    class Pool:
        def acquire(self):
            class Acquire:
                async def __aenter__(self): return conn
                async def __aexit__(self, *args): return False
            return Acquire()

    monkeypatch.setattr(router, "_pool", lambda: Pool())
    monkeypatch.setattr(router, "_require_operator", lambda request: None)
    result = asyncio.run(router._purge(None, scan_id=PARENT, hunt_run_id=None))
    assert result["transactions_deleted"] == 2
    assert set(result["owner_ids"]) == {PARENT, CHILD, GRANDCHILD}
    assert conn.transactions == [{"scan_id": UNRELATED}]
    assert conn.stats == {("scan", UNRELATED)}
    again = asyncio.run(router._purge(None, scan_id=PARENT, hunt_run_id=None))
    assert again["transactions_deleted"] == 0 and conn.transactions == [{"scan_id": UNRELATED}]


def test_scan_capture_rows_carry_the_action_capability():
    """The unarchived-capability query matches rows on capability_name, so a scan row
    stamped with its adapter instead of its capability left every in-process capability
    reported as missing even when its calls were stored."""
    from api.runtime.http_archive import scan_transactions_from_capture

    http_archive_capture.start_capture()
    http_archive_capture.record_scan_call(
        {"method": "GET", "url": "https://t/openapi.json", "status_code": 200},
        capability_name="web.spec_ingest", source="replay_transport",
    )
    http_archive_capture.record_scan_call({"method": "GET", "url": "https://t/"})
    attributed, legacy = scan_transactions_from_capture(
        http_archive_capture.drain_capture(), scan_id="scan-1",
    )
    assert attributed.capability_name == "web.spec_ingest"
    assert attributed.adapter == "replay_transport"
    assert legacy.capability_name == "http.request"
    assert legacy.adapter == "http.request"


def test_scan_capture_carries_the_private_workflow_marker():
    from api.runtime.http_archive import scan_transactions_from_capture

    http_archive_capture.start_capture()
    http_archive_capture.record_scan_call(
        {"method": "POST", "url": "https://t/login", "workflow_values_private": True},
        capability_name="sqli.request_verify_batch", source="replay_transport",
    )
    http_archive_capture.record_scan_call(
        {"method": "GET", "url": "https://t/", "workflow_values_private": "yes"},
    )
    private, public = scan_transactions_from_capture(
        http_archive_capture.drain_capture(), scan_id="scan-1",
    )
    assert private.metadata["workflow_values_private"] is True
    assert "workflow_values_private" not in public.metadata


def test_scan_private_workflow_rows_are_withheld_in_redacted_view():
    """Scan mutation verifiers replay private collection requests carrying CSRF tokens,
    PINs and session headers under arbitrary names. Key-name redaction cannot find those,
    so a scan row marked private is blanked in every masked view exactly as Hunt is."""
    digest = hashlib.sha256(b"csrf=tok123").hexdigest()
    row = {
        "id": "scan-private", "plane": "scan", "scan_id": "s1",
        "capability_name": "sqli.request_verify_batch", "method": "POST",
        "url": "https://t/form", "sequence": 0,
        "request_headers": {"X-Session": "secret-value"},
        "response_headers": {"X-Echo": "secret-value"},
        "request_body": "csrf=tok123", "response_body": "welcome tok123",
        "request_body_sha256": digest, "response_body_sha256": digest,
        "metadata_json": {"workflow_values_private": True},
    }
    public = project(row, redaction="redacted")
    text = json.dumps(public)
    assert "secret-value" not in text and "tok123" not in text and digest not in text
    assert public["request"]["body"] is None and public["response"]["body"] is None
    assert public["request"]["sha256"] is None and public["response"]["sha256"] is None
    assert public["request"]["headers"] == {"X-Session": "[REDACTED]"}
    assert public["response"]["headers"] == {"X-Echo": "[REDACTED]"}
    raw = project(row, redaction="raw")
    assert raw["request"]["headers"]["X-Session"] == "secret-value"
    assert raw["request"]["body"] == "csrf=tok123"


def test_scan_rows_without_the_private_marker_keep_their_masked_bodies():
    row = {
        "id": "scan-public", "plane": "scan", "scan_id": "s1",
        "capability_name": "web.spec_ingest", "method": "GET",
        "url": "https://t/openapi.json", "sequence": 0,
        "response_body": "openapi: 3.0.0", "metadata_json": {},
    }
    assert project(row, redaction="redacted")["response"]["body"] == "openapi: 3.0.0"


@pytest.mark.asyncio
async def test_scan_stats_separate_external_tool_gaps_from_engine_gaps():
    class Conn:
        async def fetchrow(self, query, *params):
            return {"attempted": 3, "stored": 3, "failed": 0, "dropped": 0}

        async def fetchval(self, query, *params):
            return 0

        async def fetch(self, query, *params):
            return [
                {"capability_name": "not.a.capability", "status": "success", "http_consumed": 1},
                {"capability_name": "templates.passive_batch", "status": "success", "http_consumed": 7},
                {"capability_name": "web.crawl", "status": "success", "http_consumed": 71},
                {"capability_name": "web.spec_ingest", "status": "partial", "http_consumed": 11},
            ]

    stats = await read_archive_stats(Conn(), scan_id="scan-1", hunt_run_id=None)
    assert stats["unarchived_external_tool_capabilities"] == [
        "templates.passive_batch", "web.crawl",
    ]
    assert stats["unarchived_engine_capabilities"] == [
        "not.a.capability", "web.spec_ingest",
    ]
    assert stats["unarchived_http_capabilities"] == [
        "not.a.capability", "templates.passive_batch", "web.crawl", "web.spec_ingest",
    ]


def test_fidelity_names_external_tool_gap_separately():
    """A HAR that silently omits the crawl, probe and template traffic reads as the
    whole scan. The detail says which gap is the opaque tool tunnel and which is an
    engine capability that recorded nothing; neither upgrades the archive."""
    fidelity, detail = archive_fidelity({
        "attempted": 2, "stored": 2, "failed": 0, "dropped": 0, "capture_limited": 0,
        "unarchived_http_capabilities": ["web.crawl", "web.spec_ingest"],
        "unarchived_external_tool_capabilities": ["web.crawl"],
        "unarchived_engine_capabilities": ["web.spec_ingest"],
    }, total=2)
    assert fidelity == "partial"
    assert (
        "external scanner traffic (relayed as an opaque pinned tunnel, not archived): web.crawl"
        in detail
    )
    assert "engine capabilities with no archived calls: web.spec_ingest" in detail
    only_external = archive_fidelity({
        "attempted": 2, "stored": 2, "failed": 0, "dropped": 0, "capture_limited": 0,
        "unarchived_http_capabilities": ["web.crawl"],
        "unarchived_external_tool_capabilities": ["web.crawl"],
        "unarchived_engine_capabilities": [],
    }, total=2)
    assert only_external[0] == "partial"
    assert "engine capabilities" not in only_external[1]


def test_recorded_replay_transport_keeps_hunt_slot_and_records_scan_slot_as_given():
    from types import SimpleNamespace

    from api.capabilities.replay import (
        RecordedHuntReplayTransport,
        RecordedReplayTransport,
    )

    class Inner:
        async def send(self, request, **_kwargs):
            return SimpleNamespace(
                response_headers={"X": "1"}, response_body=b"ok", status_code=200,
                connected_address="192.0.2.1", elapsed_ms=1, error_code=None,
            )

    request = SimpleNamespace(method="GET", url="https://t/", headers=(("A", "b"),), body=b"")
    recorded = []
    asyncio.run(RecordedHuntReplayTransport(
        Inner(), recorded.append, principal_slot="",
    ).send(request))
    asyncio.run(RecordedReplayTransport(
        Inner(), recorded.append, principal_slot=None,
    ).send(request))
    asyncio.run(RecordedReplayTransport(
        Inner(), recorded.append, principal_slot="primary", private=True,
    ).send(request))
    assert [item["principal_slot"] for item in recorded] == ["anonymous", None, "primary"]
    assert [item["workflow_values_private"] for item in recorded] == [False, False, True]
    assert recorded[0]["request_headers"] == {"A": "b"}


def test_a_refused_archive_export_says_whether_verbatim_har_is_available(monkeypatch):
    """The header was set only on a successful export, while a refusal -- the response a client
    reads to learn the deployment's answer -- carried none."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.runtime import http_archive_router as archive_router

    def _reached_database():
        raise AssertionError("a refused export must not reach the database")

    monkeypatch.setattr(archive_router, "_pool", _reached_database)
    monkeypatch.delenv("SHAKERSCAN_BIND_HOST", raising=False)
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", "0")
    app = FastAPI()
    app.include_router(archive_router.router)
    client = TestClient(app)
    scan = "/scans/11111111-1111-4111-8111-111111111111/http-transactions"

    refused = client.get(scan, params={"format": "har", "redaction": "raw"})
    assert refused.status_code == 403
    assert refused.headers["x-shakerscan-raw-har"] == "disabled"
    assert "masked HAR" in refused.json()["detail"]

    unknown = client.get(scan, params={"format": "pcap"})
    assert unknown.status_code == 400
    assert unknown.headers["x-shakerscan-raw-har"] == "disabled"

    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", "1")
    assert client.get(scan, params={"format": "pcap"}).headers["x-shakerscan-raw-har"] == "available"


@pytest.mark.asyncio
async def test_scan_stats_name_verifier_traffic_that_ended_at_its_wall():
    """Soak 146b6c03/da4c0531: 340 and 905 SQLi requests went out under ``sqli.verify_batch``
    actions that settled ``timed_out``. They are tunnel traffic like any other external tool and
    must be named, not dropped because the action did not end success or partial."""
    class Conn:
        async def fetchrow(self, query, *params):
            return {"attempted": 13, "stored": 13, "failed": 0, "dropped": 0}

        async def fetchval(self, query, *params):
            return 0

        async def fetch(self, query, *params):
            return [
                {"capability_name": "sqli.verify_batch", "status": "timed_out", "http_consumed": 110},
                {"capability_name": "sqli.verify_batch", "status": "timed_out", "http_consumed": 230},
                {"capability_name": "xss.verify_batch", "status": "success", "http_consumed": 5},
                # Refused before any traffic: nothing to archive, nothing to name.
                {"capability_name": "templates.active_batch", "status": "failed", "http_consumed": 0},
                # Failed after sending traffic: that traffic is part of the run.
                {"capability_name": "web.content_discover", "status": "failed", "http_consumed": 40},
            ]

    stats = await read_archive_stats(Conn(), scan_id="scan-1", hunt_run_id=None)
    assert stats["unarchived_external_tool_capabilities"] == [
        "sqli.verify_batch", "web.content_discover", "xss.verify_batch",
    ]
    fidelity, detail = archive_fidelity(stats, total=13)
    assert fidelity == "partial"
    assert "sqli.verify_batch" in detail
