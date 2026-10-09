"""Masked archive exports are bounded, honest about what they leave out, and never stall the loop.

External release audit, 2026-10-09 (R2), and its review: the async archive endpoints built the
export on the event loop, and even on a thread the regex engine holds the interpreter lock for a
whole pass, so an 8 M-character body stalled the loop for 0.6-1.3 s. Bodies are now decoded,
masked and encoded in a worker process pool, the response is rendered from those bytes, exports
are admitted before any row is read, and a masked export holds at most a configured number of
encoded body bytes. A body left out is listed under ``payload_omitted`` with its reason, carries
no digest, lowers the fidelity, and is never shown unmasked. The canaries are test fixtures.
"""

from __future__ import annotations

import asyncio
import json
import time
from concurrent.futures.process import BrokenProcessPool
from contextlib import asynccontextmanager

import pytest

from api.runtime import archive_body_masking as masking
from api.runtime import archive_export_worker as worker
from api.runtime import http_archive_reader as reader
from api.runtime import http_archive_router as archive_router
from api.runtime.archive_body_masking import withhold_body_secrets

CANARY = "BoundsCanaryR2x7Kq"
MIB = 1024 * 1024


def _row(index: int, body, **extra) -> dict:
    return {
        "id": f"row-{index}", "sequence": index, "plane": "scan", "capability_name": "web.spec_ingest",
        "method": "GET", "url": "https://example.test/spec.yaml", "status_code": 200,
        "request_headers": {}, "response_headers": {}, "request_body": None, "response_body": body,
        "response_body_sha256": f"sha-{index}", "response_body_bytes": len(body) if isinstance(body, str) else 0,
        **extra,
    }


_ARGUMENTS = {"export_format": "transactions", "redaction": "redacted", "owner": {"scan_id": "s"}}
_COMPLETE = {"attempted": 1, "stored": 1}


def _pooled(rows, **arguments) -> reader.EncodedExport:
    return asyncio.run(reader.build_export(rows, **{**_ARGUMENTS, "total": len(rows), **arguments}))


def _budget(monkeypatch, size: int) -> None:
    monkeypatch.setattr(reader, "MIN_MASKED_EXPORT_BYTES", 1)
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES", str(size))


# --- The masking limit -------------------------------------------------------------------------


def test_a_body_at_the_masking_limit_is_masked_and_one_past_it_is_withheld(monkeypatch):
    monkeypatch.setattr(masking, "MAX_MASKED_BODY_CHARS", 4_096)
    head = f"- name: api_key\n  example: {CANARY}\n"
    at_limit = head + "x" * (4_096 - len(head))
    assert len(at_limit) == 4_096
    masked = withhold_body_secrets(at_limit)
    assert CANARY not in masked
    assert masked.startswith("- name: api_key")

    past_limit = at_limit + "x"
    withheld = withhold_body_secrets(past_limit)
    assert CANARY not in withheld
    assert withheld == masking.withheld_body_notice(4_097)
    # Bytes and decoded JSON objects meet the same limit.
    assert CANARY not in withhold_body_secrets(past_limit.encode())
    assert CANARY not in withhold_body_secrets({"api_key": CANARY, "pad": "x" * 4_096})


def test_an_export_omits_a_body_over_the_masking_limit_without_its_digest(monkeypatch):
    for module in (worker, reader):
        monkeypatch.setattr(module, "MAX_MASKED_BODY_CHARS", 4_096)
    near = f"- name: api_key\n  example: {CANARY}\n" + "x" * 4_000
    over = near + "y" * 200
    # A stored JSON object whose text is under the limit only once decoded is judged decoded.
    spread = json.dumps({"api_key": CANARY, "pad": "z" * 4_200}, indent=1)
    rows = [_row(0, near), _row(1, over), _row(2, spread)]
    document = reader.export_document(rows, **_ARGUMENTS, total=3, stats={"attempted": 3, "stored": 3})
    near_item, over_item, spread_item = document["transactions"]
    assert near_item["response"]["body"] and CANARY not in near_item["response"]["body"]
    assert near_item["payload_omitted"] == []
    for item in (over_item, spread_item):
        assert item["response"]["body"] is None
        assert item["response"]["sha256"] is None  # nothing reads as present
        assert item["payload_omitted"] == ["response_body"]
        assert item["payload_omitted_reasons"] == {"response_body": "over_masking_limit"}
    assert document["fidelity"] == "partial"
    assert "2 recorded call(s) have a body over the 4096-character masking limit" in document["fidelity_detail"]
    assert CANARY not in json.dumps(document)


# --- The byte budget ---------------------------------------------------------------------------


def test_the_budget_parses_and_clamps(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES", raising=False)
    assert reader.masked_export_budget() == reader.DEFAULT_MASKED_EXPORT_BYTES == 32 * MIB
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES", "not-a-number")
    assert reader.masked_export_budget() == 32 * MIB
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES", "1")
    assert reader.masked_export_budget() == reader.MIN_MASKED_EXPORT_BYTES
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES", str(10**12))
    assert reader.masked_export_budget() == reader.MAX_MASKED_EXPORT_BYTES
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES", str(8 * MIB))
    assert reader.masked_export_budget() == 8 * MIB
    assert reader.export_read_budget("redacted") == 8 * MIB
    assert reader.export_read_budget("raw") == reader.MAX_EXTERNAL_PAYLOAD_BYTES


def _wide_rows():
    return [
        _row(0, f"- name: api_key\n  example: {CANARY}\n" + "a" * 300_000),  # ~300 KB encoded
        _row(1, "\U0001F600" * 100_000),  # 100 K characters, 400 KB of UTF-8
        _row(2, "\x01" * 100_000),  # 100 K characters, 600 KB as JSON escapes
        _row(3, "small body"),
    ]


def _encoded_body_bytes(document) -> int:
    return sum(
        len(json.dumps(item["response"]["body"], ensure_ascii=False).encode())
        for item in document["transactions"] if item["response"]["body"] is not None
    )


def test_the_budget_counts_encoded_bytes_not_characters(monkeypatch):
    _budget(monkeypatch, 1 * MIB)
    document = reader.export_document(_wide_rows(), **_ARGUMENTS, total=4, stats={"attempted": 4, "stored": 4})
    reasons = [item["payload_omitted_reasons"] for item in document["transactions"]]
    # 300 KB + 400 KB fit; the escaped body (600 KB encoded, 100 K characters) does not, and
    # every body after it is left out too.
    assert reasons == [{}, {}, {"response_body": "masking_budget"}, {"response_body": "masking_budget"}]
    assert _encoded_body_bytes(document) <= 1 * MIB
    assert document["transactions"][2]["response"]["sha256"] is None
    assert "2 recorded call(s) have bodies left out because this masked export reached its masking budget" \
        in document["fidelity_detail"]
    assert "externally stored" not in document["fidelity_detail"]
    assert CANARY not in json.dumps(document)


def test_the_worker_pool_and_the_in_process_export_agree(monkeypatch):
    _budget(monkeypatch, 1 * MIB)
    rows = _wide_rows() + [
        _row(4, json.dumps({"password": CANARY, "items": [1, 2]})),
        _row(5, f"<input name=\"password\" value=\"{CANARY}\">".encode()),
    ]
    for export_format in ("transactions", "har"):
        arguments = {**_ARGUMENTS, "export_format": export_format, "total": len(rows), "stats": _COMPLETE}
        in_process = reader.export_document(rows, **arguments)
        pooled = asyncio.run(reader.build_export(rows, **arguments))
        assert json.loads(pooled.render()) == json.loads(json.dumps(in_process))
        assert pooled.materialize() == in_process
        assert len(pooled.render()) < 1 * MIB + 64 * 1024  # the bodies plus a small envelope
    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES")
    raw = {**_ARGUMENTS, "redaction": "raw", "total": len(rows)}
    assert json.loads(_pooled(rows, **raw).render()) == reader.export_document(rows, **raw)


def test_a_raw_export_spends_no_masking_budget(monkeypatch):
    _budget(monkeypatch, 10)
    rows = [_row(0, "plain body well past ten characters")]
    document = reader.export_document(rows, **{**_ARGUMENTS, "redaction": "raw"}, total=1)
    assert document["transactions"][0]["response"]["body"] == "plain body well past ten characters"
    assert document["transactions"][0]["payload_omitted"] == []


def test_external_and_budget_omissions_are_reported_separately_and_in_the_har(monkeypatch):
    _budget(monkeypatch, 100)
    rows = [
        _row(0, "x" * 80),
        _row(1, "y" * 80),
        {**_row(2, "z"), "response_body": None, "payload_omitted": ["response_body"]},
    ]
    document = reader.export_document(rows, **_ARGUMENTS, total=3, stats={"attempted": 3, "stored": 3})
    reasons = [item["payload_omitted_reasons"] for item in document["transactions"]]
    assert reasons == [{}, {"response_body": "masking_budget"}, {"response_body": "external_read_budget"}]
    detail = document["fidelity_detail"]
    assert "1 recorded call(s) have externally stored payloads omitted from this export" in detail
    assert "1 recorded call(s) have bodies left out because this masked export reached its masking budget" in detail
    # The external omission keeps its recorded digest; a masking omission does not.
    assert document["transactions"][2]["response"]["sha256"] == "sha-2"
    assert document["transactions"][1]["response"]["sha256"] is None

    har = reader.export_document(rows, **{**_ARGUMENTS, "export_format": "har"}, total=3, stats=_COMPLETE)
    comments = [entry["comment"] for entry in har["log"]["entries"]]
    assert comments[0] == ""
    assert comments[1] == "response body omitted: beyond this export's masking budget"
    assert comments[2] == "response body omitted: stored externally beyond this export's read budget"
    assert "text" not in har["log"]["entries"][1]["response"]["content"]


def test_a_body_the_worker_cannot_mask_is_withheld(monkeypatch):
    def out_of_memory(_value):
        raise MemoryError

    monkeypatch.setattr(worker, "masked_body_text", out_of_memory)
    assert worker.encode_body(f"password={CANARY}", True) == (None, worker.MASKING_FAILED)
    document = reader.export_document([_row(0, f"password={CANARY}")], **_ARGUMENTS, total=1)
    item = document["transactions"][0]
    assert item["response"]["body"] is None
    assert item["payload_omitted_reasons"] == {"response_body": "masking_failed"}
    assert "could not be masked" in document["fidelity_detail"]


# --- Off the event loop ------------------------------------------------------------------------


def test_the_event_loop_keeps_serving_while_a_hostile_export_is_masked():
    rows = [
        _row(0, '<input name="password" value="' * (4_000_000 // 31)),
        _row(1, "token " * (4_000_000 // 6)),
        _row(2, "name: api_key\n" * 200_000 + f"- name: api_key\n  example: {CANARY}\n"),
    ]

    async def scenario():
        await reader.build_export([_row(9, "warm")], **_ARGUMENTS, total=1)  # workers started
        gaps: list[float] = []
        done = False

        async def ticker():
            last = time.perf_counter()
            while not done:
                await asyncio.sleep(0.001)
                now = time.perf_counter()
                gaps.append(now - last)
                last = now

        counting = asyncio.create_task(ticker())
        encoded = await reader.build_export(rows, **_ARGUMENTS, total=3)
        content = encoded.render()
        done = True
        await counting
        return content, gaps

    content, gaps = asyncio.run(scenario())
    assert CANARY.encode() not in content
    assert len(gaps) > 10
    # Masked on the loop (or a thread), bodies like these stalled it for most of a second.
    assert max(gaps) < 0.1, max(gaps)


def test_a_stopped_worker_pool_refuses_the_export(monkeypatch):
    class Broken:
        def submit(self, *args, **kwargs):
            raise BrokenProcessPool("stopped")

        def shutdown(self, **kwargs):
            pass

    monkeypatch.setattr(reader, "_body_pool", Broken())
    with pytest.raises(reader.ExportUnavailable):
        _pooled([_row(0, f"password={CANARY}")])
    assert reader._body_pool is None  # a fresh pool is started next time


# --- Admission ---------------------------------------------------------------------------------


def test_exports_past_the_slots_are_refused_after_a_short_wait():
    async def scenario():
        holders_ready = asyncio.Event()
        release = asyncio.Event()
        entered = 0

        async def hold():
            nonlocal entered
            async with reader.export_admission():
                entered += 1
                if entered == reader.MAX_CONCURRENT_EXPORT_BUILDS:
                    holders_ready.set()
                await release.wait()

        holders = [asyncio.create_task(hold()) for _ in range(reader.MAX_CONCURRENT_EXPORT_BUILDS)]
        await holders_ready.wait()
        with pytest.raises(reader.ExportBusy):
            async with reader.export_admission(wait_seconds=0.05):
                pass
        release.set()
        await asyncio.gather(*holders)
        async with reader.export_admission(wait_seconds=0.05):
            return "admitted again"

    assert asyncio.run(scenario()) == "admitted again"


def test_a_refused_export_is_a_503_with_retry_after_and_reads_no_rows(monkeypatch):
    from fastapi import HTTPException

    reads = []

    @asynccontextmanager
    async def busy(wait_seconds=None):
        raise archive_router.ExportBusy("busy")
        yield  # pragma: no cover

    class _Pool:
        def acquire(self):
            reads.append("acquire")
            raise AssertionError("no row may be read without an export slot")

    monkeypatch.setattr(archive_router, "export_admission", busy)
    monkeypatch.setattr(archive_router, "_pool", lambda: _Pool())
    with pytest.raises(HTTPException) as refused:
        asyncio.run(archive_router._export(
            request=object(), scan_id="11111111-1111-4111-8111-111111111111", hunt_run_id=None,
            export_format="transactions", redaction="redacted", method=None, status_code=None,
            search=None, limit=10, offset=0,
        ))
    assert refused.value.status_code == 503
    assert refused.value.headers["Retry-After"] == str(archive_router.EXPORT_RETRY_AFTER_SECONDS)
    assert "x-shakerscan-raw-har" in refused.value.headers
    assert reads == []


def test_the_route_reads_external_payloads_within_the_masking_budget(monkeypatch):
    _budget(monkeypatch, 3 * MIB)
    seen = {}

    @asynccontextmanager
    async def acquire():
        yield object()

    class _Pool:
        def acquire(self):
            return acquire()

    async def _ids(conn, scan_id):
        return (scan_id,)

    async def _count(conn, **kwargs):
        return 1

    async def _stats(conn, **kwargs):
        return {}

    async def _rows(conn, **kwargs):
        seen.update(kwargs)
        return [_row(0, f"password={CANARY}")]

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
    assert seen["external_payload_budget"] == 3 * MIB
    assert response.media_type == "application/json"
    assert CANARY not in response.body.decode()
    assert json.loads(response.body)["transactions"][0]["response"]["body"] == "password=***"
