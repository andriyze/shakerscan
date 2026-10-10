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
    assert reader.export_read_budget("redacted") == 8 * MIB + reader.MAX_EXPORT_HEADER_BYTES
    assert reader.export_read_budget("redacted", light=True) == \
        reader.LIGHT_EXPORT_BODY_BYTES + reader.LIGHT_EXPORT_HEADER_BYTES
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
    # A masked export carries no raw body digest, whether the body was shown, masked or omitted.
    assert [item["response"]["sha256"] for item in document["transactions"]] == [None, None, None]

    har = reader.export_document(rows, **{**_ARGUMENTS, "export_format": "har"}, total=3, stats=_COMPLETE)
    comments = [entry["comment"] for entry in har["log"]["entries"]]
    assert comments[0] == ""
    assert comments[1] == "response body omitted: beyond this export's masking budget"
    assert comments[2] == "response body omitted: stored externally beyond this export's read budget"
    assert "text" not in har["log"]["entries"][1]["response"]["content"]


@pytest.mark.parametrize("failure", [MemoryError, RecursionError, ValueError, UnicodeError])
def test_a_body_the_worker_cannot_mask_is_withheld_and_never_quoted(monkeypatch, caplog, failure):
    def fails(value):
        raise failure(f"cannot mask {value}")  # an exception message can quote the body

    monkeypatch.setattr(worker, "masked_body_text", fails)
    assert worker.encode_body(f"password={CANARY}", True) == (None, worker.MASKING_FAILED)
    rows = [_row(0, f"password={CANARY}"), _row(1, "next body")]
    document = reader.export_document(rows, **_ARGUMENTS, total=2)
    first, second = document["transactions"]
    assert first["response"]["body"] is None and first["response"]["sha256"] is None
    assert first["payload_omitted_reasons"] == {"response_body": "masking_failed"}
    assert second["payload_omitted_reasons"] == {"response_body": "masking_failed"}  # same stub
    assert "could not be masked" in document["fidelity_detail"]
    assert CANARY not in json.dumps(document) and CANARY not in caplog.text


def test_one_hostile_body_does_not_fail_the_export():
    deep = "[" * 200_000 + "]" * 200_000  # json.loads raises RecursionError on this
    rows = [_row(0, deep), _row(1, f"password={CANARY}"), _row(2, b"\xff\xfe password=" + CANARY.encode())]
    for export_format in ("transactions", "har"):
        encoded = _pooled(rows, export_format=export_format)
        content = encoded.render()
        assert CANARY.encode() not in content
        assert json.loads(content.decode("utf-8"))
    document = reader.export_document(rows, **_ARGUMENTS, total=3)
    assert document["transactions"][0]["response"]["body"].startswith("[[[")
    assert document["transactions"][1]["response"]["body"] == "password=***"


def _assert_well_formed(value) -> None:
    """Every string in a parsed export encodes as UTF-8 (no lone surrogate survived)."""
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, dict):
        for key, item in value.items():
            _assert_well_formed(key)
            _assert_well_formed(item)
    elif isinstance(value, list):
        for item in value:
            _assert_well_formed(item)


def test_the_export_is_strict_utf8_json_with_lone_surrogates_anywhere():
    lone = "\ud800"
    rows = [
        _row(0, '{"a":"\\ud800","password":"' + CANARY + '"}'),  # decodes to a lone surrogate
        _row(1, f"x{lone}y password={CANARY}"),
        {**_row(2, "body"), "url": f"https://example.test/{lone}", "response_headers": {"x-weird": f"a{lone}b"}},
    ]
    for redaction in ("redacted", "raw"):
        for export_format in ("transactions", "har"):
            arguments = {**_ARGUMENTS, "redaction": redaction, "export_format": export_format, "total": 3}
            content = asyncio.run(reader.build_export(rows, **arguments)).render()
            text = content.decode("utf-8")  # strict: raises on surrogates
            _assert_well_formed(json.loads(text))
            if redaction == "redacted":
                assert CANARY not in text
    document = reader.export_document(rows, **_ARGUMENTS, total=3)
    assert "\ufffd" in document["transactions"][1]["response"]["body"]


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

    monkeypatch.setattr(reader, "_payload_pool", Broken())
    with pytest.raises(reader.ExportUnavailable):
        _pooled([_row(0, f"password={CANARY}")])
    assert reader._payload_pool is None  # a fresh pool is started next time


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
    async def busy(*args, **kwargs):
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
        search=None, limit=1_000, offset=0,
    ))
    assert seen["external_payload_budget"] == 3 * MIB + reader.MAX_EXPORT_HEADER_BYTES
    assert response.media_type == "application/json"
    assert CANARY not in response.body.decode()
    assert json.loads(response.body)["transactions"][0]["response"]["body"] == "password=***"


def test_a_caller_holds_at_most_two_heavy_slots_and_browsing_is_never_held_up():
    async def scenario():
        release = asyncio.Event()
        holding: list[str] = []

        async def hold(caller):
            async with reader.export_admission(caller):
                holding.append(caller)
                await release.wait()

        holders = [asyncio.create_task(hold("198.51.100.7")) for _ in range(reader.MAX_EXPORTS_PER_CALLER)]
        while len(holding) < reader.MAX_EXPORTS_PER_CALLER:
            await asyncio.sleep(0)
        # The same caller's third download waits, then is refused, though a slot is free...
        with pytest.raises(reader.ExportBusy):
            async with reader.export_admission("198.51.100.7", wait_seconds=0.05):
                pass
        # ...another caller still gets that slot at once, and with every heavy slot taken, a
        # browse page of either caller is admitted.
        async with (
            reader.export_admission("203.0.113.9", wait_seconds=0.05),
            reader.export_admission("198.51.100.7", wait_seconds=0.05, light=True),
        ):
            pass
        release.set()
        await asyncio.gather(*holders)
        async with reader.export_admission("198.51.100.7", wait_seconds=0.05):
            return "admitted again"

    assert asyncio.run(scenario()) == "admitted again"


def test_only_small_json_pages_are_browse_pages():
    assert reader.is_light_export("transactions", 25, redaction="redacted")
    assert reader.is_light_export("transactions", reader.LIGHT_EXPORT_ROWS, redaction="redacted")
    assert not reader.is_light_export("transactions", reader.LIGHT_EXPORT_ROWS + 1, redaction="redacted")
    assert not reader.is_light_export("transactions", 1_000, redaction="redacted")
    assert not reader.is_light_export("har", 25, redaction="redacted")
    # A raw export has no body budget: never a browse page, however small.
    assert not reader.is_light_export("transactions", 25, redaction="raw")
    assert not reader.is_light_export("har", 25, redaction="raw")


@pytest.mark.parametrize("redaction, light", [("redacted", True), ("raw", False)])
def test_a_raw_page_takes_a_heavy_slot_and_its_caller_limit(monkeypatch, redaction, light):
    taken = []

    @asynccontextmanager
    async def admission(caller=None, wait_seconds=None, *, light=False):
        taken.append((caller, light))
        yield

    async def build(**kwargs):
        taken.append(("budgets", kwargs["light"]))
        return b"{}", 0

    monkeypatch.setattr(archive_router, "export_admission", admission)
    monkeypatch.setattr(archive_router, "_build_export_bytes", build)
    monkeypatch.setattr(archive_router, "_authorize_raw", lambda request: None)

    class Request:
        client = type("Client", (), {"host": "198.51.100.7"})()
        headers = None

    asyncio.run(archive_router._export(
        request=Request(), scan_id="11111111-1111-4111-8111-111111111111", hunt_run_id=None,
        export_format="transactions", redaction=redaction, method=None, status_code=None,
        search=None, limit=25, offset=0,
    ))
    assert taken == [("198.51.100.7", light), ("budgets", light)]


def test_the_caller_is_the_peer_or_the_trusted_gateways_forwarded_address(monkeypatch):
    class Request:
        def __init__(self, headers):
            self.client = type("Client", (), {"host": "10.0.0.5"})()
            self.headers = headers

    monkeypatch.setenv("FLEET_GATEWAY_PROXY_SECRET", "gateway-fixture-secret")
    forwarded = {"x-forwarded-for": "192.0.2.1, 198.51.100.7"}
    assert archive_router.export_caller(Request(forwarded)) == "10.0.0.5"  # not from the gateway
    trusted = {**forwarded, "x-shakerscan-gateway-secret": "gateway-fixture-secret"}
    assert archive_router.export_caller(Request(trusted)) == "198.51.100.7"  # right-most only
    junk = {"x-forwarded-for": "not-an-ip", "x-shakerscan-gateway-secret": "gateway-fixture-secret"}
    assert archive_router.export_caller(Request(junk)) == "10.0.0.5"


# --- Bodies read a batch at a time -------------------------------------------------------------


def _lazy_row(index: int, size: int, **extra) -> dict:
    row = _row(index, "")
    row.update(response_body=None, request_body=None, **{reader.LAZY_PAYLOADS: {"response_body": size}}, **extra)
    return row


def test_bodies_are_read_in_bounded_batches_and_never_past_the_budget(monkeypatch):
    _budget(monkeypatch, 3 * MIB)
    monkeypatch.setattr(reader, "EXPORT_BATCH_BYTES", 2 * MIB)
    body = "lorem ipsum " * (MIB // 12)  # ~1 MiB
    rows = [_lazy_row(index, len(body)) for index in range(8)]
    reads: list[list[str]] = []

    async def read_bodies(ids, budget):
        reads.append([str(item) for item in ids])
        return {str(item): {"response_body": body, "request_body": None, "unavailable": set(), "omitted": set()}
                for item in ids}, 0

    encoded = asyncio.run(reader.build_export(rows, **_ARGUMENTS, total=8, stats=_COMPLETE, read_payloads=read_bodies))
    document = encoded.materialize()
    shown = [item["response"]["body"] is not None for item in document["transactions"]]
    assert shown == [True, True, True, False, False, False, False, False]  # 3 x ~1 MiB fit in 3 MiB
    assert all(len(batch) <= 2 for batch in reads)  # 2 MiB of stored body per read
    read = {row_id for batch in reads for row_id in batch}
    # A batch is chosen before its own bodies are charged, so the body after the last that fits
    # may be read; nothing beyond that batch is read at all.
    assert read <= {"row-0", "row-1", "row-2", "row-3"}
    assert {item["payload_omitted_reasons"].get("response_body") for item in document["transactions"][3:]} \
        == {"masking_budget"}


def test_a_lazily_read_body_gets_the_legacy_decoding_and_its_read_outcome(monkeypatch):
    legacy = repr(f"password={CANARY}".encode())  # stored by the old writer as b'...'
    rows = [
        _lazy_row(0, len(legacy)),
        _lazy_row(1, 10),
        _lazy_row(2, 10),
        _lazy_row(3, 10),
    ]

    async def read_bodies(ids, budget):
        return {
            "row-0": {"response_body": legacy, "request_body": None, "unavailable": set(), "omitted": set()},
            "row-1": {"response_body": None, "request_body": None, "unavailable": {"response_body"}, "omitted": set()},
            "row-2": {"response_body": None, "request_body": None, "unavailable": set(), "omitted": {"response_body"}},
        }, 0  # row-3 was purged between the reads

    document = asyncio.run(reader.build_export(
        rows, **_ARGUMENTS, total=4, stats={"attempted": 4, "stored": 4}, read_payloads=read_bodies,
    )).materialize()
    first, second, third, fourth = document["transactions"]
    assert first["response"]["body"] == "password=***"
    assert second["payload_unavailable"] == ["response_body"] and second["payload_omitted"] == []
    assert third["payload_omitted_reasons"] == {"response_body": "external_read_budget"}
    assert fourth["payload_unavailable"] == ["response_body"]
    assert "payloads that are unavailable" in document["fidelity_detail"]
    assert CANARY not in json.dumps(document)


def test_the_route_reads_rows_without_bodies(monkeypatch):
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
        return [_lazy_row(0, 30)]

    async def _bodies(conn, ids, **kwargs):
        seen["body_ids"] = [str(item) for item in ids]
        seen["owner"] = (kwargs.get("scan_id"), kwargs.get("scan_ids"), kwargs.get("hunt_run_id"))
        return {"row-0": {"response_body": f"password={CANARY}", "request_body": None,
                          "unavailable": set(), "omitted": set()}}, 0

    for name, value in (("_pool", lambda: _Pool()), ("_scan_archive_ids", _ids), ("count_transactions", _count),
                        ("read_archive_stats", _stats), ("read_transactions", _rows),
                        ("read_transaction_payloads", _bodies)):
        monkeypatch.setattr(archive_router, name, value)
    response = asyncio.run(archive_router._export(
        request=object(), scan_id="11111111-1111-4111-8111-111111111111", hunt_run_id=None,
        export_format="transactions", redaction="redacted", method=None, status_code=None,
        search=None, limit=10, offset=0,
    ))
    assert seen["payloads"] is False and seen["body_ids"] == ["row-0"]
    scan = "11111111-1111-4111-8111-111111111111"
    assert seen["owner"] == (scan, (scan,), None)  # payloads are read for this scan only
    assert json.loads(response.body)["transactions"][0]["response"]["body"] == "password=***"


_NO_MAIN_SCRIPT = r"""
import asyncio, os
print("MAIN RAN", flush=True)  # no __main__ guard on purpose: a worker must not run this
from api.runtime import http_archive_reader as reader

async def main():
    rows = [{"id": f"r{i}", "sequence": i, "plane": "scan", "method": "GET", "url": "https://e.test/",
             "status_code": 200, "request_headers": {}, "response_headers": {}, "request_body": None,
             "response_body": "password=x"} for i in range(4)]
    print(reader.EncodedExport.render(await reader.build_export(
        rows, export_format="transactions", redaction="redacted", owner={}, total=4)).count(b"***"), flush=True)

if __name__ == "__main__":
    asyncio.run(main())
"""


def test_masking_workers_do_not_rerun_the_launching_script(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    script = tmp_path / "launcher.py"
    script.write_text(_NO_MAIN_SCRIPT)
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join(str(repo / part) for part in ("", "api", "scanner"))}
    completed = subprocess.run(
        [sys.executable, str(script)], cwd=tmp_path, env=environment,
        capture_output=True, text=True, timeout=120, check=True,
    )
    assert completed.stdout.splitlines() == ["MAIN RAN", "4"]


# --- Headers are budgeted and redacted in the workers -------------------------------------------


def test_headers_past_the_header_budget_are_withheld(monkeypatch):
    monkeypatch.setattr(reader, "MAX_EXPORT_HEADER_BYTES", 2_000)
    big = {"x-pad": "p" * 900, "authorization": f"Bearer {CANARY}"}
    rows = [{**_row(index, "body"), "response_headers": big} for index in range(4)]
    for redaction in ("redacted", "raw"):
        document = reader.export_document(
            rows, **{**_ARGUMENTS, "redaction": redaction}, total=4, stats={"attempted": 4, "stored": 4},
        )
        items = document["transactions"]
        assert [bool(item["response"]["headers"]) for item in items] == [True, True, False, False]
        assert [item["payload_omitted_reasons"] for item in items[2:]] == [{"response_headers": "header_budget"}] * 2
        assert "headers left out because this export reached its header budget" in document["fidelity_detail"]
        if redaction == "redacted":
            assert CANARY not in json.dumps(document)
            assert items[0]["response"]["headers"]["authorization"] != f"Bearer {CANARY}"
    pooled = asyncio.run(reader.build_export(rows, **_ARGUMENTS, total=4, stats={"attempted": 4, "stored": 4}))
    assert pooled.materialize() == reader.export_document(rows, **_ARGUMENTS, total=4, stats={"attempted": 4, "stored": 4})


def test_private_workflow_headers_keep_only_their_names():
    row = {**_row(0, "body"), "plane": "hunt", "capability_name": "collections.replay_safe",
           "request_headers": {"x-pin": "4821", "cookie": f"s={CANARY}"}}
    item = reader.export_document([row], **_ARGUMENTS, total=1)["transactions"][0]
    assert item["request"]["headers"] == {"x-pin": "[REDACTED]", "cookie": "[REDACTED]"}
    assert item["response"]["body"] is None


def test_a_hostile_header_payload_is_withheld_not_fatal(monkeypatch):
    def fails(value, masked, private):
        raise RecursionError(f"cannot redact {value}")

    monkeypatch.setattr(worker, "encoded_headers", fails)
    rows = [{**_row(0, "body"), "request_headers": {"x": CANARY}}]
    document = reader.export_document(rows, **_ARGUMENTS, total=1)
    item = document["transactions"][0]
    assert item["request"]["headers"] == {}
    assert item["payload_omitted_reasons"]["request_headers"] == "masking_failed"
    assert CANARY not in json.dumps(document)


def test_payloads_are_read_only_for_the_exports_owner():
    seen = {}

    class Connection:
        async def fetch(self, query, *params):
            seen["query"], seen["params"] = query, params
            return []

    scan = "11111111-1111-4111-8111-111111111111"
    asyncio.run(reader.read_transaction_payloads(Connection(), ["row-1"], external_payload_budget=0, scan_id=scan))
    assert seen["query"].rstrip().endswith("AND t.scan_id=$2") and seen["params"] == (["row-1"], scan)
    asyncio.run(reader.read_transaction_payloads(
        Connection(), ["row-1"], external_payload_budget=0, scan_ids=[scan, "22222222-2222-4222-8222-222222222222"],
    ))
    assert "t.scan_id=ANY($2::uuid[])" in seen["query"]
    asyncio.run(reader.read_transaction_payloads(Connection(), ["row-1"], external_payload_budget=0, hunt_run_id="h"))
    assert seen["query"].rstrip().endswith("AND t.hunt_run_id=$2")
    with pytest.raises(ValueError):
        asyncio.run(reader.read_transaction_payloads(Connection(), ["row-1"], external_payload_budget=0))


def test_a_browse_page_is_served_while_the_same_caller_downloads(monkeypatch):
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
        return [_row(0, f"password={CANARY}")]

    for name, value in (("_pool", lambda: _Pool()), ("_scan_archive_ids", _ids), ("count_transactions", _count),
                        ("read_archive_stats", _stats), ("read_transactions", _rows)):
        monkeypatch.setattr(archive_router, name, value)

    class Request:
        client = type("Client", (), {"host": "198.51.100.7"})()
        headers = None  # no forwarding headers: the socket peer is the caller

    def export(limit):
        return archive_router._export(
            request=Request(), scan_id="11111111-1111-4111-8111-111111111111", hunt_run_id=None,
            export_format="transactions", redaction="redacted", method=None, status_code=None,
            search=None, limit=limit, offset=0,
        )

    async def scenario():
        release = asyncio.Event()
        holding = 0

        async def download():
            nonlocal holding
            async with archive_router.export_admission("198.51.100.7"):
                holding += 1
                await release.wait()

        downloads = [asyncio.create_task(download()) for _ in range(reader.MAX_EXPORTS_PER_CALLER)]
        while holding < reader.MAX_EXPORTS_PER_CALLER:
            await asyncio.sleep(0)
        page = await asyncio.wait_for(export(25), 30)  # the UI's 25-row browse page
        release.set()
        await asyncio.gather(*downloads)
        return page

    page = asyncio.run(scenario())
    assert page.status_code == 200
    assert json.loads(page.body)["transactions"][0]["response"]["body"] == "password=***"


def test_the_spawn_launch_is_checked_and_falls_back_to_the_forkserver(monkeypatch):
    code = worker._STANDARD_LAUNCH.__code__
    assert "spawn" in code.co_names and "get_preparation_data" in code.co_names
    assert worker._launch_without_main is not None
    assert isinstance(worker.worker_context(), worker._WorkerContext)
    monkeypatch.setattr(worker, "_launch_without_main", None)
    calls = []

    import multiprocessing

    class Context:
        def set_forkserver_preload(self, modules):
            calls.append(modules)

    monkeypatch.setattr(multiprocessing, "get_context", lambda method: calls.append(method) or Context())
    worker.worker_context()
    assert calls == ["forkserver", ["__main__", worker.__name__]]


def test_the_reader_lists_every_archived_payload():
    from api.runtime.archive_blob_secrets import PAYLOAD_FIELDS

    assert reader.PAYLOAD_FIELDS == PAYLOAD_FIELDS
