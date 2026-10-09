"""Masked archive views are bounded and are never built on the API's event loop.

External release audit, 2026-10-09 (R2): the async archive endpoint called the synchronous
export builder directly, so masking a large or hostile captured body occupied the event loop.
The masking passes are linear now, and on top of that a body past the masking limit is withheld
whole, an export past its masking budget omits further bodies (never shows them unmasked), and
exports are built on a small dedicated thread pool. The canaries are test fixtures.
"""

from __future__ import annotations

import asyncio
import json
import threading

from api.runtime import archive_body_masking as masking
from api.runtime import http_archive_reader as reader
from api.runtime.archive_body_masking import withhold_body_secrets

CANARY = "BoundsCanaryR2x7Kq"


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


def _row(index: int, body: str) -> dict:
    return {
        "id": f"row-{index}", "sequence": index, "plane": "scan", "capability_name": "web.spec_ingest",
        "method": "GET", "url": "https://example.test/spec.yaml", "status_code": 200,
        "request_headers": {}, "response_headers": {}, "request_body": None, "response_body": body,
        "response_body_sha256": None, "response_body_bytes": len(body),
    }


def test_an_export_past_its_masking_budget_omits_bodies_rather_than_showing_them(monkeypatch):
    monkeypatch.setattr(reader, "MAX_EXPORT_MASKED_CHARS", 2_500)
    body = f"- name: api_key\n  example: {CANARY}\n" + "x" * 900
    rows = [_row(index, body) for index in range(3)]
    document = reader.export_document(
        rows, export_format="transactions", redaction="redacted", owner={"scan_id": "s"}, total=3,
        stats={"attempted": 3, "stored": 3},
    )
    serialized = json.dumps(document)
    assert CANARY not in serialized
    bodies = [item["response"]["body"] for item in document["transactions"]]
    assert bodies[0] and bodies[1] and bodies[2] is None
    assert document["transactions"][2]["payload_omitted"] == ["response_body"]
    assert document["fidelity"] == "partial"
    assert "omitted from this export to bound its size" in document["fidelity_detail"]

    har = reader.export_document(
        rows, export_format="har", redaction="redacted", owner={"scan_id": "s"}, total=3,
    )
    assert CANARY not in json.dumps(har)


def test_a_raw_export_spends_no_masking_budget(monkeypatch):
    monkeypatch.setattr(reader, "MAX_EXPORT_MASKED_CHARS", 10)
    rows = [_row(0, "plain body well past ten characters")]
    document = reader.export_document(
        rows, export_format="transactions", redaction="raw", owner={"scan_id": "s"}, total=1,
    )
    assert document["transactions"][0]["response"]["body"] == "plain body well past ten characters"
    assert document["transactions"][0]["payload_omitted"] == []


_EXPORT_ARGUMENTS = {
    "export_format": "transactions", "redaction": "redacted", "owner": {"scan_id": "s"}, "total": 1,
}


def test_the_export_is_built_off_the_event_loop(monkeypatch):
    release = threading.Event()
    threads: list[str] = []

    def blocking_export(rows, **_arguments):
        threads.append(threading.current_thread().name)
        # Only a free event loop can set this; built on the loop, it would wait out the timeout.
        if not release.wait(5):
            raise AssertionError("the export blocked the event loop")
        return {"rows": len(rows)}

    monkeypatch.setattr(reader, "export_document", blocking_export)

    async def scenario():
        build = asyncio.create_task(reader.build_export_document([{}], **_EXPORT_ARGUMENTS))
        await asyncio.sleep(0.05)
        release.set()
        return await asyncio.wait_for(build, 5)

    assert asyncio.run(scenario()) == {"rows": 1}
    assert threads and threads[0].startswith("archive-export")


def test_the_event_loop_keeps_serving_while_a_hostile_export_is_masked():
    body = (
        "name: api_key\n" * 20_000
        + '<input name="password">' * 20_000 + "\n"
        + "token-" * 20_000 + "\n"
        + f"- name: api_key\n  example: {CANARY}\n"
    )
    rows = [_row(index, body) for index in range(4)]

    async def scenario():
        ticks = 0
        done = asyncio.Event()

        async def ticker():
            nonlocal ticks
            while not done.is_set():
                ticks += 1
                await asyncio.sleep(0.001)

        counting = asyncio.create_task(ticker())
        ticks_before = ticks
        document = await reader.build_export_document(rows, **{**_EXPORT_ARGUMENTS, "total": 4})
        done.set()
        await counting
        return document, ticks - ticks_before

    document, ticks = asyncio.run(scenario())
    assert CANARY not in json.dumps(document)
    # Built on the loop, the ticker could not run at all until the export returned.
    assert ticks >= 3, ticks


def test_concurrent_exports_are_bounded(monkeypatch):
    lock = threading.Lock()
    running = peak = 0
    release = threading.Event()

    def blocking_export(rows, **_arguments):
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        try:
            release.wait(5)
        finally:
            with lock:
                running -= 1
        return {}

    monkeypatch.setattr(reader, "export_document", blocking_export)

    async def scenario():
        builds = [
            asyncio.create_task(reader.build_export_document([], **_EXPORT_ARGUMENTS)) for _ in range(5)
        ]
        await asyncio.sleep(0.2)
        observed = peak
        release.set()
        await asyncio.gather(*builds)
        return observed

    assert asyncio.run(scenario()) == reader.MAX_CONCURRENT_EXPORT_BUILDS
