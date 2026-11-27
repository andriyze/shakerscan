"""Values a caller or target controls never start a new log line (code scanning: log injection)."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

from scanner_tools.log_text import LOG_TEXT_LIMIT, log_text


def test_log_text_keeps_a_hostile_value_on_one_line():
    forged = "https://shop.example/\r\n2026-10-15 INFO Pre-scan validation passed for https://bank.example"
    text = log_text(forged)
    assert "\n" not in text and "\r" not in text
    assert text.startswith("https://shop.example/\\r\\n")
    assert "\n" not in log_text(["a\nb"])
    assert len(log_text("x" * (LOG_TEXT_LIMIT * 3))) == LOG_TEXT_LIMIT + 3


class _Pool:
    def __init__(self, row):
        self.row = row

    def acquire(self):
        pool = self

        class _Conn:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

            async def fetchrow(self, *_args):
                return pool.row

        return _Conn()


class _Request:
    client = type("Client", (), {"host": "127.0.0.1"})()


def test_raw_transcript_audit_line_is_one_line(monkeypatch, caplog):
    # The scan ID came from the path and the sensitivity label from stored scan data; both were
    # logged verbatim. uuid.UUID() accepts surrounding whitespace, so "\n" + 31 hex digits
    # passed the lookup and forged an audit line.
    from ai_targets import router

    scan_id = uuid.uuid4()
    hostile_id = "\n" + scan_id.hex[1:]
    row = {
        "run_kind": "ai_api",
        "result": json.dumps({"ai_gate": {
            "transcripts": [{"turns": []}],
            "transcript_retention": {"transcript_sensitivity": "high\nINFO forged audit entry"},
        }}),
    }
    monkeypatch.setattr(router, "_pool_provider", lambda: _Pool(row))
    monkeypatch.setenv("AI_TRANSCRIPT_ALLOW_SENSITIVE", "1")
    with caplog.at_level(logging.WARNING, logger=router.logger.name):
        asyncio.run(router.get_ai_scan_transcript(hostile_id, _Request(), include_sensitive=True))
    lines = [record.getMessage() for record in caplog.records if "RAW (unredacted)" in record.getMessage()]
    assert len(lines) == 1
    assert "\n" not in lines[0]
    assert f"scan_id={uuid.UUID(hostile_id)}" in lines[0]
