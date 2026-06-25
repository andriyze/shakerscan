"""Phase B: first-class durable evidence objects. Tests the write-path helper's
contract — hashing, redaction profile, retention class, no-op, and never-raises
(it must never fail/roll back the scan)."""
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

import worker  # noqa: E402


class _CaptureConn:
    def __init__(self):
        self.calls = []

    async def execute(self, sql, *args):
        self.calls.append((sql, args))


def test_evidence_object_is_hashed_redaction_profiled_and_retention_classed():
    conn = _CaptureConn()
    finding = {"tool": "smart_sqli", "request": "POST /login", "response": "ok"}
    evidence = {"payload": "' OR 1=1--", "proof": "auth bypass"}
    asyncio.run(worker._persist_evidence_object(conn, "scan-uuid", "finding-uuid", finding, evidence))
    assert len(conn.calls) == 1
    args = conn.calls[0][1]
    # (scan_id, finding_id, object_type, sha256, size, storage_uri, redaction_profile, retention, content)
    assert args[1] == "finding-uuid"
    assert args[2] == "smart_sqli_evidence"
    assert args[3] and len(args[3]) == 64        # content_sha256
    assert args[5] == "inline:evidence_objects"  # storage_uri
    assert args[6] == "redact_sensitive_v1"      # redaction profile
    assert args[7] == "sensitive"                # has request/response -> sensitive
    assert "1=1" in args[8]                       # content carries the evidence


def test_evidence_object_retention_standard_without_sensitive_fields():
    conn = _CaptureConn()
    asyncio.run(worker._persist_evidence_object(conn, "s", "f", {"tool": "headers"}, {"k": "v"}))
    assert conn.calls[0][1][7] == "standard"


def test_no_write_without_finding_id():
    conn = _CaptureConn()
    asyncio.run(worker._persist_evidence_object(conn, "s", None, {}, {"x": 1}))
    assert conn.calls == []


def test_never_raises_on_db_error():
    class _BadConn:
        async def execute(self, *a):
            raise RuntimeError("db down")
    # Best-effort: a write failure must not propagate (would otherwise fail the scan).
    asyncio.run(worker._persist_evidence_object(_BadConn(), "s", "f", {}, {"x": 1}))
