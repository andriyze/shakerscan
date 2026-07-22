"""Phase B: first-class durable evidence objects. Tests the write-path helper's
contract — hashing, redaction profile, retention class, no-op, and never-raises
(it must never fail/roll back the scan)."""
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

import worker  # noqa: E402
from evidence_storage import delete_remote_evidence_object, hydrate_evidence_content, local_evidence_path  # noqa: E402


class _CaptureConn:
    def __init__(self):
        self.calls = []
        self.fetchval_calls = []

    async def fetchval(self, sql, *args):
        self.fetchval_calls.append((sql, args))
        if "SELECT retention_delete_preview_id" in sql:
            return None
        return True

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
    assert any("pg_advisory_lock" in sql for sql, _ in conn.fetchval_calls)
    assert any("pg_advisory_unlock" in sql for sql, _ in conn.fetchval_calls)


def test_large_evidence_object_externalizes_to_local_store(monkeypatch, tmp_path):
    monkeypatch.setattr(worker, "RESULTS_DIR", tmp_path)
    monkeypatch.setenv("EVIDENCE_INLINE_MAX_BYTES", "16")
    conn = _CaptureConn()
    evidence = {"blob": "x" * 200}

    asyncio.run(worker._persist_evidence_object(conn, "scan-uuid", "finding-uuid", {"tool": "ai_gate"}, evidence))

    args = conn.calls[0][1]
    assert args[3] and len(args[3]) == 64
    assert args[4] > 16
    assert args[5].startswith("local:evidence_objects/")
    assert args[8] is None
    path = local_evidence_path(tmp_path, args[5])
    assert path is not None and path.exists()
    assert "x" * 200 in path.read_text(encoding="utf-8")

    hydrated = hydrate_evidence_content(
        {
            "content_sha256": args[3],
            "storage_uri": args[5],
            "content": None,
        },
        results_dir=tmp_path,
    )
    assert hydrated["storage_status"] == "external"
    assert hydrated["storage_integrity"] == "verified"
    assert "x" * 200 in hydrated["content"]


def test_large_evidence_object_externalizes_to_s3_compatible_store(monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_INLINE_MAX_BYTES", "16")
    monkeypatch.setenv("EVIDENCE_STORAGE_BACKEND", "s3")
    monkeypatch.setenv("EVIDENCE_S3_BUCKET", "shakerscan-evidence")
    monkeypatch.setenv("EVIDENCE_S3_ENDPOINT_URL", "http://minio.local:9000")
    monkeypatch.setenv("EVIDENCE_S3_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("EVIDENCE_S3_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("EVIDENCE_S3_REGION", "us-test-1")
    stored_by_url: dict[str, bytes] = {}

    class _Response:
        def __init__(self, body: bytes = b""):
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return self._body

    def fake_urlopen(request, timeout=0):
        headers = {k.lower(): v for k, v in request.headers.items()}
        assert "authorization" in headers
        assert "x-amz-date" in headers
        assert timeout == 15
        if request.get_method() == "PUT":
            stored_by_url[request.full_url] = request.data
            return _Response()
        if request.get_method() == "GET":
            return _Response(stored_by_url[request.full_url])
        raise AssertionError(f"unexpected method {request.get_method()}")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    stored = worker.store_evidence_content({"blob": "x" * 200}, results_dir=tmp_path, inline_max_bytes=16)

    assert stored["storage_uri"].startswith("s3:evidence_objects/shakerscan-evidence/evidence-objects/")
    assert stored["content"] is None
    assert stored["remote"] is True
    hydrated = hydrate_evidence_content(
        {
            "content_sha256": stored["content_sha256"],
            "storage_uri": stored["storage_uri"],
            "content": None,
        },
        results_dir=tmp_path,
    )
    assert hydrated["storage_status"] == "remote"
    assert hydrated["storage_integrity"] == "verified"
    assert "x" * 200 in hydrated["content"]


def test_s3_storage_falls_back_to_local_store_when_remote_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_INLINE_MAX_BYTES", "16")
    monkeypatch.setenv("EVIDENCE_STORAGE_BACKEND", "s3")
    monkeypatch.setenv("EVIDENCE_S3_BUCKET", "shakerscan-evidence")
    monkeypatch.setenv("EVIDENCE_S3_ENDPOINT_URL", "http://minio.local:9000")

    def fake_urlopen(*args, **kwargs):
        raise OSError("remote down")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    stored = worker.store_evidence_content({"blob": "x" * 200}, results_dir=tmp_path, inline_max_bytes=16)

    assert stored["storage_uri"].startswith("local:evidence_objects/")
    assert stored["remote_error"]
    assert local_evidence_path(tmp_path, stored["storage_uri"]).exists()


def test_s3_remote_delete_uses_signed_delete(monkeypatch):
    monkeypatch.setenv("EVIDENCE_STORAGE_BACKEND", "s3")
    monkeypatch.setenv("EVIDENCE_S3_BUCKET", "shakerscan-evidence")
    monkeypatch.setenv("EVIDENCE_S3_ENDPOINT_URL", "http://minio.local:9000")
    monkeypatch.setenv("EVIDENCE_S3_ACCESS_KEY_ID", "ak")
    monkeypatch.setenv("EVIDENCE_S3_SECRET_ACCESS_KEY", "sk")

    seen = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b""

    def fake_urlopen(request, timeout=0):
        headers = {k.lower(): v for k, v in request.headers.items()}
        seen["method"] = request.get_method()
        seen["url"] = request.full_url
        seen["headers"] = headers
        assert timeout == 15
        return _Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = delete_remote_evidence_object(
        "s3:evidence_objects/shakerscan-evidence/evidence-objects/aa/" + ("a" * 64) + ".json"
    )

    assert result["status"] == "deleted"
    assert result["deleted"] is True
    assert seen["method"] == "DELETE"
    assert seen["url"] == "http://minio.local:9000/shakerscan-evidence/evidence-objects/aa/" + ("a" * 64) + ".json"
    assert "authorization" in seen["headers"]
    assert "x-amz-date" in seen["headers"]


def test_evidence_object_retention_standard_without_sensitive_fields():
    conn = _CaptureConn()
    asyncio.run(worker._persist_evidence_object(conn, "s", "f", {"tool": "headers"}, {"k": "v"}))
    assert conn.calls[0][1][7] == "standard"


def test_no_write_without_finding_id():
    conn = _CaptureConn()
    asyncio.run(worker._persist_evidence_object(conn, "s", None, {}, {"x": 1}))
    assert conn.calls == []


def test_retention_pending_object_is_not_rewritten():
    class _PendingConn(_CaptureConn):
        async def fetchval(self, sql, *args):
            self.fetchval_calls.append((sql, args))
            if "SELECT retention_delete_preview_id" in sql:
                return "preview-uuid"
            return True

    conn = _PendingConn()
    asyncio.run(worker._persist_evidence_object(conn, "s", "f", {}, {"x": 1}))
    assert conn.calls == []
    lock_keys = [args[0] for sql, args in conn.fetchval_calls if "pg_advisory_lock" in sql]
    assert lock_keys == ["evidence-row:f:finding_evidence"]
    assert any("pg_advisory_unlock" in sql for sql, _ in conn.fetchval_calls)
    assert not any("evidence-blob:" in str(args) for _sql, args in conn.fetchval_calls)


def test_never_raises_on_db_error():
    class _BadConn:
        async def execute(self, *a):
            raise RuntimeError("db down")
    # Best-effort: a write failure must not propagate (would otherwise fail the scan).
    asyncio.run(worker._persist_evidence_object(_BadConn(), "s", "f", {}, {"x": 1}))
