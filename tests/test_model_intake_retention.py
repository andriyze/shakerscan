import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scanner.scanner_tools.model_intake_retention import execute_cleanup, plan_cleanup


def _object(root: Path, digest: str, data: bytes, age_days: int):
    path = root / "sha256" / digest[:2] / digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    timestamp = (datetime.now(timezone.utc) - timedelta(days=age_days)).timestamp()
    os.utime(path, (timestamp, timestamp))
    return path


def test_retention_protects_active_admission_subjects_and_deletes_expired(tmp_path):
    protected = "a" * 64
    expired = "b" * 64
    protected_path = _object(tmp_path, protected, b"active", 100)
    expired_path = _object(tmp_path, expired, b"expired", 100)

    plan = plan_cleanup(tmp_path, protected_digests={protected}, retention_days=30)
    result = execute_cleanup(tmp_path, plan)

    assert [item["digest"] for item in plan["candidates"]] == [expired]
    assert result["deleted_count"] == 1
    assert protected_path.exists()
    assert not expired_path.exists()


def test_retention_quota_evicts_oldest_unprotected_object(tmp_path):
    oldest = "1" * 64
    newest = "2" * 64
    _object(tmp_path, oldest, b"123456", 5)
    _object(tmp_path, newest, b"abcdef", 1)

    plan = plan_cleanup(tmp_path, retention_days=100, max_total_bytes=6)

    assert plan["candidate_count"] == 1
    assert plan["candidates"][0]["digest"] == oldest
    assert plan["candidates"][0]["reason"] == "quota_eviction"


def test_retention_ignores_symlinks_and_non_content_addressed_files(tmp_path):
    outside = tmp_path.parent / "outside-model-object"
    outside.write_bytes(b"do not delete")
    prefix = tmp_path / "sha256" / "aa"
    prefix.mkdir(parents=True)
    (prefix / ("a" * 64)).symlink_to(outside)
    (prefix / "not-a-digest").write_bytes(b"ignored")

    plan = plan_cleanup(tmp_path, retention_days=1, max_total_bytes=0)

    assert plan["objects"] == 0
    assert plan["candidate_count"] == 0
    assert outside.exists()
