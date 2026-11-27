"""Erasing a deleted scan's files also removes its empty artifact directories (named by its ID)."""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "api"), str(ROOT)]


class _NoRowsLeft:
    async def fetchval(self, *args):
        return False


def test_a_deleted_scans_artifact_tree_is_removed_but_other_scans_are_untouched(tmp_path, monkeypatch):
    from data_lifecycle import erasure
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    deleted, kept = str(uuid.uuid4()), str(uuid.uuid4())
    for scan in (deleted, kept):
        result = tmp_path / "scan-artifacts" / scan / "standalone" / "result"
        result.mkdir(parents=True)
        (result / "result.json").write_text("{}")
    captured = {"evidence": [], "scans": [{"id": deleted, "job_id": None}],
                "artifacts": [f"local:scan_artifacts/{deleted}/standalone/result/result.json"]}
    outcome = asyncio.run(erasure.erase_files(_NoRowsLeft(), captured, []))
    assert outcome["complete"] and outcome["files_erased"] == 1
    assert not (tmp_path / "scan-artifacts" / deleted).exists()
    assert (tmp_path / "scan-artifacts" / kept / "standalone" / "result" / "result.json").exists()


def test_a_file_that_could_not_be_erased_keeps_its_directory(tmp_path, monkeypatch):
    from data_lifecycle import erasure
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    scan = str(uuid.uuid4())
    left = tmp_path / "scan-artifacts" / scan / "standalone" / "other.json"
    left.parent.mkdir(parents=True)
    left.write_text("{}")  # not named by any deleted row, so never erased
    asyncio.run(erasure.erase_files(_NoRowsLeft(), {"evidence": [], "artifacts": [], "scans": [{"id": scan, "job_id": None}]}, []))
    assert left.exists()
