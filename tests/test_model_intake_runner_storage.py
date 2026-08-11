from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import model_intake_runner_storage as storage  # noqa: E402


def test_large_conversion_plan_accounts_for_multiple_images(monkeypatch, tmp_path: Path):
    work = tmp_path / "work"
    conversions = tmp_path / "conversions"
    filesystem = {
        "device": 1,
        "total_bytes": 2 * 1024**4,
        "used_bytes": 0,
        "free_bytes": 2 * 1024**4,
        "reserve_bytes": 10 * storage.GIB,
    }
    monkeypatch.setattr(storage, "_filesystem", lambda *_args, **_kwargs: dict(filesystem))

    plan = storage.storage_plan(
        subject_bytes=100 * storage.GIB,
        mode="conversion",
        requested_output_bytes=None,
        work_root=work,
        conversion_root=conversions,
        component_bytes=5 * storage.GIB,
        environment={},
    )

    assert plan["sufficient"] is True
    assert plan["output_image_bytes"] >= 130 * storage.GIB
    assert plan["estimated_peak_scratch_bytes"] > 700 * storage.GIB
    assert plan["required_work_bytes"] > plan["estimated_peak_scratch_bytes"]


def test_plan_rejects_before_allocation_when_reserve_would_be_crossed(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(storage, "_filesystem", lambda *_args, **_kwargs: {
        "device": 1,
        "total_bytes": 500 * storage.GIB,
        "used_bytes": 100 * storage.GIB,
        "free_bytes": 400 * storage.GIB,
        "reserve_bytes": 50 * storage.GIB,
    })
    plan = storage.storage_plan(
        subject_bytes=100 * storage.GIB,
        mode="conversion",
        requested_output_bytes=None,
        work_root=tmp_path / "work",
        conversion_root=tmp_path / "conversions",
        environment={},
    )
    assert plan["sufficient"] is False
    assert "safety reserve" in plan["reason"]


def test_cleanup_never_follows_symlinks_or_removes_active_scratch(tmp_path: Path):
    work = tmp_path / "work"
    jobs = tmp_path / "jobs"
    outside = tmp_path / "outside"
    work.mkdir()
    jobs.mkdir()
    outside.mkdir()
    (outside / "keep.bin").write_bytes(b"keep")
    scratch = work / "mi-old"
    scratch.mkdir()
    (scratch / "large.bin").write_bytes(b"x" * 1024)
    (work / "mi-link").symlink_to(outside, target_is_directory=True)

    assert storage.cleanup_candidates(
        work_root=work,
        job_root=jobs,
        active=True,
        force_inactive_work=True,
        environment={},
    ) == []

    candidates = storage.cleanup_candidates(
        work_root=work,
        job_root=jobs,
        active=False,
        force_inactive_work=True,
        environment={},
    )
    result = storage.cleanup_storage(candidates, dry_run=False)
    assert result["items"] == 1
    assert not scratch.exists()
    assert (outside / "keep.bin").read_bytes() == b"keep"


def test_cleanup_only_expires_terminal_job_metadata(monkeypatch, tmp_path: Path):
    work = tmp_path / "work"
    jobs = tmp_path / "jobs"
    work.mkdir()
    jobs.mkdir()
    terminal = jobs / "00000000-0000-0000-0000-000000000001.json"
    running = jobs / "00000000-0000-0000-0000-000000000002.json"
    terminal.write_text(json.dumps({"state": "failed"}))
    running.write_text(json.dumps({"state": "running"}))
    monkeypatch.setattr(storage, "_old_enough", lambda *_args: True)

    candidates = storage.cleanup_candidates(
        work_root=work,
        job_root=jobs,
        active=True,
        force_inactive_work=False,
        environment={},
    )
    assert [item["path"] for item in candidates] == [terminal]


def test_output_quota_is_large_but_bounded():
    sizes = storage.runner_drive_sizes(100 * storage.GIB, "conversion", None, {})
    assert sizes["max_input_bytes"] == 128 * storage.GIB
    assert sizes["max_output_bytes"] == 256 * storage.GIB
    with pytest.raises(ValueError, match="input quota"):
        storage.runner_drive_sizes(129 * storage.GIB, "conversion", None, {})
    with pytest.raises(ValueError, match="output quota"):
        storage.runner_drive_sizes(1 * storage.GIB, "runtime", 300 * storage.GIB, {})
