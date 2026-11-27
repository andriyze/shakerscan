"""Candidate-tag cleanup must only ever select expired, well-formed candidate tags."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _cleanup():
    spec = importlib.util.spec_from_file_location(
        "cleanup_candidate_tags_under_test", ROOT / "scripts" / "cleanup_candidate_tags.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cleanup = _cleanup()
NOW = datetime(2026, 9, 3, tzinfo=timezone.utc)
SHA = "a" * 40


def _tag(name: str, age_days: int) -> dict:
    return {"name": name, "last_updated": (NOW - timedelta(days=age_days)).isoformat().replace("+00:00", "Z")}


def test_only_expired_candidate_tags_are_selected():
    tags = [
        _tag(f"candidate-{SHA}-1", 45),
        _tag(f"candidate-{SHA}-2", 10),
        _tag("2.0.0", 400),
        _tag("latest", 400),
        _tag("0.8.18", 400),
        _tag("candidate-not-a-sha-3", 400),
        {"name": f"candidate-{SHA}-4"},
    ]
    assert cleanup.expired_candidates(tags, now=NOW, older_than_days=30) == [f"candidate-{SHA}-1"]


def test_the_delete_helper_refuses_non_candidate_tags():
    with pytest.raises(cleanup.HubError):
        cleanup.delete_tag("shakerscan/shakerscan-scanner", "latest", "token")
    with pytest.raises(cleanup.HubError):
        cleanup.delete_tag("shakerscan/shakerscan-scanner", "2.0.0", "token")


def test_the_cleanup_workflow_defaults_to_a_dry_run_and_never_touches_version_tags():
    workflow = (ROOT / ".github" / "workflows" / "candidate-cleanup.yml").read_text(encoding="utf-8")
    assert "scripts/cleanup_candidate_tags.py" in workflow
    assert "default: false" in workflow
    assert "inputs.delete" in workflow
    assert "imagetools create" not in workflow
