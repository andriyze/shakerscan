"""The disposition manifest is the record of what survives V2.

A behaviour-preserving extraction cannot decide whether a surface belongs in the
product. These tests keep that decision written down and keep the deletion
backlog shrinking rather than drifting.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config" / "v2_surface_disposition.yaml"
CHECKER = ROOT / "scripts" / "check_surface_dispositions.py"

DISPOSITIONS = {
    "DELETE_NOW", "QUARANTINE_READ_ONLY", "MERGE_THEN_DELETE",
    "KEEP_AND_SPLIT", "KEEP_CANONICAL", "ARCHIVE_DOC_ONLY",
}


@pytest.fixture(scope="module")
def manifest() -> dict:
    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))


def test_every_public_route_has_a_written_disposition():
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_every_surface_declares_a_valid_disposition_and_owner(manifest):
    ids = set()
    for surface in manifest["surfaces"]:
        sid = surface["id"]
        assert sid not in ids, f"duplicate surface id: {sid}"
        ids.add(sid)
        assert surface["disposition"] in DISPOSITIONS
        assert surface.get("owner"), f"{sid} has no owner"
        assert surface.get("routes"), f"{sid} declares no routes"


def test_surfaces_that_must_not_grow_declare_a_replacement(manifest):
    """A surface being removed has to say what replaces it."""
    for surface in manifest["surfaces"]:
        if surface["disposition"] not in {"DELETE_NOW", "MERGE_THEN_DELETE"}:
            continue
        assert surface.get("canonical_replacement"), (
            f"{surface['id']} is {surface['disposition']} but names no canonical "
            "replacement"
        )
        assert surface.get("new_writes_allowed") is False, (
            f"{surface['id']} is {surface['disposition']} but still allows new writes"
        )


def test_quarantined_surfaces_declare_a_sunset_and_telemetry(manifest):
    for surface in manifest["surfaces"]:
        if surface["disposition"] != "QUARANTINE_READ_ONLY":
            continue
        assert surface.get("new_writes_allowed") is False
        assert surface.get("historical_reads_required") is True
        assert surface.get("caller_telemetry") == "required", (
            f"{surface['id']} must record who still calls it before it can be removed"
        )


def test_the_deletion_backlog_only_shrinks():
    """Pin the backlog size so a new pending write cannot be added quietly.

    Lower this number when work is deleted. Raising it means a surface that was
    supposed to stop accepting writes gained another one, which the playbook
    forbids.
    """
    manifest_data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    backlog = sum(
        len(surface.get("pending_write_removals") or ())
        for surface in manifest_data["surfaces"]
    )
    assert backlog <= 41, (
        f"the pending write-removal backlog grew to {backlog}; it may only shrink"
    )
