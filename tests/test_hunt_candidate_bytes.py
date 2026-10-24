"""A Hunt's candidate writes are bounded in bytes; a write past the bound is refused, nothing more.

Labelled fixtures stand in for the database: ``stored`` is the bytes this Hunt's candidate records
already hold. The PostgreSQL test of the stored-bytes query runs in tests/test_hunt_recording_postgres.py.
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
import uuid

import pytest

from hunt import candidate_bytes
from hunt import interaction_router as router

HUNT = str(uuid.uuid4())


class Store:
    """Labelled fixture: one Hunt row, its evidence action and the bytes its candidates hold."""

    def __init__(self, stored: int, action: str):
        self.stored, self.action = stored, action
        self.writes: list[str] = []
        self.size_queries: list[tuple] = []

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self, **_kwargs):
        yield self

    async def fetch(self, _sql, *args):
        return [{"id": self.action, "kind": "action", "status": "completed"}] if self.action in args[0] else []

    async def fetchval(self, sql, *args):
        assert sql == candidate_bytes.STORED_CANDIDATE_BYTES_SQL
        self.size_queries.append(args)
        return self.stored

    async def execute(self, sql, *args):
        self.writes.append(sql)


def _patch(monkeypatch, store, status="active"):
    run = {"id": HUNT, "target_id": str(uuid.uuid4()), "device_target_id": None, "status": status,
           "objective": "o", "context_pack": {}, "budget_used_json": {"candidates": 0},
           "budget_json": {"max_candidates": 20}, "completed_at": None, "notes": None}
    upserts, updates = [], []

    async def lookup(_conn, _hunt_id, for_update=False):
        return run

    async def upsert(_conn, candidate, **kwargs):
        upserts.append((candidate, kwargs))
        return {"id": str(uuid.uuid4()), "outcome": "inserted", "inserted": True}

    async def update(*_args, **kwargs):
        updates.append(kwargs)
        return {"id": kwargs["candidate_id"], "updated_fields": sorted(kwargs["changes"])}

    monkeypatch.setattr(router, "_pool", lambda: store)
    monkeypatch.setattr(router, "_hunt_run_or_404", lookup)
    monkeypatch.setattr(router.investigation_candidates, "upsert_candidate", upsert)
    monkeypatch.setattr(router.investigation_candidates, "update_candidate_for_hunt", update)
    return upserts, updates


def _request(action, claim="22/tcp open"):
    return router.HuntCandidateRequest(
        family="device_service_exposure", locus={"transport": "tcp", "port": 22},
        title="SSH exposed", claim=claim, evidence_refs=[action],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["active", "budget_exhausted"])
async def test_a_candidate_past_the_byte_bound_is_refused_and_nothing_is_written(monkeypatch, status):
    action = str(uuid.uuid4())
    store = Store(candidate_bytes.MAX_CANDIDATE_BYTES_PER_HUNT - 100, action)
    upserts, _ = _patch(monkeypatch, store, status)
    with pytest.raises(router.HTTPException) as refused:
        await router.create_hunt_candidate(HUNT, _request(action))
    assert refused.value.status_code == 422
    assert refused.value.detail["error"] == "candidate_bytes_limit"
    assert "limit per Hunt" in refused.value.detail["message"]
    assert "keeps running" in refused.value.detail["message"]
    # Nothing written, no record unit charged, no Hunt status or budget state recorded.
    assert upserts == [] and store.writes == []
    assert store.size_queries == [(uuid.UUID(HUNT),)]


@pytest.mark.asyncio
async def test_a_candidate_inside_the_byte_bound_is_recorded(monkeypatch):
    action = str(uuid.uuid4())
    store = Store(0, action)
    upserts, _ = _patch(monkeypatch, store)
    result = await router.create_hunt_candidate(HUNT, _request(action))
    assert result["candidate"]["outcome"] == "inserted" and len(upserts) == 1
    candidate, kwargs = upserts[0]
    # The checked size is what the write stores: the row and its observation, with its context.
    size = candidate_bytes.sighting_bytes(candidate, kwargs["observation_context"])
    assert size > 2 * len("SSH exposed22/tcp open")
    store.stored = candidate_bytes.MAX_CANDIDATE_BYTES_PER_HUNT - size
    await router.create_hunt_candidate(HUNT, _request(action))
    store.stored += 1
    with pytest.raises(router.HTTPException):
        await router.create_hunt_candidate(HUNT, _request(action))


@pytest.mark.asyncio
async def test_a_candidate_correction_past_the_byte_bound_is_refused(monkeypatch):
    action = str(uuid.uuid4())
    store = Store(candidate_bytes.MAX_CANDIDATE_BYTES_PER_HUNT, action)
    _, updates = _patch(monkeypatch, store)
    with pytest.raises(router.HTTPException) as refused:
        await router.update_hunt_candidate(HUNT, str(uuid.uuid4()), router.HuntCandidateUpdateRequest(title="New"))
    assert refused.value.status_code == 422 and refused.value.detail["error"] == "candidate_bytes_limit"
    assert updates == []
    store.stored = 0
    await router.update_hunt_candidate(HUNT, str(uuid.uuid4()), router.HuntCandidateUpdateRequest(title="New"))
    assert len(updates) == 1


def test_a_correction_counts_a_field_it_leaves_at_its_largest_stored_size():
    full = candidate_bytes.correction_bytes({"title": "t" * 300, "claim": "c" * 8_000, "evidence_refs": ["a"]})
    assert candidate_bytes.correction_bytes({"title": "t"}) > full
    assert candidate_bytes.correction_bytes({"claim": "c"}) > candidate_bytes.correction_bytes({"claim": "c", "title": "t"})


def test_the_documented_count_of_largest_candidates_matches_the_bound():
    four_byte = "\U0001F600"
    locus = {"path": "x" * (16_384 - 12)}  # a whole locus is at most 16,384 bytes
    largest = candidate_bytes.sighting_bytes({
        "title": four_byte * 300, "claim": four_byte * 8_000, "canonical_locus": locus,
        "evidence_refs": [four_byte * 119 + chr(0x4E00 + index) for index in range(100)],
    }, {"hunt_id": HUNT, "objective": four_byte * 20_000})
    assert len(json.dumps(locus).encode()) == 16_384
    fits = candidate_bytes.MAX_CANDIDATE_BYTES_PER_HUNT // largest
    root = Path(__file__).resolve().parents[1]
    for note in (root / "docs/hunt-recording-and-budgets.md", root / "api/hunt/candidate_bytes.py"):
        text = " ".join(note.read_text(encoding="utf-8").split())
        assert f"About {fits // 10 * 10:,}" in text, (note, fits)


@pytest.mark.asyncio
async def test_a_boundary_draft_past_the_byte_bound_is_refused(monkeypatch):
    action = str(uuid.uuid4())
    store = Store(candidate_bytes.MAX_CANDIDATE_BYTES_PER_HUNT, action)
    upserts, _ = _patch(monkeypatch, store)
    draft = {"draft_id": "a" * 64, "source_binding": {"origin": "https://app.test"},
             "candidate_request": {"family": "data_exposure", "locus": {"path": "/x"}, "title": "t",
                                   "claim": "c", "severity": "info", "evidence_refs": [action]},
             "evidence_refs_total": 1, "evidence_refs_truncated": False, "provenance_omitted": 0}

    async def discovery(_conn, *, run):
        return {"drafts": [draft]}
    monkeypatch.setattr(router, "discover_hunt_boundaries", discovery)
    with pytest.raises(router.HTTPException) as refused:
        await router.prepare_hunt_boundary_discovery(HUNT, "a" * 64)
    assert refused.value.status_code == 422 and refused.value.detail["error"] == "candidate_bytes_limit"
    assert upserts == [] and store.writes == []
    store.stored = 0
    prepared = await router.prepare_hunt_boundary_discovery(HUNT, "a" * 64)
    assert prepared["candidate"]["outcome"] == "inserted" and len(upserts) == 1
