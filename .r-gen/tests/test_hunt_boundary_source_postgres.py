"""Real PostgreSQL semantics for admitting Hunt discovery provenance at verify time."""
from __future__ import annotations

import json
import os
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

from api.ai_gate.boundary.hypothesis import compile_boundary_hypothesis
from api.hunt.boundary_context import read_candidate_boundary_source_binding
from api.hunt.boundary_source import BoundarySourceError, admit_boundary_source_binding

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

SCHEMA_SQL = """
CREATE TABLE hunt_runs (id UUID PRIMARY KEY, target_id UUID, device_target_id UUID);
CREATE TABLE investigation_candidates (
    id UUID PRIMARY KEY, plane TEXT NOT NULL, target_id UUID, device_target_id UUID,
    family TEXT NOT NULL, status TEXT NOT NULL, canonical_locus JSONB NOT NULL
);
CREATE TABLE investigation_candidate_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    candidate_id UUID NOT NULL REFERENCES investigation_candidates(id),
    hunt_run_id UUID REFERENCES hunt_runs(id),
    source_kind TEXT NOT NULL DEFAULT 'hunt',
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    observation_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


def _binding(hunt, target, **changes):
    return {"schema_version": "hunt-boundary-source/v1", "hunt_id": hunt, "target_id": target,
            "origin": "https://agent.example.test", "agent_paths": ["/chat"], **changes}


def _proposal(candidate, capture, binding=None, *, cite_candidate=True):
    provenance = [{"kind": "evidence", "id": capture}]
    if cite_candidate:
        provenance.insert(0, {"kind": "hunt_candidate", "id": candidate})
    proposal = compile_boundary_hypothesis({
        "version": 1, "hypothesis_id": "hunt-read", "kind": "cross_tenant_read",
        "owner": {"role": "victim", "subject": "a", "tenant": "ta", "resource_id": "doc-a"},
        "attacker": {"role": "attacker", "subject": "b", "tenant": "tb", "resource_id": "doc-b"},
        "provenance": provenance,
    })
    if binding is not None:
        proposal["source_binding"] = binding
    return proposal


CONTRACT = {
    "owner": {"resource_id": "doc-a"}, "attacker": {"resource_id": "doc-b"},
    "resource": {"path": "/documents/{{resource_id}}"},
}


@pytest.mark.asyncio
async def test_discovery_binding_admission_uses_latest_prepared_binding_in_real_sql():
    import asyncpg

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1"}
    schema = "boundary_source_" + uuid4().hex
    conn = await asyncpg.connect(DSN)
    try:
        await conn.execute(f'CREATE SCHEMA "{schema}"; SET search_path TO "{schema}"')
        await conn.execute(SCHEMA_SQL)
        hunt, target, candidate, other = (str(uuid4()) for _ in range(4))
        capture = str(uuid4())
        await conn.execute("INSERT INTO hunt_runs VALUES($1,$2,NULL)", hunt, target)
        locus = {"route": "/documents/{{resource_id}}", "ai_boundary_context": {
            "discovery_draft_id": "a" * 64, "owner_resource_id": "doc-a", "attacker_resource_id": "doc-b"}}
        for row_id in (candidate, other):
            await conn.execute(
                "INSERT INTO investigation_candidates VALUES($1,'web',$2,NULL,'cross_tenant_retrieval','new',$3::jsonb)",
                row_id, target, json.dumps(locus),
            )
        insert = """INSERT INTO investigation_candidate_observations
                    (candidate_id, hunt_run_id, source_kind, evidence_refs, observation_context, observed_at)
                    VALUES($1,$2,$3,$4::jsonb,$5::jsonb,NOW() + ($6 || ' seconds')::interval)"""
        old = _binding(hunt, target)
        current = _binding(hunt, target, agent_paths=["/chat", "/v2/chat"])
        await conn.execute(insert, candidate, hunt, "hunt_boundary_discovery", json.dumps([capture]),
                           json.dumps({"boundary_source_binding": old}), "1")
        await conn.execute(insert, candidate, hunt, "hunt_boundary_discovery", json.dumps([capture]),
                           json.dumps({"boundary_source_binding": current}), "2")
        for offset in range(3, 63):  # lifecycle edits: same source_kind, no binding
            await conn.execute(insert, candidate, hunt, "hunt_boundary_discovery", json.dumps([capture]),
                               json.dumps({"event": "candidate.updated"}), str(offset))
        await conn.execute(insert, other, hunt, "hunt_v2", json.dumps([capture]), "{}", "1")

        run = {"id": hunt, "target_id": target, "device_target_id": None}
        assert await read_candidate_boundary_source_binding(conn, run=run, candidate_id=candidate) == current
        assert await admit_boundary_source_binding(
            conn, proposal=_proposal(candidate, capture, current), contract=CONTRACT,
        ) == current
        with pytest.raises(BoundarySourceError, match="superseded_or_mismatched"):
            await admit_boundary_source_binding(conn, proposal=_proposal(candidate, capture, old), contract=CONTRACT)
        for stripped in (_proposal(candidate, capture), _proposal(candidate, capture, cite_candidate=False)):
            with pytest.raises(BoundarySourceError, match="boundary_source_binding_required"):
                await admit_boundary_source_binding(conn, proposal=stripped, contract=CONTRACT)
        # A hand-built candidate citing the same capture is not discovery-derived.
        assert await admit_boundary_source_binding(
            conn, proposal=_proposal(other, capture), contract=CONTRACT,
        ) is None
    finally:
        await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await conn.close()
