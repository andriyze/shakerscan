"""Admit Hunt discovery provenance on an AI Boundary proposal before verification.

A proposal is client-held JSON, so its ``source_binding`` is a claim until it is
checked against the Hunt record. This module performs that check server-side:

* a binding must name an existing Hunt for the bound asset, cite exactly one
  Hunt candidate, and equal the binding that discovery preparation last wrote
  for that candidate in that Hunt;
* the executable contract must test the resource pair and path template that
  discovery observed for that candidate;
* a proposal citing a discovery candidate, or citing no candidate but evidence a
  discovery observation cites, must carry the binding: stripping it is refused
  rather than queued.

A proposal with no Hunt discovery provenance (a plain operator-authored one) is
unaffected. Admission is provenance, never authority: the AI target's own
authorization, credentials and budgets are still enforced by the queue path.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from .boundary_context import (
    CANDIDATE_QUERY,
    BoundaryContextError,
    read_candidate_boundary_source_binding,
)

try:
    from ai_gate.boundary.hypothesis import normalize_boundary_source_binding
except ModuleNotFoundError:  # package import in host-side tests
    from ..ai_gate.boundary.hypothesis import normalize_boundary_source_binding

MAX_PROVENANCE_REFERENCES = 256

DISCOVERY_ASSOCIATION_QUERY = """
SELECT o.candidate_id
FROM investigation_candidate_observations o
WHERE o.source_kind='hunt_boundary_discovery'
  AND o.observation_context->'boundary_source_binding' IS NOT NULL
  AND (o.candidate_id=ANY($1::uuid[]) OR o.evidence_refs ?| $2::text[])
LIMIT 1
"""
HUNT_QUERY = """
SELECT id, target_id, device_target_id
FROM hunt_runs
WHERE id=$1::uuid
"""


class BoundarySourceError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_uuid(value: Any) -> str | None:
    # Any spelling UUID() accepts (case, no hyphens, urn: prefix) names the same
    # row, so a re-spelled reference cannot dodge the association check.
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def _provenance_references(provenance: Any) -> tuple[list[str], list[str], int]:
    """Return UUID-shaped candidate/evidence IDs and the hunt_candidate entry count."""
    candidates: list[str] = []
    evidence: list[str] = []
    candidate_entries = 0
    for item in provenance if isinstance(provenance, list) else []:
        if not isinstance(item, Mapping):
            continue
        kind = item.get("kind")
        if kind == "hunt_candidate":
            candidate_entries += 1
        identifier = _canonical_uuid(item.get("id"))
        if identifier is None:
            continue
        if kind == "hunt_candidate" and identifier not in candidates:
            candidates.append(identifier)
        elif kind == "evidence" and identifier not in evidence:
            evidence.append(identifier)
    if len(candidates) + len(evidence) > MAX_PROVENANCE_REFERENCES:
        raise BoundarySourceError("boundary_provenance_reference_limit")
    return candidates, evidence, candidate_entries


def _locus_context(row: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    locus = row.get("canonical_locus")
    if isinstance(locus, str):
        try:
            locus = json.loads(locus)
        except (ValueError, RecursionError):
            locus = None
    if not isinstance(locus, dict):
        raise BoundarySourceError("boundary_source_candidate_locus_invalid")
    context = locus.get("ai_boundary_context")
    route = locus.get("route")
    return (context if isinstance(context, dict) else {}), (route if isinstance(route, str) else None)


async def admit_boundary_source_binding(
    conn: Any, *, proposal: Mapping[str, Any], contract: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return the validated binding, ``None`` for unbound proposals, or refuse."""
    try:
        binding = normalize_boundary_source_binding(proposal.get("source_binding"))
    except ValueError as exc:
        raise BoundarySourceError(str(exc)) from exc
    candidates, evidence, candidate_entries = _provenance_references(proposal.get("provenance"))

    if binding is None:
        # A cited candidate decides: a hand-built candidate that happens to cite the
        # same captures makes no service-binding claim. With no candidate cited,
        # discovery captures alone still identify a discovery-derived proposal.
        if (candidates or evidence) and await conn.fetchrow(
            DISCOVERY_ASSOCIATION_QUERY, candidates, [] if candidates else evidence,
        ) is not None:
            raise BoundarySourceError("boundary_source_binding_required")
        return None

    if candidate_entries != 1 or len(candidates) != 1:
        raise BoundarySourceError("boundary_source_binding_requires_one_hunt_candidate")
    run = await conn.fetchrow(HUNT_QUERY, binding["hunt_id"])
    if run is None:
        raise BoundarySourceError("boundary_source_hunt_not_found")
    run = dict(run)
    target_ref = run.get("device_target_id") or run.get("target_id")
    if target_ref is None or str(target_ref) != binding["target_id"]:
        raise BoundarySourceError("boundary_source_target_mismatch")
    try:
        recorded = await read_candidate_boundary_source_binding(
            conn, run=run, candidate_id=candidates[0],
        )
    except BoundaryContextError as exc:
        raise BoundarySourceError(exc.code) from exc
    if recorded is None:
        raise BoundarySourceError("boundary_source_binding_not_recorded")
    if recorded != binding:
        raise BoundarySourceError("boundary_source_binding_superseded_or_mismatched")

    candidate = await conn.fetchrow(
        CANDIDATE_QUERY, candidates[0], binding["hunt_id"],
        str(run["target_id"]) if run.get("target_id") else None,
        str(run["device_target_id"]) if run.get("device_target_id") else None,
    )
    if candidate is None:
        raise BoundarySourceError("boundary_source_binding_not_recorded")
    context, route = _locus_context(dict(candidate))
    owner, attacker = contract.get("owner") or {}, contract.get("attacker") or {}
    resource = contract.get("resource") or {}
    if (context.get("owner_resource_id") != owner.get("resource_id")
            or context.get("attacker_resource_id") != attacker.get("resource_id")):
        raise BoundarySourceError("boundary_source_resource_mismatch")
    if route is None or resource.get("path") != route:
        raise BoundarySourceError("boundary_source_resource_path_mismatch")
    return binding
