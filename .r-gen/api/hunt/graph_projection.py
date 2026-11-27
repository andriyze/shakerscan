"""Allowlisted reference metadata for resuming an existing investigation.

Graph attributes can hold arbitrary imported data. Never return the raw object.
These references describe existing records; they confer no execution authority.
"""
from __future__ import annotations

import json
import re
from typing import Any, Mapping
import uuid


_FIELDS = {
    "authorization_proposal": {
        "hunt_id", "proposal_id", "capture_id", "baseline_capture_id",
        "primary_session_ref", "secondary_session_ref", "proposal_digest",
        "resource_id_sha256", "baseline_resource_id_sha256", "baseline_kind", "expected_access",
    },
    "authorization_attempt": {"hunt_id", "proposal_id", "action_id", "attempt"},
    "authorization_candidate_link": {"hunt_id", "proposal_id", "action_id", "candidate_id", "candidate_fingerprint"},
    "authorization_decision": {"hunt_id", "proposal_id"},
}
_ENUMS = {"baseline_kind": {"collection", "own_object"}, "expected_access": {"unknown", "denied", "allowed"}}


def project_graph_node(row: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(row)
    raw = result.pop("attributes", {})
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            raw = {}
    attributes = raw if isinstance(raw, Mapping) else {}
    safe: dict[str, Any] = {}
    for key in _FIELDS.get(str(row.get("node_type")), set()):
        value = attributes.get(key)
        if key == "attempt":
            if type(value) is int and 1 <= value <= 20:
                safe[key] = value
        elif key in _ENUMS:
            if isinstance(value, str) and value in _ENUMS[key]:
                safe[key] = value
        elif key.endswith(("_digest", "_sha256", "_fingerprint")):
            if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
                safe[key] = value
        elif isinstance(value, (str, uuid.UUID)):
            try:
                safe[key] = str(uuid.UUID(str(value)))
            except ValueError:
                pass
    result["attributes"] = safe
    result["attributes_omitted"] = set(attributes) != set(safe)
    result["attributes_are_references_only"] = True
    return result
