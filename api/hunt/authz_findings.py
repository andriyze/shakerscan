"""Project the existing canonical authz proof, never promote access-only candidates.

Called only by the worker-owned deterministic finding bridge. The existing
object-authorization validator remains the proof authority; this checks that the
content-free receipt still contains its controls and belongs to the executed origin.
"""
from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

try:
    from scanner_tools.finding_validator import validate_object_authorization
except ModuleNotFoundError:
    from scanner.scanner_tools.finding_validator import validate_object_authorization

_DIGEST = re.compile(r"[0-9a-f]{64}")
_STATUS_KEYS = ("owner_listing_status", "attacker_listing_status",
                "owner_replay_status", "attacker_replay_status")


def _url(value: Any) -> tuple[str, tuple[str, str, int]] | None:
    if not isinstance(value, str) or len(value) > 4_000 or any(ord(c) < 32 for c in value) or "\\" in value:
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            return None
        return (urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")),
                (parsed.scheme, parsed.hostname.lower().rstrip("."), port))
    except (ValueError, UnicodeError):
        return None


def verified_authz_observations(observations: Any, *, target_url: str) -> list[dict[str, Any]]:
    """Map a settled canonical differential to Scan-compatible evidence fields.

    The selected-object path deliberately does not claim entitlement. Neither a
    planner declaration nor an HTTP 200 can substitute for the listing differential.
    """
    target = _url(target_url)
    if target is None:
        return []
    accepted = []
    seen = set()
    for raw in observations if isinstance(observations, (list, tuple)) else ():
        if not isinstance(raw, Mapping):
            continue
        producer, consumer = _url(raw.get("producer_url")), _url(raw.get("consumer_url"))
        statuses = raw.get("accepted_principal_responses")
        digest = raw.get("resource_id_sha256")
        if (
            raw.get("kind") != "authz_differential" or raw.get("proof_state") != "verified"
            or raw.get("proof_type") != "cross_principal_replay" or raw.get("mode") == "selected_object"
            or raw.get("method") != "GET" or raw.get("principal_contexts_distinct") is not True
            or raw.get("object_absent_from_secondary_listing") is not True
            or raw.get("responses_equivalent") is not True
            or type(raw.get("owner_status")) is not int or raw["owner_status"] != 200
            or type(raw.get("attacker_status")) is not int or raw["attacker_status"] != 200
            or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
            or producer is None or consumer is None or producer[1] != target[1] or consumer[1] != target[1]
            or not isinstance(statuses, Mapping)
            or any(type(statuses.get(key)) is not int or not 200 <= statuses[key] < 300 for key in _STATUS_KEYS)
            or statuses["owner_replay_status"] != 200 or statuses["attacker_replay_status"] != 200
        ):
            continue
        evidence = {
            "url": consumer[0], "method": "GET", "producer_url": producer[0],
            "resource_id_sha256": digest,
            "owner_status": raw["owner_status"], "attacker_status": raw["attacker_status"],
            "accepted_principal_responses": {key: statuses[key] for key in _STATUS_KEYS},
            "distinct_principal_control": True,
            "object_id_absent_from_attacker_listing": True,
            "responses_equivalent": True, "proof_type": "cross_principal_replay",
        }
        if not validate_object_authorization({"evidence": evidence}).verified:
            continue
        key = (consumer[0], producer[0], digest)
        if key not in seen:
            accepted.append(evidence)
            seen.add(key)
        if len(accepted) >= 20:
            break
    return accepted
