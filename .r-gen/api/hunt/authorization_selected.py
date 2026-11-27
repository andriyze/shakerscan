"""Interpret exact selected-object access evidence, not authorization proof.

Only canonical, action-linked records reach this module. A declared access
expectation is shown separately from observed behavior; it cannot verify a BOLA.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

try:
    from capabilities.authz_selected import request_digest, selected_object_pair
except ModuleNotFoundError:
    from ..capabilities.authz_selected import request_digest, selected_object_pair


def capability_input(refs: Mapping[str, Any], capture: Mapping[str, Any], baseline: Mapping[str, Any]) -> dict[str, Any]:
    # Ordered pair for no-listing execution: selection as primary, own reference
    # as secondary. The old collection+object inventory is unchanged.
    routes = ([capture["url"], baseline["url"]] if refs.get("baseline_kind") == "own_object"
              else [baseline["url"], capture["url"]])
    return {"primary_session_ref": refs["primary_session_ref"],
            "secondary_session_ref": refs["secondary_session_ref"], "routes": routes}


def selected_outcome(
    result: dict[str, Any], proposal: Mapping[str, Any], attempt: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]], transactions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Keep proof inconclusive even when access itself was conclusively observed."""
    expected = proposal.get("expected_access", "unknown")
    result.update(cross_access_observed=False, authorization_assessment="inconclusive",
                  expected_access=expected, expectation_source="operator_declared_not_proof")
    matching = [o for o in observations if (
        o.get("kind") == "authz_differential" and o.get("mode") == "selected_object"
        and o.get("proof_type") == "selected_object_comparison" and o.get("method") == "GET"
        and o.get("proof_state") == "inconclusive" and o.get("listing_used") is False
        and o.get("principal_contexts_distinct") is True
        and o.get("selected_request_sha256") == proposal["capture_sha256"]
        and o.get("baseline_request_sha256") == proposal["baseline_sha256"]
        and o.get("resource_id_sha256") == proposal["resource_id_sha256"]
        and o.get("baseline_resource_id_sha256") == proposal["baseline_resource_id_sha256"]
    )]
    # The result may be exposed both directly and in a typed envelope. Identical
    # copies are fine; contradictory copies cannot be cherry-picked as proof.
    if not matching or any(dict(o) != dict(matching[0]) for o in matching[1:]):
        result["reason"] = "No unambiguous selected-object observation matches this proposal; rebuild current workers if the action used the listing verifier"
        return result
    observation = matching[0]
    selected: dict[str, list[int]] = {"primary": [], "secondary": []}
    own: list[int] = []
    seen: set[str] = set()
    for transaction in transactions:
        tid = str(transaction.get("id") or "")
        if (not tid or tid in seen or str(transaction.get("hunt_run_id")) != proposal["hunt_id"]
                or str(transaction.get("hunt_action_id")) != attempt["action_id"]
                or transaction.get("method") != "GET" or transaction.get("request_body_bytes") != 0
                or transaction.get("error") or not isinstance(transaction.get("url"), str)
                or type(transaction.get("status_code")) is not int):
            continue
        identity = request_digest(transaction["url"])
        slot = transaction.get("principal_slot")
        if identity == proposal["capture_sha256"] and slot in selected:
            selected[slot].append(transaction["status_code"])
        elif identity == proposal["baseline_sha256"] and slot == "secondary":
            own.append(transaction["status_code"])
        else:
            continue
        seen.add(tid)
        result["transaction_ids"].append(tid)
    result["selected_request_examined"] = bool(selected["primary"] and selected["secondary"])
    result["status_codes_by_principal"] = {k: sorted(set(v)) for k, v in selected.items()}
    result["comparison_reason"] = str(observation.get("reason") or "comparison_incomplete")[:160]
    if (own != [200] or observation.get("secondary_baseline_valid") is not True
            or type(observation.get("secondary_baseline_status")) is not int
            or observation["secondary_baseline_status"] != 200):
        result["reason"] = "The second principal's own-object baseline was not established; retry after correcting the session or capture"
        return result
    if (selected["primary"] == [200] and selected["secondary"] == [403]
            and observation.get("access_denied") is True
            and observation.get("selected_request_examined") is True
            and observation.get("owner_status") == 200 and observation.get("attacker_status") == 403
            and type(observation.get("requests_attempted")) is int and observation["requests_attempted"] == 3):
        result.update(outcome="refuted", certainty="observed", authorization_assessment="access_denied",
                      reason="The selected object was denied to the secondary principal while both reference reads succeeded; other objects and conditions remain unexamined")
        return result
    if (len(selected["primary"]) != 2 or set(selected["primary"]) != {200}
            or selected["secondary"] != [200] or observation.get("owner_repeat_stable") is not True
            or observation.get("cross_access_observed") is not True or observation.get("responses_equivalent") is not True
            or observation.get("selected_request_examined") is not True
            or observation.get("owner_status") != 200 or observation.get("attacker_status") != 200
            or type(observation.get("requests_attempted")) is not int or observation["requests_attempted"] != 4):
        result["reason"] = "No complete, stable selected-object crossing was established; inspect the action-linked responses and comparison_reason"
        return result
    result.update(cross_access_observed=True, certainty="observed", selected_request_examined=True,
                  requires_entitlement_review=expected != "allowed")
    if expected == "denied":
        result.update(authorization_assessment="potential_violation",
                      reason="The secondary principal received the exact selected object, contrary to the declared access expectation. This is an evidence-backed lead, not a verified vulnerability; independently confirm the access rule")
    elif expected == "allowed":
        result.update(authorization_assessment="shared_access_as_declared",
                      reason="The selected object is accessible to both principals, consistent with the declared shared-access expectation; no authorization violation is asserted")
    else:
        result.update(authorization_assessment="entitlement_unknown",
                      reason="Cross-principal access to the exact selected object was observed and reproduced. Establish whether this access is forbidden or legitimately shared before asserting a vulnerability")
    return result
