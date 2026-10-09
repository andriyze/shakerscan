"""Effective Hunt authority from the baseline plus live grants (R1, external release audit,
2026-10-09). Pure functions; the PostgreSQL behaviour (locks, admission, migration) is in
``test_hunt_grant_revocation_postgres``. Grant rows here are unit fixtures shaped like the stored rows.
"""
from __future__ import annotations

import json

from hunt.grant_authority import (
    authority_diff,
    baseline_from_policy,
    effective_policy,
    grant_fields,
    reconstruct_baseline,
)

START = {
    "schema_version": "hunt-policy/v2", "active_testing": False, "allow_state_changing_http": False,
    "allow_oob_interactions": False, "network_discovery": False, "mutation_allowed": False,
    "approval_receipt_id": "receipt-1", "allowed_capabilities": ["http.request", "web.probe"],
}


def capability(capability_name, flag, *, created, **effect):
    return {"id": created, "created_at": created, "kind": "capability.enable",
            "subject_json": json.dumps({"capability": capability_name, "flag": flag}),
            "effect_json": json.dumps({"flag": flag, "capability": capability_name, **effect})}


def destination(origin, request_id, *, created):
    return {"id": created, "created_at": created, "kind": "target.authorize", "request_id": request_id,
            "subject_json": {}, "effect_json": {"destination": {"origin": origin, "request_id": request_id}}}


def test_a_field_is_on_while_the_baseline_or_any_live_grant_holds_it():
    baseline = baseline_from_policy(START)
    write = capability("http.request", "state-changing", created="1")
    discovery = capability("service.snmp.inspect", "tcp-discovery", created="2")
    both = effective_policy(START, baseline, [write, discovery])
    assert both["allow_state_changing_http"] and both["mutation_allowed"] and both["network_discovery"]
    only_discovery = effective_policy(both, baseline, [discovery])
    assert only_discovery["active_testing"] and only_discovery["network_discovery"]
    assert not only_discovery["allow_state_changing_http"] and not only_discovery["mutation_allowed"]
    none = effective_policy(only_discovery, baseline, [])
    assert {key: none[key] for key in ("active_testing", "network_discovery", "allow_state_changing_http")} == {
        "active_testing": False, "network_discovery": False, "allow_state_changing_http": False}
    assert none["allowed_capabilities"] == ["http.request", "web.probe"]
    assert none["approval_receipt_id"] == "receipt-1" and none["schema_version"] == "hunt-policy/v2"


def test_a_recorded_field_list_wins_over_the_flag_table():
    recorded = capability("xss.verify", "state-changing", created="1", fields_enabled=["active_testing"])
    assert grant_fields(recorded) == ("active_testing",)
    legacy = capability("xss.verify", "state-changing", created="1")  # 2.8.0: no fields_enabled
    assert grant_fields(legacy) == ("active_testing", "allow_state_changing_http")
    assert grant_fields(capability("x", "s", created="1", fields_enabled=["approval_receipt_id"])) == ()


def test_a_destination_two_live_grants_authorize_survives_revoking_either():
    baseline = baseline_from_policy(START)
    first = destination("https://api.example.test:8443", "request-1", created="1")
    second = destination("https://api.example.test:8443", "request-2", created="2")
    both = effective_policy(START, baseline, [first, second])
    assert [item["request_id"] for item in both["granted_destinations"]] == ["request-1"]
    # The entry names a live grant's request, which dispatch re-checks.
    after = effective_policy(both, baseline, [second])
    assert [item["request_id"] for item in after["granted_destinations"]] == ["request-2"]
    assert effective_policy(after, baseline, [])["granted_destinations"] == []


def test_the_reconstructed_baseline_of_a_2_8_0_hunt_is_its_authority_before_any_grant():
    # 2.8.0 after: grant A (writes), grant B (discovery), revoke A, revoke B.
    before_a = {key: START[key] for key in (
        "active_testing", "allow_state_changing_http", "allow_oob_interactions", "network_discovery",
        "mutation_allowed", "approval_receipt_id")}
    after_a = {**before_a, "active_testing": True, "allow_state_changing_http": True, "mutation_allowed": True}
    grants = [
        capability("service.snmp.inspect", "tcp-discovery", created="2", policy_before=after_a, capability_added=True),
        capability("http.request", "state-changing", created="1", policy_before=before_a, capability_added=False),
        destination("https://other.example.test", "request-9", created="3"),
    ]
    corrupted = {**START, **after_a, "granted_destinations": [{"origin": "https://other.example.test",
                                                               "request_id": "request-9"}]}
    baseline = reconstruct_baseline(corrupted, grants)
    assert baseline["flags"] == {key: False for key in baseline["flags"]}
    assert baseline["allowed_capabilities"] == ["http.request", "web.probe"]
    assert baseline["granted_destinations"] == []
    repaired = effective_policy(corrupted, baseline, [])
    assert not repaired["allow_state_changing_http"] and not repaired["mutation_allowed"]


def test_the_diff_names_fields_capabilities_and_origins_only():
    baseline = baseline_from_policy(START)
    granted = effective_policy(START, baseline, [capability("xss.verify", "oob", created="1"),
                                                 destination("https://a.example.test", "r", created="2")])
    diff = authority_diff(granted, effective_policy(granted, baseline, []))
    assert diff == {"flags_on": [], "flags_off": ["active_testing", "allow_oob_interactions"],
                    "capabilities_added": [], "capabilities_removed": ["xss.verify"],
                    "destinations_added": [], "destinations_removed": ["https://a.example.test"]}


def test_the_reconstructed_flags_do_not_depend_on_grant_order():
    """Two 2.8.0 grants in one transaction share ``created_at`` and their ids are random; the
    baseline is the intersection of every recorded ``policy_before``, whatever the order."""
    start = {key: False for key in ("active_testing", "allow_state_changing_http", "allow_oob_interactions",
                                     "network_discovery", "mutation_allowed")}
    later = {**start, "active_testing": True, "network_discovery": True}
    grants = [
        capability("xss.verify", "active-testing", created="t", policy_before=start, capability_added=True),
        capability("service.snmp.inspect", "tcp-discovery", created="t", policy_before=later, capability_added=True),
    ]
    forward = reconstruct_baseline({**START, **later}, grants)
    backward = reconstruct_baseline({**START, **later}, list(reversed(grants)))
    assert forward == backward
    assert not any(forward["flags"].values())


def test_coverage_keys_name_what_a_bound_covers():
    from hunt.grant_authority import coverage_key

    assert coverage_key("capability.enable", {"capability": "http.request", "flag": "state-changing"}) == \
        "capability:state-changing"
    assert coverage_key("target.authorize", json.dumps({"host": "API.example.test.", "port": 443,
                                                        "scheme": "https"})) == "target:https://api.example.test:443"
    assert coverage_key("credential.use", {"profile_id": "p-1"}) == "credential:p-1"
    assert coverage_key("budget.raise", {"dimension": "max_http_requests"}) is None
    assert coverage_key("capability.enable", "[1]") is None


def test_withholding_is_by_distinctive_field_not_by_flag_name():
    from hunt.grant_authority import withheld_flags

    assert withheld_flags(("active_testing", "allow_state_changing_http")) == ["active-replay", "state-changing"]
    assert withheld_flags(("active_testing", "network_discovery")) == ["tcp-discovery"]
    assert withheld_flags(("active_testing", "allow_oob_interactions")) == ["oob"]
    assert withheld_flags(("active_testing",)) == ["active-testing"]
