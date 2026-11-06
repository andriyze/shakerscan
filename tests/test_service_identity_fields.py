"""Protocol, version build and authentication are separate, allowlisted service claims."""

from api.exposure.service_inventory import normalized_observation
from scanner.scanner_tools import service_identity


def _row(**extras):
    return {"kind": "service", "address": "192.0.2.1", "transport": "tcp", "port": 6379,
            "state": "open", "service": "redis", "method": "probed", **extras}


def test_authentication_defaults_to_not_tested_for_a_handshake():
    observation = normalized_observation(_row(protocol="redis", product="Redis", version="7.2.4"))
    assert observation["protocol"] == "redis"
    assert observation["authentication"] == "not_tested"
    assert observation["authentication_proof"] is None


def test_an_access_claim_needs_a_known_proof_code():
    proven = normalized_observation(_row(
        protocol="redis", authentication="not_required",
        authentication_proof="redis_info_without_credentials",
    ))
    assert proven["authentication"] == "not_required"
    assert proven["authentication_proof"] == "redis_info_without_credentials"
    # A report cannot invent a state or a proof the adapters never produce.
    forged = normalized_observation(_row(authentication="open", authentication_proof="trust me"))
    assert forged["authentication"] == "not_tested" and forged["authentication_proof"] is None
    unproven = normalized_observation(_row(
        authentication="not_tested", authentication_proof="redis_info_without_credentials",
    ))
    assert unproven["authentication_proof"] is None


def test_a_port_hint_carries_no_protocol_or_access_claim():
    observation = normalized_observation(_row(
        method="table", protocol="redis", authentication="not_required",
        authentication_proof="redis_info_without_credentials",
    ))
    assert observation["service"] == "unknown"
    assert observation["protocol"] is None
    assert observation["authentication"] == "not_tested"


def test_reported_version_keeps_the_build_suffix_and_is_bounded():
    fields = service_identity.identity_fields({
        "protocol": "SSH", "product": "OpenSSH", "version": "8.9p1",
        "version_reported": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\x1b[31m" + "x" * 400,
        "version_basis": "reported",
    })
    assert fields["protocol"] == "ssh"
    assert fields["version_reported"].startswith("OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
    assert "\x1b" not in fields["version_reported"] and len(fields["version_reported"]) == 200
    assert fields["version_basis"] == "reported"
    assert service_identity.identity_fields({"version_basis": "reported"})["version_basis"] is None


def test_the_port_hint_is_only_a_hint():
    assert service_identity.port_hint(6379) == "redis"
    assert service_identity.port_hint(40000) is None
