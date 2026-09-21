"""The Hunt start contract resolves what it can and reports it, instead of refusing.

Every case here refused with a 422 before, on a rule the operator had no way to answer from
the message. The authorization gate itself is unchanged and still refuses; what changed is
everything that was only a restatement of what the operator had already asked for.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from hunt.contracts import allowed_capability_names  # noqa: E402
from hunt.start_contract import (  # noqa: E402
    MAX_DIRECT_ORIGIN_ADDRESSES,
    MAX_SKILLS,
    HuntStartContractError,
    normalize_hunt_start_payload,
)
from hunt.skills import MAX_SKILLS_PER_HUNT  # noqa: E402

TARGET = "11111111-1111-1111-1111-111111111111"
AUTHORIZED = {"authorization_confirmed": True, "approval_receipt_id": "receipt-1"}
SUB_AUTHORITIES = [
    "allow_state_changing_http",
    "network_discovery",
    "allow_oob_interactions",
    "allow_identity_headers",
]


def start(policy, *, target_kind="web", **extra):
    payload = {
        "target_id": TARGET, "target_kind": target_kind, "goal": "find bugs",
        "policy": {**AUTHORIZED, **policy}, **extra,
    }
    return normalize_hunt_start_payload(payload)


@pytest.mark.parametrize("authority", SUB_AUTHORITIES)
def test_a_sub_authority_implies_active_testing_instead_of_refusing(authority):
    contract = start({authority: True})
    assert contract.policy.active_testing is True
    assert getattr(contract.policy, authority) is True
    assert any(
        "active_testing was enabled" in line and authority in line
        for line in contract.adjustments
    ), contract.adjustments


def test_several_sub_authorities_are_named_in_one_adjustment():
    contract = start({"allow_state_changing_http": True, "network_discovery": True})
    (line,) = [item for item in contract.adjustments if "active_testing" in item]
    assert "allow_state_changing_http" in line and "network_discovery" in line


def test_an_explicit_active_policy_records_no_implication():
    contract = start({"active_testing": True, "allow_state_changing_http": True})
    assert contract.policy.active_testing is True
    assert not [item for item in contract.adjustments if "active_testing was enabled" in item]


def test_a_passive_request_stays_passive():
    contract = start({})
    assert contract.policy.active_testing is False
    assert list(contract.adjustments) == []


def test_a_budget_without_its_authority_resolves_to_zero_and_says_so():
    """The same request used to resolve silently or hard-refuse, decided only by whether the
    caller wrote the number down."""
    contract = start({}, budgets={"max_tcp_ports": 50, "max_http_requests": 100})
    assert "max_tcp_ports" not in contract.budgets
    assert contract.budgets["max_http_requests"] == 100
    assert contract.resolved_budget["max_tcp_ports"] == 0
    assert any(
        "resolved to 0" in line and "max_tcp_ports" in line
        for line in contract.adjustments
    ), contract.adjustments


def test_a_funded_dimension_whose_authority_is_on_is_untouched():
    contract = start({"network_discovery": True}, budgets={"max_tcp_ports": 50})
    assert contract.budgets["max_tcp_ports"] == 50
    assert contract.resolved_budget["max_tcp_ports"] == 50
    assert not [item for item in contract.adjustments if "resolved to 0" in item]


def test_an_unvalidated_privileged_policy_reports_that_it_runs_passively():
    """The run was stored with every authority off and said nothing, so a Hunt that did no
    active work looked like a Hunt that found nothing."""
    contract = start({"active_testing": True, "allow_state_changing_http": True})
    (line,) = [
        item for item in contract.resolution_adjustments(approval_validated=False)
        if "runs passively" in item
    ]
    assert "active_testing" in line and "allow_state_changing_http" in line
    assert "POST /targets/{target_id}/authorization" in line


def test_a_validated_approval_reports_no_downgrade():
    contract = start({"active_testing": True})
    assert not [
        item for item in contract.resolution_adjustments(approval_validated=True)
        if "runs passively" in item
    ]


def test_a_passive_run_is_not_described_as_a_downgrade():
    contract = start({})
    assert contract.resolution_adjustments(approval_validated=False) == []


def test_adjustments_reach_the_public_contract():
    contract = start({"network_discovery": True})
    assert contract.public_dict()["policy_adjustments"] == list(contract.adjustments)


class TestDirectOriginAddressPolicy:
    """The field used to carry its own hardcoded refusal list, so a deployment that admitted
    192.168.1.50 as a target refused the same address as a direct origin."""

    def addresses(self, *values):
        return start(
            {"allow_direct_origin": True}, direct_origin_addresses=list(values),
        ).direct_origin_addresses

    def test_private_addresses_follow_the_deployment_that_admits_private_targets(
        self, monkeypatch,
    ):
        monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
        assert self.addresses("192.168.1.50", "10.0.0.8") == ("192.168.1.50", "10.0.0.8")

    def test_private_addresses_are_refused_where_the_deployment_refuses_them(
        self, monkeypatch,
    ):
        monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
        with pytest.raises(HuntStartContractError, match="private, local, or non-routable"):
            self.addresses("192.168.1.50")

    @pytest.mark.parametrize("policy", ["allow", "refuse"])
    @pytest.mark.parametrize(
        "address", ["169.254.169.254", "224.0.0.1", "0.0.0.0", "255.255.255.255"],
    )
    def test_never_routable_addresses_stay_refused_under_every_policy(
        self, monkeypatch, policy, address,
    ):
        monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", policy)
        with pytest.raises(HuntStartContractError):
            self.addresses(address)

    def test_a_public_address_is_admitted_under_every_policy(self, monkeypatch):
        monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "refuse")
        assert self.addresses("203.0.113.9") == ("203.0.113.9",)

    def test_hostnames_are_still_refused(self, monkeypatch):
        monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", "allow")
        with pytest.raises(HuntStartContractError, match="literal IP addresses"):
            self.addresses("origin.example.com")


def test_a_network_hunt_can_speak_http_to_what_it_finds():
    """A network Hunt held ports.discover, service.fingerprint and subdomains.discover: it
    could find an open port and had nothing that could send a request to it."""
    policy = {"active_testing": True, "network_discovery": True}
    names = allowed_capability_names(
        start(policy, target_kind="network"), credentials_available=False,
    )
    assert {"http.request", "web.crawl", "web.probe", "tls.inspect"} <= set(names)
    assert {"ports.discover", "service.fingerprint"} <= set(names)
    assert len(names) > 3


def test_a_network_hunt_is_not_wider_than_a_web_hunt():
    policy = {"active_testing": True, "network_discovery": True}
    web = set(allowed_capability_names(start(policy), credentials_available=False))
    network = set(allowed_capability_names(
        start(policy, target_kind="network"), credentials_available=False,
    ))
    assert network <= web | {"ports.discover", "service.fingerprint", "subdomains.discover"}


def test_the_skill_cap_matches_the_library_and_leaves_room_for_a_real_engagement():
    assert MAX_SKILLS == MAX_SKILLS_PER_HUNT
    assert MAX_SKILLS >= 12


def test_direct_origin_addresses_cover_both_families_with_failover():
    assert MAX_DIRECT_ORIGIN_ADDRESSES >= 32
    with pytest.raises(HuntStartContractError, match="at most"):
        start(
            {"allow_direct_origin": True},
            direct_origin_addresses=[
                f"203.0.113.{index}" for index in range(MAX_DIRECT_ORIGIN_ADDRESSES + 1)
            ],
        )


def test_the_authorization_gate_itself_still_refuses():
    """Nothing here loosens the trust boundary: privileged authority without a confirmed
    authorization is still refused, and the refusal still names the remedy."""
    with pytest.raises(HuntStartContractError, match="authorization_confirmed"):
        normalize_hunt_start_payload({
            "target_id": TARGET, "target_kind": "web", "goal": "g",
            "policy": {"allow_state_changing_http": True},
        })
    with pytest.raises(HuntStartContractError, match="/targets/\\{target_id\\}/authorization"):
        normalize_hunt_start_payload({
            "target_id": TARGET, "target_kind": "web", "goal": "g",
            "policy": {"active_testing": True, "authorization_confirmed": True},
        })
