"""A device candidate verification must reserve the traffic it is about to authorize.

`candidate.verify` on a device Hunt charged a flat 40 HTTP requests and one fragility point, then
queued a full device inventory scan plus up to eight standard web children. Each of those children
carries its own imported-request ceiling, so a forty-request reservation authorized thousands of
downstream requests and a hundred-port sweep the Hunt's multidimensional budget never saw --
budget-before-execution held for the parent action and nothing beneath it.

The charge is now derived from the same constants the fan-out actually uses, so it cannot drift
away from what is queued: if the Hunt cannot fund the fan-out, the reservation fails and the queue
is refused.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))

from device_agent import device_verification_fanout_budget  # noqa: E402
from scanner_tools.device_posture import INVENTORY_UDP_PORTS  # noqa: E402
from scanner_tools.device_web import IMPORTED_REQUEST_LIMITS  # noqa: E402


def test_a_web_bearing_verification_reserves_every_child_it_can_queue():
    budget = device_verification_fanout_budget(
        contract_id="device.tls", web_scan_type="standard", max_web_origins=8,
    )
    # Eight origins, each allowed the standard imported-request ceiling. Reserving 40 for this was
    # the escape: the parent could fund a fraction of one child.
    assert budget["http_requests"] >= 8 * IMPORTED_REQUEST_LIMITS["standard"]
    # The inventory sweep is port traffic the Hunt must also account for.
    assert budget["tcp_ports_attempted"] >= 100
    assert budget["udp_ports_attempted"] >= len(INVENTORY_UDP_PORTS)
    assert budget["device_fragility_points"] >= 1


def test_the_charge_tracks_the_constants_rather_than_a_frozen_number():
    # Halving the origins must halve the reserved request ceiling, or the charge has drifted away
    # from what the fan-out queues.
    eight = device_verification_fanout_budget(
        contract_id="device.tls", web_scan_type="standard", max_web_origins=8)
    four = device_verification_fanout_budget(
        contract_id="device.tls", web_scan_type="standard", max_web_origins=4)
    assert eight["http_requests"] - four["http_requests"] == 4 * IMPORTED_REQUEST_LIMITS["standard"]

    deep = device_verification_fanout_budget(
        contract_id="device.tls", web_scan_type="deep", max_web_origins=8)
    assert deep["http_requests"] > eight["http_requests"]


def test_a_verification_that_queues_no_web_children_is_not_overcharged():
    # service_exposure probes one fixed port and queues no web scan; charging it for eight web
    # children would make an honest verification unaffordable.
    service = device_verification_fanout_budget(
        contract_id="device.service_exposure", web_scan_type="standard", max_web_origins=0,
    )
    assert service["http_requests"] < IMPORTED_REQUEST_LIMITS["standard"]
    assert service["tcp_ports_attempted"] >= 1


def test_control_plane_contracts_queue_nothing_and_cost_nothing_downstream():
    # These return without queueing a scan at all.
    for contract in ("device.control_authorization", "device.firmware_advisory"):
        budget = device_verification_fanout_budget(
            contract_id=contract, web_scan_type="standard", max_web_origins=8,
        )
        assert budget.get("http_requests", 0) == 0, contract
        assert budget.get("tcp_ports_attempted", 0) == 0, contract


def test_every_returned_dimension_is_a_non_negative_int():
    budget = device_verification_fanout_budget(
        contract_id="device.auth_bypass", web_scan_type="standard", max_web_origins=8)
    assert budget
    for name, amount in budget.items():
        assert isinstance(amount, int) and amount >= 0, (name, amount)


def test_the_tcp_port_count_is_read_from_the_profile_not_assumed():
    # The profile field is `tcp_args`; an accessor that silently missed it would fall through to a
    # constant that happened to match today and would stop tracking the profile tomorrow.
    import device_agent
    from scanner_tools.device_posture import PROFILES

    assert device_agent._inventory_tcp_port_count() == 100
    inventory = PROFILES["inventory"]
    assert "--top-ports" in inventory.tcp_args, "profile shape changed; the accessor must follow"

    class _FullSweep:
        tcp_args = ("-p-",)

    original = dict(device_agent.DEVICE_SCAN_PROFILES)
    try:
        device_agent.DEVICE_SCAN_PROFILES = {"inventory": _FullSweep()}
        assert device_agent._inventory_tcp_port_count() == 65_535
        # An unrecognised specification must charge a full sweep, never a small default:
        # under-reserving is exactly how the fan-out escaped the budget.
        class _Unknown:
            tcp_args = ("--something-new",)

        device_agent.DEVICE_SCAN_PROFILES = {"inventory": _Unknown()}
        assert device_agent._inventory_tcp_port_count() == 65_535
    finally:
        device_agent.DEVICE_SCAN_PROFILES = original


def test_the_reservation_mirrors_the_values_the_fanout_actually_passes():
    """The charge is computed from constants in the router; the queue call lives in the devices
    router. If those drift apart the reservation silently stops covering the traffic, which is the
    original defect wearing a different shape."""
    from tests.api_sources import definition_source

    fanout = definition_source("_device_verify_candidate_tool")
    router = Path("api/hunt/interaction_router.py").read_text(encoding="utf-8")

    # What the fan-out queues.
    assert 'web_scan_type="standard"' in fanout
    assert "max_web_origins=8 if include_web else 0" in fanout
    assert 'include_web = contract_id in {"device.tls", "device.auth_bypass"}' in fanout

    # What the reservation assumes.
    assert '_DEVICE_VERIFICATION_WEB_SCAN_TYPE = "standard"' in router
    assert "_DEVICE_VERIFICATION_MAX_WEB_ORIGINS = 8" in router
    assert (
        '_DEVICE_VERIFICATION_WEB_CONTRACTS: frozenset[str] = frozenset({"device.tls", "device.auth_bypass"})'
        in router
    )


def test_the_flat_forty_request_charge_is_gone():
    router = Path("api/hunt/interaction_router.py").read_text(encoding="utf-8")
    assert 'charges["http_requests"] = 40' not in router, (
        "the device verification parent must charge its fan-out, not a flat constant"
    )
    assert "device_verification_fanout_budget(" in router
