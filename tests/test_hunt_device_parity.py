"""A connected device is authorized and examined like any other target.

The same host was reachable as a web target and not as a device: the device could not hold a
standing authorization at all, its Hunt was offered six capabilities against twenty-eight, and
every web capability that reached it failed on a different layer that assumed a device could
not be an HTTP asset.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from capabilities.network import CapabilityInputError  # noqa: E402
from hunt.contracts import allowed_capability_names  # noqa: E402
from hunt.start_contract import normalize_hunt_start_payload  # noqa: E402
from hunt.target_binding import web_hunt_target  # noqa: E402
from runtime.capability_registry import CAPABILITY_REGISTRY  # noqa: E402

DEVICE_ID = "99ba2c18-fdca-4e9d-bf66-ca56e97d3af6"
WEB_ID = "f9ac8c85-947c-4aba-9ac7-173644f627fc"
AUTHORIZED = {
    "active_testing": True, "network_discovery": True,
    "authorization_confirmed": True, "approval_receipt_id": "receipt-1",
}


def contract(kind):
    return normalize_hunt_start_payload({
        "target_id": DEVICE_ID if kind == "device" else WEB_ID,
        "target_kind": kind, "goal": "examine the service", "policy": AUTHORIZED,
    })


class TestOneAssetReachesTheSameCapabilities:
    def test_a_device_is_offered_the_http_capabilities(self):
        names = set(allowed_capability_names(contract("device"), credentials_available=False))
        assert {
            "http.request", "web.crawl", "web.probe", "tls.inspect", "javascript.analyze",
        } <= names

    def test_a_device_keeps_its_own_capabilities(self):
        names = set(allowed_capability_names(contract("device"), credentials_available=False))
        assert {"device.inspect", "device.http.probe", "device.scan"} <= names

    def test_a_device_reaches_the_same_count_as_a_web_target(self):
        device = allowed_capability_names(contract("device"), credentials_available=False)
        web = allowed_capability_names(contract("web"), credentials_available=False)
        assert len(device) >= len(web) - 4, (len(device), len(web))
        assert len(device) > 6, "a device Hunt used to hold six capabilities"

    def test_a_web_target_is_never_offered_device_capabilities(self):
        names = set(allowed_capability_names(contract("web"), credentials_available=False))
        assert not {name for name in names if name.startswith("device.")}


class TestTheHttpBindingAcceptsEitherInventory:
    """A device records a bare locator, not a URL, and its row uses device_target_id."""

    def binding(self, **context):
        run = {
            "target_kind": "device", "target_id": None, "device_target_id": DEVICE_ID,
        }
        return web_hunt_target(run, context, {"scope_receipt_id": "scope-1"})

    def test_a_bare_locator_becomes_a_usable_binding(self):
        target, url = self.binding(
            target={"locator": "172.31.33.227"},
            authorized_target_addresses=["172.31.33.227"],
        )
        assert url == "http://172.31.33.227"
        assert target.canonical_host == "172.31.33.227"
        assert target.target_id == DEVICE_ID
        assert target.target_kind == "device"
        assert target.allowed_addresses == ("172.31.33.227",)

    def test_an_ipv6_locator_is_bracketed(self):
        target, url = self.binding(target={"locator": "2001:db8::10"})
        assert url == "http://[2001:db8::10]"
        assert target.canonical_host == "2001:db8::10"

    def test_a_locator_that_already_has_a_scheme_is_left_alone(self):
        _target, url = self.binding(target={"locator": "https://cam.example.test"})
        assert url == "https://cam.example.test"

    def test_a_web_target_binding_is_unchanged(self):
        run = {"target_kind": "web", "target_id": WEB_ID, "device_target_id": None}
        target, url = web_hunt_target(
            run, {"target": {"url": "http://172.31.33.227:8443"}}, {},
        )
        assert url == "http://172.31.33.227:8443"
        assert target.target_id == WEB_ID

    def test_a_run_naming_no_asset_at_all_is_still_refused(self):
        run = {"target_kind": "device", "target_id": None, "device_target_id": None}
        with pytest.raises(CapabilityInputError, match="requires a Web, API, network or device"):
            web_hunt_target(run, {"target": {"locator": "172.31.33.227"}}, {})

    def test_an_unusable_locator_is_refused(self):
        with pytest.raises(CapabilityInputError, match="persisted Hunt target URL is invalid"):
            self.binding(target={})


class TestExecutionRoutesByPlacementNotByTargetKind:
    """Sending every capability in a device Hunt down the device adapter made `http.request`
    answer "Native device Hunt adapter state is unavailable" instead of reaching the service."""

    def routes_to_device_adapter(self, capability: str) -> bool:
        spec = CAPABILITY_REGISTRY.require(capability)
        return (
            not capability.startswith("collections.")
            and str(spec.hunt_executor or "").startswith("device")
        )

    @pytest.mark.parametrize("capability", [
        "device.inspect", "device.http.probe", "device.scan", "device.service.verify",
    ])
    def test_a_device_capability_takes_the_device_adapter(self, capability):
        assert self.routes_to_device_adapter(capability) is True

    @pytest.mark.parametrize("capability", [
        "http.request", "web.crawl", "tls.inspect", "browser.navigate", "javascript.analyze",
    ])
    def test_a_web_capability_takes_the_ordinary_path(self, capability):
        assert self.routes_to_device_adapter(capability) is False


def test_the_worker_and_the_control_plane_resolve_one_target_id():
    """The control plane digests a device Hunt by its device id. Reading only the web id in
    the worker made every queued capability on a device fail as a payload mismatch."""
    worker = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    control = (ROOT / "api" / "hunt" / "interaction_router.py").read_text(encoding="utf-8")
    assert 'target_id=run["target_id"],\n' not in worker, (
        "a digest site still reads only the web id"
    )
    assert worker.count('target_id=run["device_target_id"] or run["target_id"],') >= 4
    assert 'target_id=run["device_target_id"] or run["target_id"],' in control


def test_a_device_standing_authorization_is_recorded_and_read_from_either_inventory():
    """`POST /targets/{id}/authorization` answered 404 for a device, so a device was the one
    asset whose permission could not be recorded once and reused."""
    source = (ROOT / "api" / "target_authorization.py").read_text(encoding="utf-8")
    assert "FROM device_targets WHERE id=$1" in source
    router = (ROOT / "api" / "targets" / "router.py").read_text(encoding="utf-8")
    assert "UNION ALL SELECT 1 FROM device_targets" in router


def test_a_device_scan_reuses_the_standing_authorization():
    source = (ROOT / "api" / "devices" / "router.py").read_text(encoding="utf-8")
    assert "_device_has_standing_authorization" in source
    assert "POST /targets/{device_id}/authorization" in source


def test_an_operator_named_port_needs_no_discovery_scan():
    """A device locator cannot carry a port, so requiring a scan first made a known port
    unreachable and unsayable."""
    source = (ROOT / "api" / "devices" / "router.py").read_text(encoding="utf-8")
    assert "_device_operator_named_web_origin" in source
    assert "port directly with origin_port" in source
