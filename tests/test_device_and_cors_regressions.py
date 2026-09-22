"""Three regressions introduced by widening what a device Hunt and a browser may do.

Each was reported against a merged change, reproduced here, and is asserted as a boundary
rather than as the shape of the code that fixes it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from public_api_contract import origin_is_same_deployment  # noqa: E402


class TestOnlyThisDeploymentsOwnWebPortsAreAdmitted:
    """Comparing only the host admitted every other service on that address: anything a
    person happens to run on the same machine could serve a page that drives this API."""

    @pytest.mark.parametrize(("origin", "host"), [
        ("http://172.31.33.227:3000", "172.31.33.227:8080"),
        ("http://172.31.33.227:8080", "172.31.33.227:8080"),
        ("http://127.0.0.1:3000", "127.0.0.1:8080"),
    ])
    def test_the_ui_and_the_api_port_are_admitted(self, origin, host):
        assert origin_is_same_deployment(origin, host) is True

    @pytest.mark.parametrize("port", [9999, 1234, 8000, 5000])
    def test_another_service_on_the_same_address_is_refused(self, port):
        assert origin_is_same_deployment(
            f"http://172.31.33.227:{port}", "172.31.33.227:8080",
        ) is False

    def test_the_reported_reproduction_is_refused(self):
        """A POST from 127.0.0.1:9999 to the API on 8080 was answered 200 with an
        allow-origin header while only port 3000 was configured."""
        assert origin_is_same_deployment("http://127.0.0.1:9999", "127.0.0.1:8080") is False

    def test_a_default_port_service_is_refused(self):
        assert origin_is_same_deployment("http://172.31.33.227", "172.31.33.227:8080") is False

    def test_a_configured_ui_port_is_honoured(self, monkeypatch):
        monkeypatch.setenv("SHAKERSCAN_UI_PORT", "4100")
        assert origin_is_same_deployment(
            "http://172.31.33.227:4100", "172.31.33.227:8080",
        ) is True
        assert origin_is_same_deployment(
            "http://172.31.33.227:9999", "172.31.33.227:8080",
        ) is False

    def test_a_cross_site_origin_is_still_refused(self):
        assert origin_is_same_deployment("http://evil.test:3000", "172.31.33.227:8080") is False


def test_every_capability_that_reaches_a_device_answers_to_its_safety_state():
    """Gating the device policy on the adapter let a web capability in a device Hunt send
    traffic through a frozen circuit breaker, past the request pacing, at zero fragility."""
    source = (ROOT / "api" / "hunt" / "interaction_router.py").read_text(encoding="utf-8")
    assert "sends_device_traffic" in source
    assert "if sends_device_traffic:" in source
    assert "if is_device_adapter:\n" not in source.split("sends_device_traffic", 1)[1][:400], (
        "the admission check must not fall back to the adapter-only condition"
    )
    # A device run reaches the check through network reachability, not through placement.
    marker = source.split("sends_device_traffic = ", 1)[1][:300]
    assert 'str(run["target_kind"]) == "device"' in marker
    assert "network_reachability" in marker


def test_a_web_capability_on_a_device_is_charged_fragility():
    source = (ROOT / "api" / "hunt" / "interaction_router.py").read_text(encoding="utf-8")
    block = source.split("sends_device_traffic:", 1)[1][:700]
    assert "device_fragility_points" in block
    assert "device_http_request" in block, "metered like the device's own HTTP probe"


def test_the_network_and_browser_bindings_accept_a_device():
    """Both advertised capabilities answered 422 "bindings require a canonical host",
    because a device stores a bare locator and its id in device_target_id."""
    source = (ROOT / "api" / "hunt" / "interaction_router.py").read_text(encoding="utf-8")
    assert source.count("_device_locator_url(target_context)") >= 2
    assert source.count('str(run["target_id"] or run["device_target_id"])') >= 2
    assert 'target_id=str(run["target_id"]),' not in source, (
        "a binding still reads only the web id"
    )


def test_the_locator_helper_builds_one_usable_url():
    """Imported by source rather than module, because importing the router pulls in the
    browser capability stack, which is not loadable in this partition."""
    source = (ROOT / "api" / "hunt" / "interaction_router.py").read_text(encoding="utf-8")
    body = source.split("def _device_locator_url(", 1)[1].split("\n\n\n", 1)[0]
    namespace: dict = {}
    exec("def _device_locator_url(" + body, {"Mapping": dict, "Any": object}, namespace)
    helper = namespace["_device_locator_url"]
    assert helper({"locator": "172.31.33.227"}) == "http://172.31.33.227"
    assert helper({"locator": "2001:db8::10"}) == "http://[2001:db8::10]"
    assert helper({"locator": "https://cam.test"}) == "https://cam.test"
    assert helper({}) == ""
