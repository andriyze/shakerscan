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
sys.path.insert(0, str(ROOT / "scanner"))

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

    def test_default_port_is_not_trusted_when_ui_moves(self, monkeypatch):
        monkeypatch.setenv("SHAKERSCAN_UI_PORT", "4100")
        assert not origin_is_same_deployment("http://127.0.0.1:3000", "127.0.0.1:8080")

    @pytest.mark.parametrize("scheme", ["http", "https"])
    def test_same_origin_default_port_is_allowed(self, scheme):
        assert origin_is_same_deployment(f"{scheme}://192.0.2.10", "192.0.2.10", scheme)

    def test_a_cross_site_origin_is_still_refused(self):
        assert origin_is_same_deployment("http://evil.test:3000", "172.31.33.227:8080") is False
