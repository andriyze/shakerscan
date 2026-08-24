from __future__ import annotations

import json
import urllib.request

from tests.e2e.fixtures import fixtures_server


def _request(base: str, path: str, *, method: str = "GET", body=None, headers=None):
    raw = json.dumps(body).encode() if body is not None else None
    request_headers = dict(headers or {})
    if raw is not None:
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        f"{base}{path}", data=raw, method=method, headers=request_headers,
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        content = response.read()
        return response.status, response.headers, content


def test_parity_fixture_exposes_deterministic_discovery_and_exact_request_surface():
    server = fixtures_server.start(0)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    fixtures_server.reset_parity_traffic()
    try:
        status, _, root = _request(base, "/")
        assert status == 200
        assert b"/assets/parity-app.js" in root
        assert b"/openapi.json" in root

        _, _, script = _request(base, "/assets/parity-app.js")
        assert b"/api/js-discovered" in script
        _, _, specification = _request(base, "/openapi.json")
        assert json.loads(specification)["paths"]["/dast/json"]

        status, _, exact = _request(
            base, "/dast/json", method="POST", body={"name": "exact-json"},
            headers={"X-ShakerScan-Parity-Lane": "local"},
        )
        assert status == 200
        assert json.loads(exact)["name"] == "exact-json"

        status, _, order = _request(
            base, "/authz/orders/owner-order",
            headers={"Authorization": "Bearer parity-attacker"},
        )
        assert status == 200
        assert json.loads(order)["owner"] == "parity-owner"

        _, headers, _ = _request(base, "/safe-template")
        assert headers["X-ShakerScan-Template-Fixture"] == "v1"

        traffic = fixtures_server.parity_traffic()
        assert any(item["path"] == "/dast/json" and item["method"] == "POST" for item in traffic)
        assert any(item["principal"] == "attacker" for item in traffic)
        assert all("authorization" not in item for item in traffic)
        assert all("body" not in item for item in traffic)
        assert fixtures_server.parity_connections() >= 1
    finally:
        server.shutdown()
        server.server_close()
