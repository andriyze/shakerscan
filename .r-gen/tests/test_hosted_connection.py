"""Hosted connector fixtures: no tenant deployment or real scanning."""

import io
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import hosted_connection as hosted


def test_credentials_are_private_origin_bound_and_expiring(tmp_path):
    path = tmp_path / "connection.json"
    data = {
        "origin": "https://tenant.example.com",
        "access_token": "ss_conn_fixture",
        "expires_at": time.time() + 100,
    }
    hosted.save(path, data)
    assert hosted.load(path) == data
    assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        hosted.save(path, data)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        hosted.load(path)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        hosted.load(link)
    path.write_text(json.dumps({**data, "expires_at": 0}))
    with pytest.raises(ValueError):
        hosted.load(path)
    assert hosted.load(path, allow_expired=True)["expires_at"] == 0


def test_authenticated_adapter_requires_https_and_never_advertises_hunt():
    with pytest.raises(ValueError):
        hosted.HostedClient("http://remote.example.com", api_token="ss_conn_fixture")

    class Fixture(hosted.HostedClient):
        def request_json(self, method, path, payload=None):
            assert method == "GET"
            assert path in self.routes.values()
            return {
                "schema": "shakerscan.workspace-capabilities/v1",
                "mode": "managed",
                "features": {"targets": {"state": "enabled"}, "findings": {"state": "enabled"}},
            }

    client = Fixture("https://tenant.example.com", api_token="ss_conn_fixture")
    assert {x["name"] for x in client.list_tools()} == set(client.routes)
    with pytest.raises(hosted.MCPError):
        client.call_tool("shakerscan_hunt_start", {})
    with pytest.raises(hosted.MCPError):
        client.call_tool("shakerscan_targets", {"url": "https://evil.example"})
    output = io.BytesIO()
    hosted.serve(
        hosted.MCPServer(client),
        io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'),
        output,
    )
    assert b"ss_conn_fixture" not in output.getvalue()
    assert b"shakerscan_hunt_start" not in output.getvalue()
