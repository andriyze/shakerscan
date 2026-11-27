"""Small hosted CLI/MCP connector. No Docker, local scanner or provider credentials."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import ClassVar

from shakerscan_mcp import ArsenalClient, MCPError, MCPServer, _NoRedirect, serve


def origin(value):
    p = urllib.parse.urlsplit(value)
    if (
        p.scheme != "https"
        or not p.hostname
        or p.username
        or p.password
        or p.path not in ("", "/")
        or p.query
        or p.fragment
    ):
        raise ValueError("Specify a tenant HTTPS origin, without credentials or a path")
    return value.rstrip("/")


def request(base, path, body=None, token=None):
    req = urllib.request.Request(
        base + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **({"Authorization": "Bearer " + token} if token else {}),
        },
    )
    try:
        response = urllib.request.build_opener(_NoRedirect()).open(req, timeout=15)
    except urllib.error.HTTPError as e:
        response = e
    with response:
        raw = response.read(64001)
        if len(raw) > 64000:
            raise ValueError("Oversized server response")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("Invalid server response")
        return response.code, data


def save(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)


def load(path, *, allow_expired=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Connection file must be owned by you with permissions 0600")
        data = json.loads(f.read(4097))
    origin(data["origin"])
    if not allow_expired and data["expires_at"] <= time.time():
        raise ValueError("Connection expired. Remove it with logout, then sign in again.")
    if (
        not isinstance(data.get("access_token"), str)
        or not data["access_token"].startswith("ss_conn_")
        or len(data["access_token"]) > 128
    ):
        raise ValueError("Invalid connector credential")
    return data


def login(path, base, label):
    if path.exists() or path.is_symlink():
        raise ValueError("Connection file already exists. Log out first or select another file.")
    verifier = secrets.token_urlsafe(32)
    proof = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    code, pair = request(base, "/_saas/connect/start", {"label": label, "code_challenge": proof})
    if code != 200 or pair.get("verification_uri") != base + "/_saas/connect":
        raise ValueError("Tenant pairing unavailable")
    print("Open " + pair["verification_uri"] + " and enter code " + pair["user_code"], flush=True)
    print(
        "Sign in through the platform first if needed. This preview grants read-only metadata access.",
        flush=True,
    )
    webbrowser.open(pair["verification_uri"])
    deadline = time.monotonic() + min(int(pair["expires_in"]), 600)
    interval = max(5, int(pair["interval"]))
    while time.monotonic() < deadline:
        time.sleep(interval)
        code, data = request(
            base,
            "/_saas/connect/token",
            {"device_code": pair["device_code"], "code_verifier": verifier},
        )
        if code == 200:
            if (
                data.get("scope") != "workspace:read"
                or not isinstance(data.get("access_token"), str)
                or not data["access_token"].startswith("ss_conn_")
                or not time.time() < data["expires_at"] <= time.time() + 3601
            ):
                raise ValueError("Unexpected connection grant")
            save(path, {**data, "origin": base})
            print("Connected to " + base + ". Credential saved privately; Hunt is not enabled.")
            return
        if data.get("error") == "slow_down":
            interval += 5
        elif data.get("error") != "authorization_pending":
            raise ValueError("Connection denied, expired or unavailable")
    raise ValueError("Pairing expired")


class HostedClient(ArsenalClient):
    """Only the explicitly admitted hosted metadata tools; no Arsenal tunnel."""

    routes: ClassVar[dict[str, str]] = {
        "shakerscan_workspace": "/workspace-capabilities",
        "shakerscan_targets": "/targets",
        "shakerscan_findings": "/findings",
    }

    def list_tools(self):
        policy = self.request_json("GET", "/workspace-capabilities")
        if (
            policy.get("schema") != "shakerscan.workspace-capabilities/v1"
            or policy.get("mode") != "managed"
            or not isinstance(policy.get("features"), dict)
        ):
            raise MCPError(-32005, "Unsupported workspace contract")
        return [
            {
                "name": name,
                "description": "Read hosted workspace metadata. No Hunt execution.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "openWorldHint": False,
                },
            }
            for name in self.routes
            if name == "shakerscan_workspace"
            or policy["features"].get(name.removeprefix("shakerscan_"), {}).get("state")
            == "enabled"
        ]

    def call_tool(self, name, arguments):
        if name not in self.routes or arguments:
            raise MCPError(-32602, "Unsupported hosted tool or arguments")
        if name not in {tool["name"] for tool in self.list_tools()}:
            raise MCPError(-32602, "Hosted capability unavailable")
        value = self.request_json("GET", self.routes[name])
        return {
            "content": [{"type": "text", "text": json.dumps(value)}],
            "structuredContent": value,
            "isError": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--connection", type=Path, default=Path.home() / ".config/shakerscan/connection.json"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("login")
    start.add_argument("--tenant", type=origin, required=True)
    start.add_argument("--label", default="Local AI tools")
    commands.add_parser("status")
    commands.add_parser("mcp")
    commands.add_parser("logout")
    args = parser.parse_args()
    try:
        if args.command == "login":
            login(args.connection, args.tenant, args.label)
            return 0
        data = load(args.connection, allow_expired=args.command == "logout")
        if args.command == "mcp":
            return serve(
                MCPServer(HostedClient(data["origin"], api_token=data["access_token"])),
                sys.stdin.buffer,
                sys.stdout.buffer,
            )
        if args.command == "logout":
            code, _ = request(data["origin"], "/_saas/connect/disconnect", {}, data["access_token"])
            if code not in {200, 401}:
                raise ValueError("Remote revocation failed; connection file retained")
            args.connection.unlink()
            print("Disconnected")
            return 0
        code, _ = request(data["origin"], "/workspace-capabilities", token=data["access_token"])
        print("Connected" if code == 200 else "Expired or revoked")
        return 0 if code == 200 else 1
    except (ValueError, TypeError, OSError, KeyError, MCPError):
        print(
            "Connection failed. Check tenant, login, expiry and private file permissions.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
