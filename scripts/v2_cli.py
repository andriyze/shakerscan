#!/usr/bin/env python3
"""First-class CLI for canonical ShakerScan V2 workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request
import uuid


MAX_JSON_BYTES = 4 * 1024 * 1024


class CliError(RuntimeError):
    """A safe, user-facing CLI failure."""


class ApiClient:
    def __init__(self, base_url: str, *, timeout: float = 60.0) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.timeout = timeout
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise CliError("the configured ShakerScan API URL is invalid")

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> Any:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_JSON_BYTES:
                raise CliError("request JSON exceeds the 4 MiB CLI limit")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=body, headers=headers, method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_JSON_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_JSON_BYTES + 1)
            detail = _safe_api_error(raw, fallback=f"API returned HTTP {exc.code}")
            raise CliError(detail) from exc
        except urllib.error.URLError as exc:
            raise CliError(f"cannot reach ShakerScan API: {exc.reason}") from exc
        if len(raw) > MAX_JSON_BYTES:
            raise CliError("API response exceeds the 4 MiB CLI limit")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CliError("ShakerScan API returned invalid JSON") from exc

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: Mapping[str, Any]) -> Any:
        return self.request("POST", path, payload=payload)


def _safe_api_error(raw: bytes, *, fallback: str) -> str:
    try:
        value = json.loads(raw[:MAX_JSON_BYTES])
    except (json.JSONDecodeError, UnicodeDecodeError):
        return fallback
    detail = value.get("detail") if isinstance(value, Mapping) else None
    if isinstance(detail, str) and detail.strip():
        return detail.strip()[:2_000]
    if isinstance(detail, list):
        messages = [
            str(item.get("msg") or "invalid request")
            for item in detail
            if isinstance(item, Mapping)
        ]
        if messages:
            return "; ".join(messages)[:2_000]
    return fallback


def _read_json(path: str | None, *, default: Any) -> Any:
    if path is None:
        return default
    if path == "-":
        raw = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
    else:
        file_path = Path(path).expanduser()
        try:
            if file_path.stat().st_size > MAX_JSON_BYTES:
                raise CliError("input JSON exceeds the 4 MiB CLI limit")
            raw = file_path.read_bytes()
        except OSError as exc:
            raise CliError(f"cannot read JSON input: {exc}") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise CliError("input JSON exceeds the 4 MiB CLI limit")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CliError("input is not valid UTF-8 JSON") from exc


def _pairs(values: Sequence[str], *, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values:
        name, separator, value = str(raw).partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not name or not value:
            raise CliError(f"{label} must use NAME=VALUE")
        if name in result:
            raise CliError(f"duplicate {label} name: {name}")
        result[name] = value
    return result


def _hunt_start_payload(args: argparse.Namespace, contract: Mapping[str, Any]) -> dict[str, Any]:
    if args.request:
        value = _read_json(args.request, default={})
        if not isinstance(value, dict):
            raise CliError("Hunt start request must be one JSON object")
        if value.get("schema_version") != contract.get("schema_version"):
            raise CliError("Hunt request schema_version does not match the server contract")
        return value

    target_kinds = {str(item) for item in contract.get("target_kinds") or ()}
    if not args.target_id:
        raise CliError("--target-id is required unless --request is used")
    if not args.target_kind:
        raise CliError("--target-kind is required unless --request is used")
    if args.target_kind not in target_kinds:
        raise CliError("target kind is not supported by the running server")
    profiles = contract.get("budget_profiles") or {}
    if args.budget_profile not in profiles:
        raise CliError("budget profile is not supported by the running server")

    dimensions = {
        str(item.get("name")): item
        for item in contract.get("budget_dimensions") or ()
        if isinstance(item, Mapping) and item.get("name")
    }
    budgets: dict[str, int] = {}
    for name, raw_value in _pairs(args.budget, label="budget").items():
        if name not in dimensions:
            raise CliError(f"budget dimension is not supported by the server: {name}")
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise CliError(f"budget {name} must be an integer") from exc
        minimum = int(dimensions[name].get("minimum") or 0)
        if value < minimum:
            raise CliError(f"budget {name} must be at least {minimum}")
        profile_max = int((profiles.get(args.budget_profile) or {}).get(name) or 0)
        if value > profile_max:
            raise CliError(
                f"budget {name} exceeds the server's {args.budget_profile} ceiling"
            )
        budgets[name] = value

    return {
        "schema_version": str(contract["schema_version"]),
        "target_id": args.target_id,
        "target_kind": args.target_kind,
        "goal": args.goal,
        "budget_profile": args.budget_profile,
        "policy": {
            "active_testing": bool(args.active_testing),
            "allow_state_changing_http": bool(args.allow_state_changing_http),
            "network_discovery": bool(args.network_discovery),
            "allow_oob_interactions": bool(args.allow_oob_interactions),
            "authorization_confirmed": bool(args.authorized),
            "approval_receipt_id": args.approval_receipt_id,
            "scope_receipt_id": args.scope_receipt_id,
        },
        "budgets": budgets,
        "credential_refs": _pairs(args.credential_ref, label="credential reference"),
        "capabilities": list(dict.fromkeys(args.capability)),
        "request_collection_ids": list(dict.fromkeys(args.collection_id)),
    }


def _run_hunt(args: argparse.Namespace, client: ApiClient) -> Any:
    if args.hunt_command == "start":
        contract = client.get("/hunts/contract")
        if not isinstance(contract, Mapping):
            raise CliError("running server returned an invalid Hunt contract")
        return client.post("/hunts", _hunt_start_payload(args, contract))
    if args.hunt_command == "call":
        run = client.get(f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}")
        if not isinstance(run, Mapping):
            raise CliError("running server returned an invalid Hunt record")
        capability_names = {
            str(item.get("name") if isinstance(item, Mapping) else item)
            for item in run.get("capabilities") or ()
        }
        if args.capability_name not in capability_names:
            raise CliError("capability is not present in the server-returned Hunt manifest")
        inputs = _read_json(args.input, default={})
        if not isinstance(inputs, dict):
            raise CliError("Hunt capability input must be one JSON object")
        key = args.idempotency_key or f"cli-{uuid.uuid4()}"
        response = client.post(
            "/hunts/{}/capabilities/{}".format(
                urllib.parse.quote(args.hunt_id, safe=""),
                urllib.parse.quote(args.capability_name, safe=""),
            ),
            {"idempotency_key": key, "input": inputs},
        )
        return {"idempotency_key": key, "response": response}
    raise CliError("unknown Hunt command")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shakerscan",
        description="Canonical ShakerScan V2 command line",
    )
    parser.add_argument("--api-url", required=True, help=argparse.SUPPRESS)
    products = parser.add_subparsers(dest="product", required=True)

    hunt = products.add_parser("hunt", help="Start or drive one canonical Hunt")
    hunt_commands = hunt.add_subparsers(dest="hunt_command", required=True)
    hunt_start = hunt_commands.add_parser("start", help="Start a target-bound Hunt")
    hunt_start.add_argument("--request", metavar="FILE", help="Complete JSON contract; use - for stdin")
    hunt_start.add_argument("--target-id")
    hunt_start.add_argument("--target-kind")
    hunt_start.add_argument("--goal", default="Investigate the authorized target.")
    hunt_start.add_argument("--budget-profile", default="balanced")
    hunt_start.add_argument("--active-testing", action="store_true")
    hunt_start.add_argument("--allow-state-changing-http", action="store_true")
    hunt_start.add_argument("--network-discovery", action="store_true")
    hunt_start.add_argument("--allow-oob-interactions", action="store_true")
    hunt_start.add_argument("--authorized", action="store_true")
    hunt_start.add_argument("--approval-receipt-id")
    hunt_start.add_argument("--scope-receipt-id")
    hunt_start.add_argument("--budget", action="append", default=[], metavar="NAME=VALUE")
    hunt_start.add_argument("--credential-ref", action="append", default=[], metavar="SLOT=ID")
    hunt_start.add_argument("--capability", action="append", default=[])
    hunt_start.add_argument("--collection-id", action="append", default=[])

    hunt_call = hunt_commands.add_parser("call", help="Call one server-returned capability")
    hunt_call.add_argument("hunt_id")
    hunt_call.add_argument("capability_name")
    hunt_call.add_argument("--input", metavar="FILE", help="JSON object; use - for stdin")
    hunt_call.add_argument("--idempotency-key")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        client = ApiClient(args.api_url)
        if args.product == "hunt":
            result = _run_hunt(args, client)
        else:
            raise CliError("unknown command")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except CliError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
