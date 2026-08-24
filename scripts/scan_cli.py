#!/usr/bin/env python3
"""V2-first, secret-free command line client for one deterministic Scan."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Iterable
import urllib.error
import urllib.request


START_SCHEMA = "scan-start/v2"
ERROR_SCHEMA = "scan-start-error/v1"
SUNSET = "2026-12-31"
LEGACY_TRANSLATIONS: dict[str, tuple[str, bool]] = {
    "quick": ("fast", False),
    "standard": ("balanced", False),
    "deep": ("thorough", False),
    "full": ("thorough", True),
    "aggressive": ("thorough", True),
    "smart": ("thorough", True),
}
ADVANCED_FLAGS = (
    "max_duration_seconds",
    "max_http_requests",
    "max_state_changing_requests",
    "max_endpoints",
    "max_hosts",
    "max_browser_actions",
    "max_tcp_ports",
    "max_tool_wall_seconds",
    "max_workers",
)


class ScanCliError(RuntimeError):
    """A content-safe command validation or API error."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.sh scan",
        description=(
            "Submit one deterministic V2 Scan. Policy selects permission and families; "
            "the budget profile supplies hard ceilings."
        ),
    )
    parser.add_argument("target", help="Authorized HTTP(S) target")
    parser.add_argument(
        "--budget-profile", choices=("fast", "balanced", "thorough"), default=None,
    )
    parser.add_argument("--target-kind", choices=("web", "api"), default="web")
    parser.add_argument("--active-testing", action="store_true")
    parser.add_argument("--allow-state-changing-http", action="store_true")
    parser.add_argument("--network-discovery", action="store_true")
    parser.add_argument("--subdomain-discovery", action="store_true")
    parser.add_argument(
        "--include-family", action="append", default=[], metavar="NAME[,NAME]",
        help="Require one or more server-advertised Scan families",
    )
    parser.add_argument(
        "--exclude-family", action="append", default=[], metavar="NAME[,NAME]",
        help="Exclude one or more server-advertised Scan families",
    )
    parser.add_argument(
        "--credential-profile", action="append", default=[], metavar="UUID",
        help="Attach an exact-target encrypted profile (maximum two)",
    )
    parser.add_argument(
        "--collection-selection", action="append", default=[], metavar="UUID",
        help="Attach an exact-target saved request selection (maximum sixteen)",
    )
    parser.add_argument("--approval-receipt", metavar="UUID")
    parser.add_argument("--endpoint", action="append", default=[], metavar="SPEC")
    parser.add_argument("--require-current-workers", action="store_true")
    parser.add_argument(
        "--placement", choices=("auto", "local", "remote"), default="auto",
    )
    parser.add_argument("--node-id", metavar="UUID")
    parser.add_argument("--region")
    parser.add_argument("--egress-group")
    parser.add_argument("--network")
    parser.add_argument("--requires", action="append", default=[], metavar="CAPABILITY")
    parser.add_argument(
        "--execution", choices=("auto", "normal", "parallel", "coverage"),
        default="auto", help="Placement-compatible execution fan-out",
    )
    parser.add_argument("--shards", metavar="N|auto")
    parser.add_argument(
        "--shard-strategy",
        choices=("auto", "scope", "family", "coverage", "coverage_family"),
    )
    parser.add_argument("--auth-state-shards", action="store_true")
    for name in ADVANCED_FLAGS:
        parser.add_argument(
            "--" + name.replace("_", "-"), type=int, metavar="N",
            help="Lower the matching server-advertised budget ceiling",
        )
    parser.add_argument("--force-single-worker", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit only scan-start/v2 JSON")
    parser.add_argument("--confirm-active", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--type", choices=tuple(LEGACY_TRANSLATIONS), help=argparse.SUPPRESS)
    parser.add_argument("--compatibility-alias", choices=tuple(LEGACY_TRANSLATIONS), help=argparse.SUPPRESS)
    parser.add_argument("--api-url", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--ui-url", required=True, help=argparse.SUPPRESS)
    return parser


def _split_names(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        for item in str(value).split(","):
            normalized = item.strip().lower()
            if normalized and normalized not in result:
                result.append(normalized)
    return result


def _request_json(
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    compatibility_command: str | None = None,
) -> dict[str, Any]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "shakerscan-cli/scan-start-v2",
    }
    data = None
    method = "GET"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        method = "POST"
    if compatibility_command:
        headers["X-ShakerScan-CLI-Compatibility"] = compatibility_command
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            error = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            error = {}
        detail = error.get("detail") if isinstance(error, dict) else None
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("error") or detail
        raise ScanCliError(f"API rejected the request (HTTP {exc.code}): {detail or 'unknown error'}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ScanCliError(f"could not reach the ShakerScan API: {exc.reason if hasattr(exc, 'reason') else exc}") from exc
    try:
        decoded = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ScanCliError("ShakerScan API returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise ScanCliError("ShakerScan API returned an invalid object")
    return decoded


def _confirm_active(args: argparse.Namespace) -> None:
    if not args.active_testing:
        return
    if args.confirm_active:
        return
    if not sys.stdin.isatty():
        raise ScanCliError(
            "active testing requires --confirm-active after confirming target authorization"
        )
    print(
        f"Active testing can change target state. Confirm authorization for {args.target}.",
        file=sys.stderr,
    )
    if input("Type 'yes' to continue: ").strip().lower() != "yes":
        raise ScanCliError("active Scan cancelled")


def _apply_legacy_translation(args: argparse.Namespace) -> str | None:
    legacy = args.compatibility_alias or args.type
    if not legacy:
        return None
    profile, active = LEGACY_TRANSLATIONS[legacy]
    if args.budget_profile is not None and args.budget_profile != profile:
        raise ScanCliError(
            f"legacy {legacy} translates to --budget-profile {profile}; remove the conflicting profile"
        )
    args.budget_profile = profile
    args.active_testing = args.active_testing or active
    replacement = f"scanner.sh scan <target> --budget-profile {profile}"
    if active:
        replacement += " --active-testing --confirm-active"
    command = f"scan-{legacy}" if args.compatibility_alias else f"scan --type {legacy}"
    print(
        json.dumps({
            "schema_version": "scan-cli-deprecation/v1",
            "deprecated_command": command,
            "canonical_translation": {
                "engine": "scan",
                "budget_profile": profile,
                "active_testing": active,
            },
            "sunset": SUNSET,
            "replacement": replacement,
        }, sort_keys=True),
        file=sys.stderr,
    )
    return command


def _validate_against_contract(
    args: argparse.Namespace, contract: dict[str, Any], advanced: dict[str, Any],
) -> None:
    if contract.get("schema_version") != "scan-public-contract/v1":
        raise ScanCliError("server does not expose the required V2 Scan contract")
    families = {str(item.get("name")) for item in contract.get("families", []) if isinstance(item, dict)}
    unknown = (set(args.include_family) | set(args.exclude_family)) - families
    if unknown:
        raise ScanCliError("unknown Scan families: " + ", ".join(sorted(unknown)))
    overlap = set(args.include_family) & set(args.exclude_family)
    if overlap:
        raise ScanCliError("families cannot be both included and excluded: " + ", ".join(sorted(overlap)))
    definitions = {
        str(item.get("name")): item
        for item in contract.get("advanced_limits", []) if isinstance(item, dict)
    }
    for name, value in advanced.items():
        if name == "force_single_worker":
            continue
        definition = definitions.get(name)
        if definition is None:
            raise ScanCliError(f"server does not advertise advanced limit {name}")
        minimum = int(definition.get("minimum", 1))
        profile_ceiling = int((definition.get("profile_ceilings") or {}).get(args.budget_profile, 0))
        if value < minimum or value > profile_ceiling:
            raise ScanCliError(
                f"{name} must be between {minimum} and the {args.budget_profile} ceiling of {profile_ceiling}"
            )


def _payload(args: argparse.Namespace) -> dict[str, Any]:
    if len(args.credential_profile) > 2:
        raise ScanCliError("Scan accepts at most two credential profiles")
    if len(args.collection_selection) > 16:
        raise ScanCliError("Scan accepts at most sixteen collection selections")
    if len(set(args.credential_profile)) != len(args.credential_profile):
        raise ScanCliError("credential profile IDs must be distinct")
    if args.allow_state_changing_http and not args.active_testing:
        raise ScanCliError("state-changing HTTP requires --active-testing")
    if args.network_discovery and not args.active_testing:
        raise ScanCliError("network discovery requires --active-testing")
    if (args.allow_state_changing_http or args.network_discovery or args.credential_profile) and not args.approval_receipt:
        raise ScanCliError("the selected authority requires --approval-receipt")
    if args.node_id and args.placement != "auto":
        raise ScanCliError("--node-id cannot be combined with --placement local or remote")
    if args.shards and args.execution not in {"parallel", "coverage"}:
        raise ScanCliError("--shards requires --execution parallel or coverage")
    if args.shards and args.shards != "auto":
        try:
            shard_count = int(args.shards)
        except ValueError as exc:
            raise ScanCliError("--shards must be auto or an integer from 2 to 20") from exc
        if not 2 <= shard_count <= 20:
            raise ScanCliError("--shards must be auto or an integer from 2 to 20")
    else:
        shard_count = args.shards

    placement: dict[str, Any] = {}
    if args.placement in {"local", "remote"}:
        placement["node_scope"] = args.placement
    if args.node_id:
        placement["node_id"] = args.node_id
    if args.region:
        placement["region"] = args.region
    if args.egress_group:
        placement["egress_group"] = args.egress_group
    if args.network:
        placement["network"] = args.network
    if args.requires:
        placement["requires"] = list(dict.fromkeys(args.requires))

    options: dict[str, Any] = {}
    if args.endpoint:
        options["custom_endpoints"] = list(dict.fromkeys(args.endpoint))
    if args.require_current_workers:
        options["require_current_workers"] = True
    if placement:
        options["placement"] = placement
    if args.auth_state_shards:
        options["auth_state_shards"] = True
    if args.execution == "normal":
        options["parallel"] = False
    elif args.execution in {"parallel", "coverage"}:
        options["parallel"] = True
        options["shard_strategy"] = "coverage" if args.execution == "coverage" else (args.shard_strategy or "auto")
        if shard_count:
            options["shards"] = shard_count
    elif args.shard_strategy:
        raise ScanCliError("--shard-strategy requires --execution parallel or coverage")

    advanced = {
        name: getattr(args, name)
        for name in ADVANCED_FLAGS if getattr(args, name) is not None
    }
    if args.force_single_worker:
        advanced["force_single_worker"] = True
    args._advanced = advanced
    return {
        "target": args.target,
        "target_kind": args.target_kind,
        "budget_profile": args.budget_profile,
        "policy": {
            "active_testing": args.active_testing,
            "allow_state_changing_http": args.allow_state_changing_http,
            "network_discovery": args.network_discovery,
            "subdomain_discovery": args.subdomain_discovery,
            "include_families": args.include_family,
            "exclude_families": args.exclude_family,
        },
        "credential_profile_ids": args.credential_profile,
        "request_collections": [
            {"id": selection_id} for selection_id in args.collection_selection
        ],
        "advanced": advanced,
        **({"approval_receipt_id": args.approval_receipt} if args.approval_receipt else {}),
        "options": options,
    }


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    args.include_family = _split_names(args.include_family)
    args.exclude_family = _split_names(args.exclude_family)
    compatibility = None
    try:
        compatibility = _apply_legacy_translation(args)
        args.budget_profile = args.budget_profile or "balanced"
        _confirm_active(args)
        payload = _payload(args)
        api_url = args.api_url.rstrip("/")
        contract = _request_json(f"{api_url}/scan/contracts")
        _validate_against_contract(args, contract, args._advanced)
        response = _request_json(
            f"{api_url}/scans",
            payload=payload,
            compatibility_command=compatibility,
        )
        scan_id = str(response.get("scan_id") or "")
        status = str(response.get("status") or "")
        if not scan_id or not status:
            raise ScanCliError("Scan submission returned no scan ID or status")
        result = {
            "schema_version": START_SCHEMA,
            "scan_id": scan_id,
            "status": status,
            "engine": "scan",
            "budget_profile": args.budget_profile,
            "active_testing": bool(args.active_testing),
            "ui_url": f"{args.ui_url.rstrip('/')}/scans/{scan_id}",
        }
        if args.json:
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        else:
            print(f"Scan ID: {scan_id}")
            print(f"Status: {status}")
            print(f"Plan: deterministic Scan · {args.budget_profile} budget · active testing {'on' if args.active_testing else 'off'}")
            print(f"View progress at: {result['ui_url']}")
        return 0
    except ScanCliError as exc:
        if args.json:
            print(json.dumps({
                "schema_version": ERROR_SCHEMA,
                "error": str(exc),
            }, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
