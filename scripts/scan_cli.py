#!/usr/bin/env python3
"""V2-first, secret-free command line client for one deterministic Scan."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Iterable
import urllib.error
import urllib.parse
import urllib.request


START_SCHEMA = "scan-start/v2"
ERROR_SCHEMA = "scan-start-error/v1"
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

    def __init__(
        self,
        message: str,
        *,
        http_status: int | None = None,
        api_detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.api_detail = api_detail


def _parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        # The command the operator typed: ``scanner.sh scan`` from a source checkout, the
        # client's ``shakerscan scan`` when it runs this file.
        prog=prog or "scanner.sh scan",
        description=(
            "Submit one deterministic V2 Scan. Policy selects permission and families; "
            "the budget profile supplies hard ceilings."
        ),
    )
    parser.add_argument("target", help="Authorized HTTP(S) target")
    parser.add_argument(
        "--budget-profile", choices=("fast", "balanced", "thorough", "deep"), default=None,
    )
    parser.add_argument("--target-kind", choices=("web", "api"), default="web")
    parser.add_argument("--active-testing", action="store_true")
    parser.add_argument(
        "--allow-state-changing-http", action="store_true",
        help=(
            "Allow active checks whose requests can change state (with --active-testing); "
            "includes default-login attempts, which can lock accounts, and exploit templates "
            "that send attack input (a shell command or a file read in a parameter)"
        ),
    )
    parser.add_argument("--network-discovery", action="store_true")
    parser.add_argument("--subdomain-discovery", action="store_true")
    parser.add_argument(
        "--include-family", action="append", default=[], metavar="NAME[,NAME]",
        help=(
            "Add server-advertised Scan families to the preset the policy implies "
            "(the standard active set runs the active templates, nuclei_active, on the "
            "thorough and deep profiles; add them here for fast or balanced)"
        ),
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
    parser.add_argument(
        "--approval-receipt", metavar="UUID",
        help=(
            "Target-bound approval receipt. Without one the server uses the target's standing "
            "authorization (GET /targets/{id}/authorization), as New Scan in the UI does, and "
            "refuses with its reason when that does not cover the request; credential use may "
            "need a credential-tier receipt from POST /arsenal/approvals"
        ),
    )
    parser.add_argument(
        "--idempotency-key",
        metavar="KEY",
        help="Stable retry key (never put credentials or other secrets in this value)",
    )
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
    parser.add_argument(
        "--confirm-active", action="store_true",
        help="Confirm target authorization for --active-testing without a prompt (required off a terminal)",
    )
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


def _bearer_token() -> str | None:
    """A bearer token (an Enterprise gateway service token) authenticates a remote API; it is
    read from SHAKERSCAN_API_TOKEN_FILE by preference, else SHAKERSCAN_API_TOKEN, and only ever
    sent over HTTPS, never printed."""
    path = os.environ.get("SHAKERSCAN_API_TOKEN_FILE", "").strip()
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            raise ScanCliError(f"cannot read SHAKERSCAN_API_TOKEN_FILE: {exc.strerror or exc}") from exc
    else:
        token = os.environ.get("SHAKERSCAN_API_TOKEN", "").strip()
    if token and (len(token) > 4096 or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in token)):
        raise ScanCliError("SHAKERSCAN_API_TOKEN must be printable ASCII without spaces")
    return token or None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never replay an authenticated request against another origin.

    The https:// guard above only covers the URL the operator supplied. Following a
    redirect with urllib's default handler re-sends the Authorization header to
    whatever Location names -- another host, or plain HTTP. Refuse instead, and let
    the caller surface the 3xx.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect())


def _person_decision():
    try:
        import person_decision
    except ModuleNotFoundError:
        from scripts import person_decision
    return person_decision


def _request_json(
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
    _person_proof: str | None = None,
) -> dict[str, Any]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "shakerscan-cli/scan-start-v2",
    }
    if _person_proof:
        headers[_person_decision().PROOF_HEADER] = _person_proof
    token = _bearer_token()
    if token:
        if not url.startswith("https://"):
            raise ScanCliError("SHAKERSCAN_API_TOKEN requires an https:// API URL")
        headers["Authorization"] = "Bearer " + token
    data = None
    method = "GET"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        method = "POST"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _opener().open(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            try:
                from redirect_hint import redirect_explanation
            except ModuleNotFoundError:
                from scripts.redirect_hint import redirect_explanation
            location = exc.headers.get("Location") if exc.headers is not None else None
            raise ScanCliError(redirect_explanation(exc.code, location, url)) from exc
        body = exc.read()
        try:
            error = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            error = {}
        detail = error.get("detail") if isinstance(error, dict) else None
        if _person_proof is None and _person_decision().required(exc.code, exc.headers, detail):
            # An Enterprise gateway wants the person's security-key touch for this submission
            # (authorizing its target for active testing): asked in the person's own terminal.
            return _scan_person_decision(url, data or b"", method, detail, payload, idempotency_key)
        api_detail = detail
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("error") or detail
        if isinstance(detail, list):
            detail = "; ".join(
                str(item.get("msg") or "invalid request")
                for item in detail if isinstance(item, dict)
            )
        raise ScanCliError(
            f"API rejected the request (HTTP {exc.code}): {detail or 'unknown error'}",
            http_status=exc.code,
            api_detail=api_detail,
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        try:
            from redirect_hint import with_certificate_hint
        except ModuleNotFoundError:
            from scripts.redirect_hint import with_certificate_hint
        reason = exc.reason if hasattr(exc, "reason") else exc
        raise ScanCliError(
            with_certificate_hint(f"could not reach the ShakerScan API: {reason}", reason)
        ) from exc
    try:
        decoded = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ScanCliError("ShakerScan API returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise ScanCliError("ShakerScan API returned an invalid object")
    return decoded


def _scan_person_decision(url: str, data: bytes, method: str, detail: dict[str, Any],
                          payload: dict[str, Any] | None, idempotency_key: str | None) -> dict[str, Any]:
    decision = _person_decision()
    parts = urllib.parse.urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    path = parts.path + (f"?{parts.query}" if parts.query else "")
    try:
        return decision.handle(
            decision.json_poster(origin, _bearer_token()), origin=origin, method=method, path=path,
            body=data, detail=detail,
            resend=lambda grant: _request_json(url, payload=payload, idempotency_key=idempotency_key,
                                               _person_proof=grant),
        )
    except decision.PersonDecisionRefused as exc:
        error = ScanCliError(exc.line, http_status=403, api_detail={**exc.detail, "command": exc.command})
        error.exit_code = decision.EXIT_REFUSED
        raise error from None
    except decision.PersonDecisionError as exc:
        raise ScanCliError(str(exc), http_status=403, api_detail=detail) from None


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
    if args.auth_state_shards and args.execution not in {"parallel", "coverage"}:
        raise ScanCliError(
            "--auth-state-shards requires --execution parallel or coverage"
        )
    if args.idempotency_key is not None:
        key = args.idempotency_key
        if not 8 <= len(key) <= 200:
            raise ScanCliError("--idempotency-key must contain 8 to 200 characters")
        if not key[0].isalnum() or any(
            not (character.isalnum() or character in "_.:-") for character in key
        ):
            raise ScanCliError(
                "--idempotency-key must start with an alphanumeric character and "
                "use only letters, numbers, underscore, dot, colon, or hyphen"
            )
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


_CEILING_FLAGS = (
    ("max_http_requests", "--max-http-requests"),
    ("max_state_changing_requests", "--max-state-changing-requests"),
)


def _active_template_hint(args: argparse.Namespace, contract: dict[str, Any]) -> str:
    """Why a Scan with active testing runs no active templates, and how to add them."""
    if args.budget_profile not in {"thorough", "deep"}:
        return ("Active templates (nuclei_active) are not in this set; add "
                "--include-family nuclei_active to run them (the standard active set "
                "runs them on --budget-profile thorough or deep).")
    # On thorough and deep the standard set runs them unless a ceiling was lowered below its floor
    # (the contract's family_preset_addition_floors).
    floors = (contract.get("family_preset_addition_floors") or {}).get("standard_active") or {}
    advanced = getattr(args, "_advanced", {}) or {}
    below = [
        f"{flag} {int(advanced[name]):,} is below the floor of {int(floors[name]):,}"
        for name, flag in _CEILING_FLAGS
        if isinstance(advanced.get(name), int) and isinstance(floors.get(name), int)
        and advanced[name] < floors[name]
        and (name != "max_state_changing_requests" or args.allow_state_changing_http)
    ]
    reason = (
        "a ceiling lowered below the standard active set's floor for them leaves them out of it "
        f"({'; '.join(below)})" if below else
        "a lowered request or mutation ceiling leaves them out of the standard active set"
    )
    return (f"Active templates (nuclei_active) are not in this set: {reason}. Raise the "
            "ceiling, or add --include-family nuclei_active to ask for them anyway (admission "
            "refuses them when the ceiling cannot hold their sweep).")


def main(argv: list[str] | None = None, prog: str | None = None) -> int:
    parser = _parser(prog)
    args = parser.parse_args(argv)
    if args.target == "help":
        # `scan help` is a request for this text, never a scan of a host named "help".
        parser.print_help()
        return 0
    args.include_family = _split_names(args.include_family)
    args.exclude_family = _split_names(args.exclude_family)
    try:
        args.budget_profile = args.budget_profile or "balanced"
        _confirm_active(args)
        payload = _payload(args)
        api_url = args.api_url.rstrip("/")
        contract = _request_json(f"{api_url}/scan/contracts")
        _validate_against_contract(args, contract, args._advanced)
        response = _request_json(
            f"{api_url}/scans",
            payload=payload,
            idempotency_key=args.idempotency_key,
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
            **(
                {"idempotency_key": args.idempotency_key}
                if args.idempotency_key else {}
            ),
        }
        resolved = [str(item) for item in response.get("resolved_families") or () if str(item)]
        if resolved:
            result["resolved_families"] = resolved
            if response.get("family_preset"):
                result["family_preset"] = str(response["family_preset"])
        # The name submitted had no address record and the engine scanned its www/apex twin.
        # Say so: the scan is running against a different name than the one typed.
        notice = str(response.get("notice") or "").strip()
        if notice:
            result["notice"] = notice
            result["target"] = str(response.get("target") or "")
            if isinstance(response.get("dns_fallback"), dict):
                result["dns_fallback"] = response["dns_fallback"]
        if args.json:
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        else:
            if notice:
                print(f"Notice: {notice}")
                print(f"Target: {result['target']}")
            print(f"Scan ID: {scan_id}")
            print(f"Status: {status}")
            print(f"Plan: deterministic Scan · {args.budget_profile} budget · active testing {'on' if args.active_testing else 'off'}")
            if resolved:
                preset = f" ({result['family_preset']})" if result.get("family_preset") else ""
                print(f"Families: {', '.join(resolved)}{preset}")
                if (
                    args.active_testing and "nuclei_active" not in resolved
                    and "nuclei_active" not in args.exclude_family
                ):
                    # The standard active set (here and in New Scan) runs the active templates on
                    # thorough and deep only; say how to add them rather than leave the operator
                    # to find out from the report. Not when they were excluded on purpose.
                    print(_active_template_hint(args, contract))
            print(f"View progress at: {result['ui_url']}")
        return 0
    except ScanCliError as exc:
        if args.json:
            error = {
                "schema_version": ERROR_SCHEMA,
                "error": str(exc),
            }
            if exc.http_status is not None:
                error["http_status"] = exc.http_status
            if exc.api_detail is not None:
                error["api_detail"] = exc.api_detail
            print(
                json.dumps(error, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
            )
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return getattr(exc, "exit_code", 1)


if __name__ == "__main__":
    raise SystemExit(main())
