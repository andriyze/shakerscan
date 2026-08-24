#!/usr/bin/env python3
"""Reject ad hoc network clients in canonical Scan execution modules."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOTS = (
    REPOSITORY_ROOT / "api" / "scan",
    REPOSITORY_ROOT / "api" / "capabilities",
    REPOSITORY_ROOT / "api" / "runtime",
    REPOSITORY_ROOT / "api" / "pinned_socks_proxy.py",
)
NETWORK_IMPORTS = frozenset({
    "aiohttp", "http.client", "httpx", "requests", "socket",
    "urllib.request",
})
NETWORK_CALLS = frozenset({
    "aiohttp.ClientSession",
    "aiohttp.TCPConnector",
    "asyncio.open_connection",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "httpx.AsyncClient",
    "httpx.Client",
    "requests.delete",
    "requests.get",
    "requests.head",
    "requests.patch",
    "requests.post",
    "requests.put",
    "requests.request",
    "requests.Session",
    "socket.create_connection",
    "socket.socket",
    "urllib.request.urlopen",
})
REVIEWED_IMPORTS = {
    "api/capabilities/http.py": frozenset({"httpx"}),
    "api/runtime/pinned_http_replay.py": frozenset({"aiohttp", "socket"}),
    "api/runtime/target_bound_socket.py": frozenset({"socket"}),
}
REVIEWED_CALLS = {
    "api/capabilities/http.py": frozenset({"httpx.AsyncClient"}),
    "api/capabilities/tls.py": frozenset({"asyncio.open_connection"}),
    "api/runtime/pinned_http_replay.py": frozenset({
        "aiohttp.ClientSession", "aiohttp.TCPConnector",
    }),
    "api/pinned_socks_proxy.py": frozenset({"asyncio.open_connection"}),
}

# Each direct non-target egress seam is reviewed by exact caller and authority class.
# Target credentials and target routing are forbidden for every entry. New provider,
# control-plane, storage, update, or local-IPC clients must be added deliberately here.
NON_TARGET_EGRESS_ALLOWLIST = (
    ("api/ai_gate_scan.py", "_rubric_judge_findings", "ai_provider"),
    ("api/ai_gate_scan.py", "_semantic_judge_probe_transcripts", "ai_provider"),
    ("api/ai_verifier.py", "_call_llm", "ai_provider"),
    ("api/api.py", "_fetch_json_url", "control_plane"),
    ("api/api.py", "_model_intake_runner_http", "control_plane"),
    ("api/api.py", "_call_model_intake_signer", "control_plane"),
    ("api/api.py", "_model_intake_stage_run", "package_update"),
    ("api/api.py", "get_workers", "local_ipc"),
    ("api/broker_worker.py", "api_request", "control_plane"),
    ("api/broker_worker.py", "upload_artifact", "object_storage"),
    ("api/evidence_storage.py", "_s3_request", "object_storage"),
    ("api/fleet_agent.py", "connect", "control_plane"),
    ("api/fleet_agent.py", "api_request", "control_plane"),
    ("api/model_intake_admission_webhook.py", "_verify", "control_plane"),
    ("api/model_intake_firecracker_runner.py", "_unix_http", "local_ipc"),
)
NON_TARGET_EGRESS_CLASSES = frozenset({
    "ai_provider", "control_plane", "object_storage", "package_update", "local_ipc",
})
REQUIRED_TARGET_TRANSPORT_ANCHORS = {
    "api/agent_tools.py": (
        "build_enforced_scanner_plan", "pinned_proxy_url", "primary_frozen_address",
    ),
    "api/capabilities/browser.py": (
        "PinnedSocksProxy", "--host-resolver-rules=MAP * ~NOTFOUND",
        "service_workers=\"block\"",
    ),
    "api/capabilities/http.py": (
        "FrozenTargetSocketFactory", "connection_addresses", '"Host": host_header',
        'request.extensions["sni_hostname"]',
    ),
    "api/capabilities/tls.py": (
        "FrozenTargetSocketFactory", "server_hostname=parsed.hostname",
    ),
    "api/runtime/pinned_http_replay.py": (
        "_FrozenAddressResolver", "socket_factory=tracked_socket_factory",
    ),
    "api/pinned_socks_proxy.py": (
        "FrozenTargetSocketFactory", "self.socket_factory.connection_addresses",
    ),
    "api/scan/action_adapter.py": (
        "FrozenTargetSocketFactory", '"authorized_addresses": list(self.target.allowed_addresses)',
        '"address_policy": socket_factory.policy_receipt',
    ),
    "api/worker.py": (
        "PinnedSocksProxy", "build_enforced_scanner_plan",
        "max_connections=connection_ceiling", "_DIRECT_ADDRESS_SCANNERS",
    ),
    "scanner/sitecustomize.py": (
        "SHAKERSCAN_CANONICAL_SCAN_EXECUTION", "frozen_getaddrinfo",
        "normalize_frozen_addresses",
    ),
}


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return path.name


def _qualified_name(node: ast.AST) -> str | None:
    names: list[str] = []
    cursor = node
    while isinstance(cursor, ast.Attribute):
        names.append(cursor.attr)
        cursor = cursor.value
    if isinstance(cursor, ast.Name):
        names.append(cursor.id)
        return ".".join(reversed(names))
    return None


class _NetworkVisitor(ast.NodeVisitor):
    def __init__(self, *, relative_path: str) -> None:
        self.relative_path = relative_path
        self.aliases: dict[str, str] = {}
        self.violations: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            alias = item.asname or item.name.split(".", 1)[0]
            self.aliases[alias] = item.name
            if (
                item.name in NETWORK_IMPORTS
                and item.name not in REVIEWED_IMPORTS.get(
                    self.relative_path, frozenset(),
                )
            ):
                self.violations.append(
                    f"{self.relative_path}:{node.lineno}: unreviewed network import {item.name}"
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = str(node.module or "")
        for item in node.names:
            alias = item.asname or item.name
            qualified = f"{module}.{item.name}" if module else item.name
            self.aliases[alias] = qualified
        if (
            module in NETWORK_IMPORTS
            and module not in REVIEWED_IMPORTS.get(
                self.relative_path, frozenset(),
            )
        ):
            self.violations.append(
                f"{self.relative_path}:{node.lineno}: unreviewed network import {module}"
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        raw = _qualified_name(node.func)
        if raw:
            first, separator, suffix = raw.partition(".")
            resolved = self.aliases.get(first, first)
            qualified = resolved + (separator + suffix if separator else "")
            if (
                qualified in NETWORK_CALLS
                and qualified not in REVIEWED_CALLS.get(
                    self.relative_path, frozenset(),
                )
            ):
                self.violations.append(
                    f"{self.relative_path}:{node.lineno}: unreviewed network call {qualified}"
                )
        self.generic_visit(node)


def find_violations(paths: Iterable[Path]) -> tuple[str, ...]:
    violations: list[str] = []
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        files.extend(path.rglob("*.py") if path.is_dir() else (path,))
    for path in sorted(set(files)):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            violations.append(f"{_relative(path)}: cannot inspect: {exc}")
            continue
        visitor = _NetworkVisitor(relative_path=_relative(path))
        visitor.visit(tree)
        violations.extend(visitor.violations)
    return tuple(violations)


def find_target_transport_anchor_violations() -> tuple[str, ...]:
    violations: list[str] = []
    for relative_path, anchors in REQUIRED_TARGET_TRANSPORT_ANCHORS.items():
        path = REPOSITORY_ROOT / relative_path
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            violations.append(f"{relative_path}: cannot inspect transport anchors: {exc}")
            continue
        for anchor in anchors:
            if anchor not in source:
                violations.append(
                    f"{relative_path}: missing reviewed target transport anchor {anchor}"
                )
    return tuple(violations)


def find_non_target_egress_allowlist_violations() -> tuple[str, ...]:
    """Prove the reviewed non-target callers still exist as separately named seams."""
    violations: list[str] = []
    seen: set[tuple[str, str]] = set()
    for relative_path, function_name, egress_class in NON_TARGET_EGRESS_ALLOWLIST:
        identity = (relative_path, function_name)
        if identity in seen:
            violations.append(
                f"{relative_path}:{function_name}: duplicate non-target egress authority"
            )
            continue
        seen.add(identity)
        if egress_class not in NON_TARGET_EGRESS_CLASSES:
            violations.append(
                f"{relative_path}:{function_name}: invalid non-target egress class"
            )
            continue
        path = REPOSITORY_ROOT / relative_path
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            violations.append(f"{relative_path}: cannot inspect egress authority: {exc}")
            continue
        if not any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
            for node in ast.walk(tree)
        ):
            violations.append(
                f"{relative_path}:{function_name}: reviewed non-target egress caller is missing"
            )
    return tuple(violations)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reject unreviewed canonical Scan network transports",
    )
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    violations = (
        *find_violations(args.paths or DEFAULT_ROOTS),
        *find_target_transport_anchor_violations(),
        *find_non_target_egress_allowlist_violations(),
    )
    if violations:
        for violation in violations:
            print(violation)
        return 1
    print("canonical Scan target transport gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
