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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reject unreviewed canonical Scan network transports",
    )
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    violations = find_violations(args.paths or DEFAULT_ROOTS)
    if violations:
        for violation in violations:
            print(violation)
        return 1
    print("canonical Scan target transport gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
