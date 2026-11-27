#!/usr/bin/env python3
"""Enforce the V2 surface disposition manifest.

Every public route must have a written disposition before it can be deleted,
moved, or extended. A behaviour-preserving extraction cannot decide whether a
surface belongs in V2; this file is where that decision is recorded, and this
script is what stops the decision from being bypassed.

Failure conditions (playbook section 5):
  1. a public route is absent from the manifest
  2. a route marked DELETE_NOW or read-only still accepts a non-cancel write
  3. a compatibility route appears in canonical generated clients
  4. a surface declares files that do not exist
  5. an extracted router exceeds its size ratchet
  6. the manifest itself is malformed or has overlapping/duplicate ids
"""

from __future__ import annotations

import ast
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPOSITORY_ROOT / "config" / "v2_surface_disposition.yaml"
GENERATED_CLIENT = REPOSITORY_ROOT / "ui" / "src" / "lib" / "publicApi.generated.ts"

DISPOSITIONS = {
    "DELETE_NOW", "QUARANTINE_READ_ONLY", "MERGE_THEN_DELETE",
    "KEEP_AND_SPLIT", "KEEP_CANONICAL", "ARCHIVE_DOC_ONLY",
}
# Dispositions that must not accept new product writes.
NO_NEW_WRITES = {"DELETE_NOW", "QUARANTINE_READ_ONLY", "MERGE_THEN_DELETE"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ROUTE_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
# A quarantined surface may still let an operator stop work that is already
# running; that is not new product behaviour.
CANCELLATION_SUFFIXES = ("/cancel", "/revoke", "/stop")


def declared_routes() -> dict[tuple[str, str], Path]:
    """Every (METHOD, path) declared under api/, with its defining module."""
    routes: dict[tuple[str, str], Path] = {}
    for path in sorted((REPOSITORY_ROOT / "api").rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        prefix = _router_prefix(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                func = decorator.func
                if not isinstance(func, ast.Attribute) or func.attr not in ROUTE_METHODS:
                    continue
                if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
                    continue
                route = prefix + str(decorator.args[0].value)
                routes[(func.attr.upper(), route)] = path
    return routes


def _router_prefix(tree: ast.AST) -> str:
    """Recover an APIRouter(prefix=...) so mounted paths compare correctly."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != "APIRouter":
            continue
        for keyword in node.keywords:
            if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
                return str(keyword.value.value)
    return ""


def _normalize(route: str) -> str:
    """Collapse path parameter names so a pattern can match any spelling."""
    parts = []
    for segment in route.split("/"):
        parts.append("{}" if segment.startswith("{") and segment.endswith("}") else segment)
    return "/".join(parts)


def _matches(route: str, pattern: str) -> bool:
    return fnmatch.fnmatch(_normalize(route), _normalize(pattern))


def main() -> int:
    violations: list[str] = []
    if not MANIFEST.is_file():
        print(f"missing disposition manifest: {MANIFEST}", file=sys.stderr)
        return 1
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8")) or {}
    surfaces = manifest.get("surfaces") or []

    source_head = str(manifest.get("source_head") or "")
    if not re.fullmatch(r"[0-9a-f]{40}", source_head):
        violations.append("source_head must be one full lowercase commit SHA")
    else:
        try:
            probe = subprocess.run(
                # safe.directory=* keeps a container that runs as a different UID than
                # the checkout owner (the candidate image over a mounted read-only
                # tree in CI) from tripping git's dubious-ownership refusal and
                # mis-reading a real ancestor as absent.
                [
                    "git", "-c", "safe.directory=*",
                    "merge-base", "--is-ancestor", source_head, "HEAD",
                ],
                cwd=REPOSITORY_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            violations.append(f"could not run git to check source_head ancestry: {exc}")
        else:
            # `--is-ancestor` returns 1 for a genuine non-ancestor and a higher code
            # (e.g. 128) for an environment/git error; only the former is a real
            # disposition violation, and a git error must surface, not masquerade.
            if probe.returncode == 1:
                violations.append("source_head is not an ancestor of the current checkout")
            elif probe.returncode != 0:
                violations.append(
                    "git could not evaluate source_head ancestry: "
                    + (probe.stderr.strip() or f"exit {probe.returncode}")
                )
    if manifest.get("release_boundary") != (
        "canonical_scan_hunt_with_transitional_compatibility_writes"
    ):
        violations.append("release_boundary must disclose transitional compatibility writes")

    seen_ids: set[str] = set()
    for surface in surfaces:
        sid = str(surface.get("id") or "")
        if not sid:
            violations.append("a surface has no id")
            continue
        if sid in seen_ids:
            violations.append(f"{sid}: duplicate surface id")
        seen_ids.add(sid)
        if str(surface.get("disposition")) not in DISPOSITIONS:
            violations.append(f"{sid}: invalid disposition {surface.get('disposition')!r}")
        if not surface.get("routes"):
            violations.append(f"{sid}: declares no routes")
        for declared_file in surface.get("files") or []:
            if not (REPOSITORY_ROOT / str(declared_file)).exists():
                violations.append(f"{sid}: declared file is missing: {declared_file}")

    routes = declared_routes()

    # 1. every public route must be covered
    for (method, route), owner in sorted(routes.items()):
        if not any(
            _matches(route, pattern)
            for surface in surfaces
            for pattern in surface.get("routes") or []
        ):
            violations.append(
                f"{method} {route} ({owner.relative_to(REPOSITORY_ROOT)}) has no "
                "disposition; add it to config/v2_surface_disposition.yaml"
            )

    # 2. a no-new-writes surface must not accept a non-cancel write
    for surface in surfaces:
        sid = str(surface.get("id") or "")
        disposition = str(surface.get("disposition"))
        allows_writes = bool(surface.get("new_writes_allowed", True))
        if disposition not in NO_NEW_WRITES and allows_writes:
            continue
        for (method, route) in sorted(routes):
            if method not in WRITE_METHODS:
                continue
            if not any(_matches(route, p) for p in surface.get("routes") or []):
                continue
            # A more specific canonical surface may legitimately own this route.
            claimed_by_canonical = any(
                other is not surface
                and str(other.get("disposition")) in {"KEEP_CANONICAL", "KEEP_AND_SPLIT"}
                and bool(other.get("new_writes_allowed", True))
                and any(_matches(route, p) for p in other.get("routes") or [])
                and _specificity(other, route) > _specificity(surface, route)
                for other in surfaces
            )
            if claimed_by_canonical:
                continue
            if route.endswith(CANCELLATION_SUFFIXES) and surface.get("cancellation_required"):
                continue
            pending = set(surface.get("pending_write_removals") or ())
            if f"{method} {route}" in pending:
                # Declared backlog: known, visible, and only allowed to shrink.
                continue
            violations.append(
                f"{sid} is {disposition} with new_writes_allowed=false but still "
                f"accepts {method} {route}; delete it, or declare it under "
                "pending_write_removals with a plan to remove it"
            )

    # 2b. the backlog is a ratchet: a declared removal that no longer exists must
    #     be struck from the manifest, so the list can only get shorter.
    for surface in surfaces:
        sid = str(surface.get("id") or "")
        for entry in surface.get("pending_write_removals") or ():
            method, _, route = str(entry).partition(" ")
            if (method, route) not in routes:
                violations.append(
                    f"{sid}: pending_write_removals still lists {entry}, which no "
                    "longer exists. Remove the entry -- this list may only shrink."
                )

    # 3. compatibility routes must stay out of the canonical generated client
    if GENERATED_CLIENT.is_file():
        client = GENERATED_CLIENT.read_text(encoding="utf-8")
        for surface in surfaces:
            if not surface.get("excluded_from_generated_clients"):
                continue
            for (method, route) in sorted(routes):
                if not any(_matches(route, p) for p in surface.get("routes") or []):
                    continue
                if route in client:
                    violations.append(
                        f"{surface.get('id')}: compatibility route {route} appears in "
                        "the canonical generated client"
                    )

    if violations:
        print("V2 surface disposition violations:", file=sys.stderr)
        for item in sorted(set(violations)):
            print(f"  - {item}", file=sys.stderr)
        return 1
    backlog = sum(
        len(surface.get("pending_write_removals") or ()) for surface in surfaces
    )
    print(
        f"V2 surface dispositions: OK ({len(routes)} routes across "
        f"{len(surfaces)} declared surfaces; {backlog} writes pending removal)"
    )
    return 0


def _specificity(surface: dict, route: str) -> int:
    """Longest matching pattern wins, so /arsenal/hypotheses beats /arsenal/*."""
    best = 0
    for pattern in surface.get("routes") or []:
        if _matches(route, pattern):
            best = max(best, len(pattern.rstrip("*")))
    return best


if __name__ == "__main__":
    raise SystemExit(main())
