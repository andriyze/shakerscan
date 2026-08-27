#!/usr/bin/env python3
"""Verify the public installer ships every module its installed files import.

`install/index.sh` carries a hand-maintained list of `download` lines. The API and workers run
from images that contain the whole tree, so the list only has to cover what runs on the HOST --
the CLI and the provisioners it calls. That made omissions invisible in development and fatal on a
real install: a missing module surfaces as `ModuleNotFoundError` the first time an operator runs
the command that needs it, with nothing in CI to catch the drift.

This computes the transitive first-party import closure of the installed Python files and reports
any module reachable from them that the installer does not ship. Run:

    python3 scripts/check_installed_import_closure.py
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install" / "index.sh"

# sys.path roots the installed runtime uses. `api/` and `scanner/` are added as roots, so their
# modules import each other by bare name rather than by package path.
IMPORT_ROOTS = ("api", "scanner", "")


def installed_paths() -> set[str]:
    text = INSTALLER.read_text(encoding="utf-8")
    return set(re.findall(r'download "\$REPO_RAW_BASE/([^"]+)"', text))


def _resolve_absolute(module: str) -> str | None:
    for root in IMPORT_ROOTS:
        parts = ([root] if root else []) + module.split(".")
        for suffix in (".py", "/__init__.py"):
            candidate = "/".join(parts) + suffix
            if (ROOT / candidate).is_file():
                return candidate
    return None


def _resolve_relative(module: str, origin: str, level: int) -> str | None:
    base = Path(origin).parent
    for _ in range(level - 1):
        base = base.parent
    parts = module.split(".") if module else []
    for suffix in (".py", "/__init__.py"):
        candidate = str(base.joinpath(*parts)) + suffix
        if (ROOT / candidate).is_file():
            return candidate
    return None


def imported_paths(path: str) -> set[str]:
    """Return the first-party repo paths one module imports, absolute or relative."""
    try:
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    except (SyntaxError, FileNotFoundError, UnicodeDecodeError):
        return set()
    found: set[str] = set()
    for node in ast.walk(tree):
        candidates: list[str | None] = []
        if isinstance(node, ast.Import):
            candidates = [_resolve_absolute(alias.name) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                candidates = [_resolve_relative(module, path, node.level)]
                candidates += [
                    _resolve_relative(f"{module}.{alias.name}".strip("."), path, node.level)
                    for alias in node.names
                ]
            elif module:
                # `from x import y` may name a module or a symbol; try both.
                candidates = [_resolve_absolute(module)]
                candidates += [_resolve_absolute(f"{module}.{alias.name}") for alias in node.names]
        found.update(item for item in candidates if item)
    return found


def missing_modules() -> dict[str, set[str]]:
    """Return {missing repo path: {installed files that reach it}} over the transitive closure."""
    installed = installed_paths()
    seen: set[str] = set()
    queue = [path for path in installed if path.endswith(".py")]
    missing: dict[str, set[str]] = {}
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        for target in imported_paths(current):
            if target not in installed:
                missing.setdefault(target, set()).add(current)
            if target not in seen:
                queue.append(target)
    return missing


def main() -> int:
    missing = missing_modules()
    if not missing:
        print("installed import closure: OK")
        return 0
    print("installed import closure: INCOMPLETE", file=sys.stderr)
    for target in sorted(missing):
        reachers = ", ".join(sorted(missing[target])[:3])
        print(f"  {target} <- {reachers}", file=sys.stderr)
    print(
        f"\n{len(missing)} module(s) are imported by installed files but not shipped by "
        "install/index.sh; add a download line for each.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
