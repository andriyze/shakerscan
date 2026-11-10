#!/usr/bin/env python3
"""Reject names that are used but never defined in tracked Python sources.

A missing import on a path no test reaches is a ``NameError`` waiting for production: the
2026-11 audit found four on live paths (a route, a scan stage, a login step, a script). This
gate reads every tracked ``*.py`` file with pyflakes and fails on the messages that mean a name
cannot resolve. It reports nothing else pyflakes knows about (unused imports, redefinitions):
those are style, and this gate is about code that raises.

A name used only in an annotation is reported too. It does not raise under
``from __future__ import annotations``, but it does as soon as something evaluates the hints
(FastAPI on a route signature, pydantic, ``typing.get_type_hints``), so import it or name a type
that exists.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Sequence
from pathlib import Path
import subprocess
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
# pyflakes message classes that mean "this name does not resolve".
UNDEFINED_MESSAGES = ("UndefinedName", "UndefinedLocal", "UndefinedExport")


class UndefinedNameCheckError(RuntimeError):
    """The gate could not run (pyflakes missing, or no source was found)."""


def tracked_python_files(root: Path) -> tuple[Path, ...]:
    """Every tracked ``*.py`` under ``root``; without Git metadata, every one on disk."""
    try:
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--", "*.py"],
            check=True, capture_output=True,
        ).stdout.decode("utf-8").split("\0")
        files = tuple(root / name for name in listed if name)
    except (OSError, subprocess.CalledProcessError):
        files = ()
    if not files:
        files = tuple(
            path for path in root.rglob("*.py")
            if not {"node_modules", ".git", ".venv", "venv"} & set(path.parts)
        )
    # A file deleted in the working tree is still listed by Git until the deletion is staged.
    return tuple(sorted(path for path in files if path.is_file()))


def undefined_names(paths: Iterable[Path], *, root: Path = REPOSITORY_ROOT) -> list[str]:
    """``path:line:col: message`` for every unresolved name (and every file that does not parse)."""
    try:
        from pyflakes import checker, messages
    except ModuleNotFoundError as exc:
        raise UndefinedNameCheckError(
            "pyflakes is not installed: "
            "python -m pip install --require-hashes -r .github/requirements/pyflakes.lock"
        ) from exc
    import ast

    wanted = tuple(getattr(messages, name) for name in UNDEFINED_MESSAGES)
    problems: list[str] = []
    for path in paths:
        try:
            shown = path.relative_to(root)
        except ValueError:
            shown = path
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except (SyntaxError, ValueError) as exc:
            problems.append(f"{shown}:{getattr(exc, 'lineno', 0) or 0}:0: does not parse: {exc}")
            continue
        for message in sorted(
            checker.Checker(tree, filename=str(path)).messages,
            key=lambda item: (item.lineno, item.col),
        ):
            if isinstance(message, wanted):
                text = message.message % message.message_args
                problems.append(f"{shown}:{message.lineno}:{message.col + 1}: {text}")
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "paths", nargs="*", type=Path,
        help="files or directories to check (default: every tracked *.py file)",
    )
    args = parser.parse_args(argv)
    try:
        if args.paths:
            files: list[Path] = []
            for path in args.paths:
                files.extend(sorted(path.rglob("*.py")) if path.is_dir() else [path])
        else:
            files = list(tracked_python_files(REPOSITORY_ROOT))
        if not files:
            raise UndefinedNameCheckError("no Python source was found")
        problems = undefined_names(files)
    except UndefinedNameCheckError as exc:
        print(f"undefined-name check could not run: {exc}", file=sys.stderr)
        return 2
    if problems:
        print("\n".join(problems), file=sys.stderr)
        print(f"undefined names: {len(problems)} in {len(files)} files", file=sys.stderr)
        return 1
    print(f"undefined names: OK ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
