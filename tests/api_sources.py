"""Locate api-tree source text for structural assertions.

Several suites assert guarantees about a specific handler or model by slicing
``api/api.py`` between two textual markers. That encodes where the code happens
to live, so every router extraction breaks them even when the guarantee still
holds. These helpers resolve a definition by name anywhere under ``api/`` and
return exactly its source, so the assertions survive code moving between the
composition root and an extracted router.
"""

from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def api_files() -> tuple[Path, ...]:
    return tuple(sorted((ROOT / "api").rglob("*.py")))


@lru_cache(maxsize=None)
def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _definition(name: str) -> tuple[str, ast.AST]:
    wanted = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for path in api_files():
        text = _read(path)
        if f"def {name}(" not in text and f"class {name}" not in text:
            continue
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, wanted) and node.name == name:
                return text, node
    raise AssertionError(f"no module under api/ defines {name!r}")


def definition_source(name: str) -> str:
    """Return the exact source of the function or class named ``name``."""
    text, node = _definition(name)
    return ast.get_source_segment(text, node) or ""


def defining_file(name: str) -> Path:
    """Return the api-tree file that defines ``name``."""
    for path in api_files():
        text = _read(path)
        if f"def {name}(" not in text and f"class {name}" not in text:
            continue
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
                return path
    raise AssertionError(f"no module under api/ defines {name!r}")


def api_tree_source() -> str:
    """Concatenate every api-tree module, for whole-tree text assertions."""
    return "\n".join(_read(path) for path in api_files())
