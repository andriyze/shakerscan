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


_ROUTE_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


@lru_cache(maxsize=1)
def _route_index() -> dict[tuple[str, str], tuple[str, str]]:
    """Map (METHOD, path) -> (defining file, handler source) across the api tree.

    Route handlers are found by their decorator, whatever object it hangs off:
    ``@app.post(...)`` in the composition root and ``@router.post(...)`` in an
    extracted domain router are the same public contract. Assertions written
    against this index survive a handler moving between modules, which a literal
    ``'@app.post("/x")' in api_py_source`` check cannot.
    """
    index: dict[tuple[str, str], tuple[str, str]] = {}
    for path in api_files():
        text = _read(path)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                func = decorator.func
                if not isinstance(func, ast.Attribute) or func.attr not in _ROUTE_METHODS:
                    continue
                if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
                    continue
                route = str(decorator.args[0].value)
                key = (func.attr.upper(), route)
                index[key] = (str(path), ast.get_source_segment(text, node) or "")
    return index


def route_is_declared(method: str, path: str) -> bool:
    """True when the api tree declares a handler for this method and path."""
    return (method.upper(), path) in _route_index()


def route_source(method: str, path: str) -> str:
    """Return the handler source for one route, wherever it is declared."""
    key = (method.upper(), path)
    entry = _route_index().get(key)
    assert entry is not None, f"no handler under api/ declares {method.upper()} {path}"
    return entry[1]


def route_defining_file(method: str, path: str) -> Path:
    """Return the api-tree file declaring this route."""
    key = (method.upper(), path)
    entry = _route_index().get(key)
    assert entry is not None, f"no handler under api/ declares {method.upper()} {path}"
    return Path(entry[0])


def declared_routes(prefix: str = "") -> tuple[tuple[str, str], ...]:
    """Every (METHOD, path) the api tree declares, optionally filtered by prefix."""
    return tuple(sorted(
        key for key in _route_index() if key[1].startswith(prefix)
    ))
