"""A route handler called directly is given every parameter whose default is a FastAPI marker.

FastAPI resolves ``Query(None)`` (and ``Path``, ``Body``, ``Header``, ``Depends`` ...) only when it
serves the request. A Python call to the same function gets the marker object itself as the
value: ``GET /api/v1/findings`` (the installed CLI's findings command) called ``list_findings``
without ``not_seen_within_days``, so a ``Query`` object reached SQL and the route answered 500
(``TypeError: must be real number, not Query``). A ``bool = Query(False)`` marker is truthy,
which silently inverts a flag.

This test finds every direct call in api/ that resolves to a route handler (the handler
itself in its module, a ``*args, **kwargs`` forwarding proxy of the only function with that
name, a name imported from the handler's module, or ``module.handler``) and requires each
marker-defaulted parameter to be passed explicitly. A proxy whose name several functions share
is not resolved.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "api"
MARKERS = frozenset({"Query", "Path", "Body", "Header", "Cookie", "Form", "File", "Depends", "Security"})
ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "api_route"})


def _is_marker(node: ast.AST | None) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return (isinstance(func, ast.Name) and func.id in MARKERS) or (
        isinstance(func, ast.Attribute) and func.attr in MARKERS)


def _is_route(function: ast.AST) -> bool:
    return any(
        isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr in ROUTE_METHODS
        for item in getattr(function, "decorator_list", ())
    )


def _is_proxy(function: ast.AST) -> bool:
    """``async def name(*a, **k): return await <something>.name(*a, **k)``."""
    args = function.args
    return bool(args.vararg and args.kwarg and not args.args and not args.posonlyargs and not args.kwonlyargs)


def _marker_parameters(function: ast.AST) -> tuple[list[str], list[str]]:
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    marked = [arg.arg for arg, default in zip(positional, defaults) if _is_marker(default)]
    marked += [arg.arg for arg, default in zip(args.kwonlyargs, args.kw_defaults) if _is_marker(default)]
    return [arg.arg for arg in positional], marked


def _modules() -> dict[Path, ast.Module]:
    return {path: ast.parse(path.read_text(encoding="utf-8"), filename=str(path)) for path in sorted(API.rglob("*.py"))}


def _dotted(path: Path) -> str:
    return ".".join(path.relative_to(API).with_suffix("").parts)


def _same_module(route_module: str, imported: str) -> bool:
    imported = imported.lstrip(".")
    if imported.startswith("api."):
        imported = imported[len("api."):]
    return bool(imported) and (route_module == imported or route_module.endswith("." + imported))


def _unresolved_calls() -> list[str]:
    modules = _modules()
    # name -> [(module, positional parameters, marker-defaulted parameters)]
    routes: dict[str, list[tuple[str, list[str], list[str]]]] = {}
    definitions: dict[str, list[ast.AST]] = {}
    for path, tree in modules.items():
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not _is_proxy(node):
                    definitions.setdefault(node.name, []).append(node)
                if _is_route(node):
                    positional, marked = _marker_parameters(node)
                    if marked:
                        routes.setdefault(node.name, []).append((_dotted(path), positional, marked))
    problems: list[str] = []
    for path, tree in modules.items():
        here = _dotted(path)
        top = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        name_from: dict[str, str] = {}  # a function name -> the module it was imported from
        module_alias: dict[str, str] = {}  # a local alias -> the module it names
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    local = alias.asname or alias.name
                    name_from[local] = node.module or ""
                    module_alias[local] = f"{node.module}.{alias.name}" if node.module else alias.name
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    module_alias[alias.asname or alias.name] = alias.name
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name):
                name = func.id
                local = top.get(name)
                if local is not None and _is_route(local):
                    candidates = [route for route in routes.get(name, ()) if route[0] == here]
                elif local is not None and _is_proxy(local):
                    # A forwarding proxy: resolved when exactly one real definition has the name.
                    candidates = routes.get(name, []) if len(definitions.get(name, ())) == 1 else []
                elif name in name_from:
                    candidates = [route for route in routes.get(name, ())
                                  if _same_module(route[0], name_from[name])]
                else:
                    candidates = []
            elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                    and func.value.id in module_alias:
                name = func.attr
                candidates = [route for route in routes.get(name, ())
                              if _same_module(route[0], module_alias[func.value.id])]
            else:
                continue
            if not candidates:
                continue
            if any(keyword.arg is None for keyword in node.keywords) or any(
                    isinstance(argument, ast.Starred) for argument in node.args):
                continue  # forwarded as received: a proxy, judged at its own call sites
            passed = {keyword.arg for keyword in node.keywords}
            for _module, positional, marked in candidates:
                passed_here = passed | set(positional[:len(node.args)])
                missing = [parameter for parameter in marked if parameter not in passed_here]
                if missing:
                    problems.append(f"{path.relative_to(ROOT)}:{node.lineno} {name}() omits {missing}")
    return problems


def test_every_direct_route_call_passes_its_marker_defaulted_parameters():
    assert _unresolved_calls() == []


def test_the_guard_sees_the_cli_findings_bridge():
    """The guard resolves the bridge that failed: operations' forwarding proxy of list_findings."""
    source = (API / "operations" / "router.py").read_text(encoding="utf-8")
    assert "return await list_findings(" in source
    tree = ast.parse(source)
    proxy = next(node for node in tree.body
                 if isinstance(node, ast.AsyncFunctionDef) and node.name == "list_findings")
    assert _is_proxy(proxy)
    bridge = next(node for node in tree.body
                  if isinstance(node, ast.AsyncFunctionDef) and node.name == "list_cli_v1_findings")
    call = next(node for node in ast.walk(bridge)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "list_findings")
    passed = {keyword.arg for keyword in call.keywords}
    assert {"not_seen_within_days", "seen_within_days", "verification_verdict"} <= passed
