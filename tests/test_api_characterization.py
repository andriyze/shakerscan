"""Characterization tests that lock the public API contract before, during, and
after the api.py decomposition.

The golden fixtures under ``tests/fixtures/api_contract/`` are the frozen public
surface: the normalized route manifest, the OpenAPI operation set, and the app
composition (middleware order and exception handlers). Every behavior-preserving
router extraction must leave all three byte-identical. When a commit deliberately
changes the public contract, regenerate the fixtures in the same commit:

    SHAKERSCAN_UPDATE_API_CONTRACT=1 python3 -m pytest tests/test_api_characterization.py

The module-size ratchet keeps the monolith from growing while extraction is in
progress; it is lowered by each extraction, never raised.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

from scripts.check_module_size import check_module_sizes


_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "tests" / "fixtures" / "api_contract"


def _app():
    try:
        import api.api as api_module
    except Exception as exc:  # pragma: no cover - host dependency guard
        pytest.skip(f"api.api is not importable in this environment: {exc}")
    return api_module.app


def _iter_effective_routes(routes):
    """Yield leaf routes, resolving included routers across Starlette versions.

    Older Starlette flattens ``include_router`` into ``app.routes``; Starlette
    1.6 mounts a lazy ``_IncludedRouter`` wrapper that exposes its child routes
    through ``original_router``. Resolving both makes the manifest reflect the
    routes that are actually served regardless of how they are mounted.
    """
    for route in routes:
        included = getattr(route, "original_router", None)
        if included is not None and getattr(included, "routes", None) is not None:
            yield from _iter_effective_routes(included.routes)
        else:
            yield route


def _normalized_routes(app):
    rows = []
    for route in _iter_effective_routes(app.routes):
        path = getattr(route, "path", None)
        if path is None:
            continue
        methods = sorted(getattr(route, "methods", None) or [])
        rows.append({
            "path": path,
            "methods": methods,
            "name": getattr(route, "name", None),
        })
    return sorted(rows, key=lambda r: (r["path"] or "", r["methods"], r["name"] or ""))


def _operations(app):
    spec = app.openapi()
    ops = []
    for path, item in spec.get("paths", {}).items():
        for method, body in item.items():
            if isinstance(body, dict) and "operationId" in body:
                ops.append({
                    "path": path, "method": method,
                    "operation_id": body.get("operationId"),
                })
    return sorted(ops, key=lambda r: (r["path"], r["method"]))


def _app_contract(app):
    return {
        "middleware": [
            getattr(x.cls, "__name__", str(x.cls)) for x in app.user_middleware
        ],
        "exception_handlers": sorted(
            str(getattr(k, "__name__", k)) for k in app.exception_handlers.keys()
        ),
        "route_count": len([
            r for r in _iter_effective_routes(app.routes)
            if getattr(r, "methods", None)
        ]),
    }


def _load(name):
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _maybe_update(name, value):
    if os.environ.get("SHAKERSCAN_UPDATE_API_CONTRACT") == "1":
        (_FIXTURES / name).write_text(
            json.dumps(value, indent=2) + "\n", encoding="utf-8",
        )


def test_route_manifest_is_unchanged():
    app = _app()
    live = _normalized_routes(app)
    _maybe_update("routes.json", live)
    stored = _load("routes.json")
    assert live == stored, (
        "The route manifest changed. A behavior-preserving extraction must keep "
        "every path/method/name identical; regenerate the fixture only for a "
        "deliberate public-contract change."
    )


def test_openapi_operations_are_unchanged():
    app = _app()
    live = _operations(app)
    _maybe_update("operations.json", live)
    stored = _load("operations.json")
    live_ids = {row["operation_id"] for row in live}
    stored_ids = {row["operation_id"] for row in stored}
    assert live_ids == stored_ids, (
        "OpenAPI operationId set changed: "
        f"added={sorted(live_ids - stored_ids)} removed={sorted(stored_ids - live_ids)}"
    )
    assert live == stored, "an operation's path or method changed"


def test_app_composition_is_unchanged():
    app = _app()
    live = _app_contract(app)
    _maybe_update("app_contract.json", live)
    stored = _load("app_contract.json")
    # Middleware order is part of behavior and must be preserved exactly.
    assert live["middleware"] == stored["middleware"]
    assert live["exception_handlers"] == stored["exception_handlers"]
    assert live["route_count"] == stored["route_count"]


def test_module_size_ratchet_holds():
    failures = check_module_sizes()
    assert not failures, "\n".join(failures)


def test_domain_modules_do_not_import_the_app_module():
    """Extracted domain code must not import back into api.api.

    The dependency direction is app-composition -> routers -> services. A domain
    module that imports ``api.api`` recreates the circular monolith coupling the
    decomposition exists to remove. api.api itself, and the app entrypoints, are
    exempt.
    """
    offenders: list[str] = []
    allow = {"api/api.py"}
    for path in sorted((_ROOT / "api").rglob("*.py")):
        rel = path.relative_to(_ROOT).as_posix()
        if rel in allow:
            continue
        text = path.read_text(encoding="utf-8")
        if "import api.api" in text or "from api.api import" in text or "from api import api" in text:
            offenders.append(rel)
    assert not offenders, (
        "these api submodules import the monolith (api.api), which reintroduces "
        f"the coupling decomposition removes: {offenders}"
    )


def test_api_packages_do_not_shadow_flat_runtime_modules():
    """An api/<pkg>/ name must not collide with a top-level scanner module.

    The release image copies scanner/*.py and api/*.py into the same /app
    directory, and the dev-source sync copies every api subpackage there too. A
    package whose name matches a scanner module silently shadows it at runtime:
    api/findings/ hid scanner/findings.py, which api/worker.py imports in six
    places, and the break only appears once workers pick up a current image.
    """
    root = _ROOT
    api_packages = {
        path.name
        for path in (root / "api").iterdir()
        if path.is_dir() and (path / "__init__.py").is_file()
    }
    flat_modules = {
        path.stem
        for path in list((root / "scanner").glob("*.py")) + list((root / "api").glob("*.py"))
    }
    collisions = sorted(api_packages & flat_modules)
    assert not collisions, (
        "these api packages shadow a flat module of the same name once both are "
        f"copied into /app, breaking that module's importers: {collisions}"
    )


def test_extracted_routers_register_routes_on_their_own_router():
    """No module under api/ outside the composition root may decorate with ``@app.``.

    A route handler carries its decorator when it is moved. If an extraction
    drags one out of api.py and the destination happens to bind some name ``app``
    -- an extraction tool once resolved it to the model-intake admission
    webhook's separate FastAPI instance -- the route silently disappears from the
    public API and reappears on an unrelated app. The route manifest catches the
    disappearance, but this names the cause directly.
    """
    offenders: list[str] = []
    for path in sorted((_ROOT / "api").rglob("*.py")):
        if path == _ROOT / "api" / "api.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        # A standalone service module that builds its own FastAPI instance is
        # allowed to decorate with it; the bug is decorating with an `app` the
        # module imported from somewhere else.
        owns_app = any(
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "app" for t in node.targets)
            for node in tree.body
        )
        if owns_app:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                call = decorator.func if isinstance(decorator, ast.Call) else decorator
                if (
                    isinstance(call, ast.Attribute)
                    and isinstance(call.value, ast.Name)
                    and call.value.id == "app"
                ):
                    offenders.append(
                        f"{path.relative_to(_ROOT)}:{node.lineno} {node.name}"
                    )
    assert not offenders, (
        "these handlers register on an `app` object instead of their module's "
        f"APIRouter, so they are not on the public API: {offenders}"
    )
