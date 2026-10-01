"""Arsenal commands call route handlers as plain functions, never with FastAPI's unresolved markers.

FastAPI turns a ``Query(...)`` default into a value only while serving an HTTP request. A
dispatcher that calls a handler directly and leaves such a parameter out hands the handler the
marker object: it is truthy, so the handler filters on it or sends it to the database. That made
``finding.list`` (the MCP findings tool) and ``exposure.graph.get`` answer HTTP 500 on every call.
"""

from __future__ import annotations

import ast
import asyncio
import functools
from pathlib import Path

import pytest
from pydantic.fields import FieldInfo

import api.arsenal_routes.router as arsenal

ROOT = Path(__file__).resolve().parents[1]


def _recording(monkeypatch, module, name, result):
    """Replace a route handler with one that keeps its signature and records what it was given."""
    real = getattr(module, name)
    calls = []

    @functools.wraps(real)
    async def handler(*args, **kwargs):
        calls.append(kwargs)
        return result

    monkeypatch.setattr(module, name, handler)
    return calls


def _no_markers(arguments):
    leaked = {name: value for name, value in arguments.items() if isinstance(value, FieldInfo)}
    assert leaked == {}, f"FastAPI markers reached the handler: {sorted(leaked)}"


def test_finding_list_passes_values_for_every_parameter(monkeypatch):
    calls = _recording(monkeypatch, arsenal._finding_routes, "list_findings", {"findings": []})
    asyncio.run(arsenal._arsenal_dispatch_finding_list({"severity": "high"}))
    (arguments,) = calls
    _no_markers(arguments)
    assert arguments["severity"] == "high"
    # The parameters the dispatcher used to leave as markers.
    assert arguments["not_seen_within_days"] is None and arguments["driven_by"] is None
    assert (arguments["limit"], arguments["offset"]) == (100, 0)


def test_finding_list_accepts_not_seen_within_days(monkeypatch):
    calls = _recording(monkeypatch, arsenal._finding_routes, "list_findings", {"findings": []})
    asyncio.run(arsenal._arsenal_dispatch_finding_list({"not_seen_within_days": "30"}))
    assert calls[0]["not_seen_within_days"] == 30


def test_exposure_graph_uses_the_handler_defaults(monkeypatch):
    calls = _recording(monkeypatch, arsenal._exposure, "exposure_graph", {"nodes": []})
    asyncio.run(arsenal._arsenal_dispatch_exposure_graph_get({"focus": "example.com"}))
    (arguments,) = calls
    _no_markers(arguments)
    assert arguments["focus"] == "example.com"
    assert (arguments["limit_findings"], arguments["limit_scans"], arguments["depth"]) == (250, 150, 1)


def test_mission_timeline_defaults_and_honours_include_flags(monkeypatch):
    calls = _recording(monkeypatch, arsenal._operations, "mission_timeline", {"events": []})
    asyncio.run(arsenal._arsenal_dispatch_mission_timeline({}))
    asyncio.run(arsenal._arsenal_dispatch_mission_timeline({"include_scans": False}))
    defaults, narrowed = calls
    _no_markers(defaults)
    assert defaults["include_scans"] is True and defaults["include_exports"] is True
    # A flag the caller set reaches the handler instead of being dropped.
    assert narrowed["include_scans"] is False and narrowed["include_evidence"] is True


def test_call_route_rejects_a_parameter_the_handler_does_not_have():
    async def handler(limit: int = arsenal.Query(10, ge=1)):
        return limit

    assert asyncio.run(arsenal._call_route(handler)) == 10
    with pytest.raises(TypeError, match="no parameter page"):
        asyncio.run(arsenal._call_route(handler, page=2))


def _route_signatures():
    """Every function in the route modules Arsenal calls directly, with its FastAPI-marker parameters."""
    modules = {
        "_ai_targets": "api/ai_targets/router.py",
        "_exposure": "api/exposure/router.py",
        "_finding_exceptions": "api/finding_exceptions/router.py",
        "_finding_routes": "api/finding_routes/router.py",
        "_model_intake": "api/model_intake/router.py",
        "_operations": "api/operations/router.py",
        "_targets": "api/targets/router.py",
    }
    markers = {"Query", "Path", "Body", "Header", "Cookie", "Form", "File", "Depends"}
    signatures = {}
    for alias, path in modules.items():
        for node in ast.walk(ast.parse((ROOT / path).read_text(encoding="utf-8"))):
            if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            positional = node.args.args
            defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
            pairs = list(zip(positional, defaults)) + list(zip(node.args.kwonlyargs, node.args.kw_defaults))
            signatures[(alias, node.name)] = [
                (index, argument.arg) for index, (argument, default) in enumerate(pairs)
                if isinstance(default, ast.Call) and getattr(default.func, "id", None) in markers
            ]
    return signatures


def test_no_dispatcher_calls_a_route_handler_leaving_a_marker_parameter_out():
    signatures = _route_signatures()
    tree = ast.parse((ROOT / "api/arsenal_routes/router.py").read_text(encoding="utf-8"))
    offenders = []
    for function in ast.walk(tree):
        if not (isinstance(function, ast.AsyncFunctionDef) and function.name.startswith("_arsenal_dispatch_")):
            continue
        for call in ast.walk(function):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)):
                continue
            marked = signatures.get((call.func.value.id, call.func.attr))
            if not marked:
                continue
            passed = {keyword.arg for keyword in call.keywords}
            missing = [name for index, name in marked if index >= len(call.args) and name not in passed]
            if missing:
                offenders.append(f"{function.name} -> {call.func.value.id}.{call.func.attr}: {missing}")
    assert offenders == [], "call these through _call_route: " + "; ".join(offenders)
