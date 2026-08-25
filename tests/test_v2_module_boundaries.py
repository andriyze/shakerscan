"""Structural gates for the V2 product/module ownership boundaries.

These checks intentionally parse Python syntax instead of matching formatting-
sensitive source snippets. Runtime authority is covered by the behavioral Scan
contract suites; this file verifies module ownership and composition.
"""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _tree(relative: str) -> ast.Module:
    return ast.parse(_source(relative), filename=relative)


def _reject_monolith_imports(relative: str) -> None:
    violations: list[str] = []
    for node in ast.walk(_tree(relative)):
        if isinstance(node, ast.Import):
            violations.extend(
                alias.name for alias in node.names
                if alias.name in {"api", "worker"}
            )
        elif isinstance(node, ast.ImportFrom) and node.module in {"api", "worker"}:
            violations.append(f"from {node.module} import")
    assert not violations, f"{relative} imports a monolith: {violations}"


def _top_level_definition(relative: str, name: str) -> ast.AST | None:
    return next(
        (
            node for node in _tree(relative).body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ),
        None,
    )


def _class_method(relative: str, class_name: str, method_name: str) -> ast.AST | None:
    class_node = _top_level_definition(relative, class_name)
    if not isinstance(class_node, ast.ClassDef):
        return None
    return next(
        (
            node for node in class_node.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == method_name
        ),
        None,
    )


def _name_references(relative: str) -> set[str]:
    return {
        node.id for node in ast.walk(_tree(relative))
        if isinstance(node, ast.Name)
    }


def _attribute_path(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        return (*_attribute_path(node.value), node.attr)
    return ()


def _has_call(relative: str, path: tuple[str, ...]) -> bool:
    return any(
        isinstance(node, ast.Call) and _attribute_path(node.func) == path
        for node in ast.walk(_tree(relative))
    )


def _included_routers(relative: str) -> set[str]:
    routers: set[str] = set()
    for node in ast.walk(_tree(relative)):
        if (
            not isinstance(node, ast.Call)
            or _attribute_path(node.func) != ("app", "include_router")
        ):
            continue
        if node.args and isinstance(node.args[0], ast.Name):
            routers.add(node.args[0].id)
    return routers


def _decorated_routes(relative: str, owner: str) -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for node in ast.walk(_tree(relative)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            path = _attribute_path(decorator.func)
            route = decorator.args[0]
            if (
                len(path) == 2
                and path[0] == owner
                and path[1] in {"get", "post", "put", "patch", "delete"}
                and isinstance(route, ast.Constant)
                and isinstance(route.value, str)
            ):
                routes.add((path[1], route.value))
    return routes


def test_api_routers_own_real_endpoint_behavior_without_monolith_imports():
    for relative in (
        "api/credential_api.py",
        "api/request_collection_api.py",
        "api/scan/read_router.py",
    ):
        _reject_monolith_imports(relative)

    assert "PostgresCredentialProfileStore" in _name_references("api/credential_api.py")
    assert _top_level_definition("api/request_collection_api.py", "create_request_collection")
    assert "PostgresScanActionStore" in _name_references("api/scan/read_router.py")
    assert {
        "credential_router", "request_collection_router", "scan_read_router",
    }.issubset(_included_routers("api/api.py"))
    assert ("post", "/request-collections") in _decorated_routes(
        "api/request_collection_api.py", "router",
    )
    assert ("get", "/scans/{scan_id}/actions") in _decorated_routes(
        "api/scan/read_router.py", "router",
    )
    assert ("post", "/request-collections") not in _decorated_routes("api/api.py", "app")
    assert ("get", "/scans/{scan_id}/actions") not in _decorated_routes("api/api.py", "app")


def test_product_services_are_concrete_and_independent_of_api_monolith():
    modules = (
        "api/scan/worker_action_executor.py",
        "api/hunt/action_dispatcher.py",
        "api/model_intake_control_plane.py",
        "api/fleet.py",
    )
    for relative in modules:
        _reject_monolith_imports(relative)

    assert isinstance(
        _class_method("api/scan/worker_action_executor.py", "ReceiptScanActionExecutor", "execute"),
        ast.AsyncFunctionDef,
    )
    assert isinstance(
        _class_method("api/hunt/action_dispatcher.py", "HuntActionDispatcher", "execute"),
        ast.AsyncFunctionDef,
    )
    for function in ("freeze_evidence_manifest", "issue_admission_v2"):
        assert isinstance(
            _top_level_definition("api/model_intake_control_plane.py", function),
            ast.FunctionDef,
        )
    for function in ("enroll_node", "record_heartbeat"):
        assert isinstance(_top_level_definition("api/fleet.py", function), ast.AsyncFunctionDef)


def test_worker_product_handlers_own_behavior_without_worker_wrappers():
    _reject_monolith_imports("api/worker_handlers/non_dast.py")
    handler_run = _class_method(
        "api/worker_handlers/non_dast.py", "NonDastWorkerHandler", "run",
    )
    assert isinstance(handler_run, ast.AsyncFunctionDef)
    handler_attributes = {
        node.attr for node in ast.walk(handler_run) if isinstance(node, ast.Attribute)
    }
    assert {"_run_device_posture", "_run_model_intake", "_run_ai_gate"}.issubset(
        handler_attributes
    )
    for method, executor in (
        ("_run_device_posture", "run_device_posture_scan"),
        ("_run_model_intake", "run_model_intake_scan"),
        ("_run_ai_gate", "run_ai_target_scan"),
    ):
        method_node = _class_method(
            "api/worker_handlers/non_dast.py", "NonDastWorkerHandler", method,
        )
        assert method_node is not None
        assert executor in {
            node.id for node in ast.walk(method_node) if isinstance(node, ast.Name)
        }
    assert _top_level_definition("api/worker.py", "run_scan") is None

    worker_tree = _tree("api/worker.py")
    assert any(
        isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "run_scan" for target in node.targets)
        and _attribute_path(node.value) == ("_NON_DAST_WORKER_HANDLER", "run")
        for node in ast.walk(worker_tree)
    )


def test_parallel_parent_uses_canonical_compiler_service():
    assert isinstance(
        _top_level_definition("api/scan/parallel_compiler.py", "ParallelActionPartition"),
        ast.ClassDef,
    )
    assert isinstance(
        _class_method("api/scan/parallel_compiler.py", "ParallelActionPlanCompiler", "compile"),
        ast.FunctionDef,
    )
    assert isinstance(
        _class_method(
            "api/scan/parallel_compiler.py",
            "ParallelActionPlanCompiler",
            "plan_parent",
        ),
        ast.FunctionDef,
    )
    planner = _top_level_definition("api/worker.py", "process_scan_plan_job")
    assert isinstance(planner, ast.AsyncFunctionDef)
    calls = {
        _attribute_path(node.func)
        for node in ast.walk(planner)
        if isinstance(node, ast.Call)
    }
    assert ("parallel_compiler", "plan_parent") in calls
    assert ("parallel_compiler", "compile") in calls
    assert not {
        ("parallel_scan", "plan_shards"),
        ("parallel_scan", "plan_coverage_shards"),
        ("parallel_scan", "plan_coverage_family_shards"),
        ("parallel_scan", "with_coverage_backbone"),
    }.intersection(calls)
    assert _has_call("api/worker.py", ("validate_parallel_partition_record",))

    parallel_tree = _tree("api/parallel_scan.py")
    assert "ACTIVE_SCAN_TYPES" not in {
        node.id for node in ast.walk(parallel_tree) if isinstance(node, ast.Name)
    }
    assert "scan_type" not in {
        node.value
        for node in ast.walk(parallel_tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
