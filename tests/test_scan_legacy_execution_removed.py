from __future__ import annotations

import ast
import os
from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import parallel_scan  # noqa: E402
from scan.contracts import resolve_scan_contract  # noqa: E402
from scan.worker_contract import (  # noqa: E402
    WorkerScanContractError,
    resolve_worker_scan_admission,
)


ROOT = Path(__file__).resolve().parents[1]


def _tree(relative: str) -> ast.Module:
    path = ROOT / relative
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _function(relative: str, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    node = next(
        (
            item for item in _tree(relative).body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == name
        ),
        None,
    )
    assert node is not None, f"{relative} does not define {name}"
    return node


def _attribute_path(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        return (*_attribute_path(node.value), node.attr)
    return ()


def _constant_mapping_lookups(tree: ast.AST) -> set[str]:
    keys: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"get", "pop", "setdefault"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            keys.add(node.args[0].value)
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            keys.add(node.slice.value)
    return keys


class _LegacyAuthorityReadTrap(dict):
    """Fail if planner behavior reaches for a retired authority key."""

    forbidden = frozenset({
        "scan_type", "check_family", "asm_check_family", "xss", "sqli",
    })

    @classmethod
    def _check(cls, key: object) -> None:
        if key in cls.forbidden:
            raise AssertionError(f"parallel planner read retired authority key {key!r}")

    def get(self, key, default=None):
        self._check(key)
        return super().get(key, default)

    def __getitem__(self, key):
        self._check(key)
        return super().__getitem__(key)

    def __contains__(self, key):
        self._check(key)
        return super().__contains__(key)


def test_digestless_deterministic_scan_execution_is_absent_from_workers():
    worker = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    broker = (ROOT / "api" / "broker_worker.py").read_text(encoding="utf-8")

    assert not (ROOT / "api" / "scan" / "migration.py").exists()
    assert "require_legacy_scan_execution_window" not in worker
    assert "require_legacy_scan_execution_window" not in broker
    assert "_execute_legacy_reserved_deterministic_scan" not in worker
    assert worker.count("digest-less deterministic Scan execution has been removed") == 1
    assert broker.count("digest-less deterministic Scan execution has been removed") == 1
    assert "canonical_action_authority is not None" in broker


def test_parallel_scan_documentation_names_the_canonical_action_graph():
    source = (ROOT / "api" / "parallel_scan.py").read_text(encoding="utf-8")

    assert "each shard executes its persisted canonical action graph" in source
    assert "each shard runs run_scan()" not in source


def test_parallel_planner_has_no_legacy_mode_or_scanner_flag_authority():
    planner = _tree("api/parallel_scan.py")
    handler = _function("api/worker.py", "process_scan_plan_job")

    retired_keys = {
        "scan_type", "check_family", "asm_check_family", "xss", "sqli",
    }
    assert _constant_mapping_lookups(planner).isdisjoint(retired_keys)
    assert "ACTIVE_SCAN_TYPES" not in {
        node.id for node in ast.walk(planner) if isinstance(node, ast.Name)
    }
    assert not any(
        isinstance(node, ast.Call)
        and _attribute_path(node.func) == ("resolve_scan_budget",)
        for node in ast.walk(planner)
    )

    handler_calls = {
        _attribute_path(node.func)
        for node in ast.walk(handler)
        if isinstance(node, ast.Call)
    }
    assert ("CanonicalScanJob", "from_queue_payload") in handler_calls
    handler_messages = {
        node.value for node in ast.walk(handler)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert any(
        "parallel planning requires a canonical Scan queue payload" in message
        for message in handler_messages
    )


def test_parallel_planner_behavior_never_reads_retired_authority_keys():
    canonical = resolve_scan_contract(
        budget_profile="balanced",
        policy={"active_testing": True},
    ).option_metadata()
    parent = _LegacyAuthorityReadTrap({
        **canonical,
        "custom_endpoints": ["GET /api/orders", "GET /api/users"],
    })

    assert parallel_scan.resolve_auto_strategy(parent, "auto") == "scope"
    plan = parallel_scan.plan_shards(
        parent,
        requested_shards=2,
        strategy="scope",
        worker_count=2,
    )
    assert plan.strategy == "scope"
    assert plan.shard_count == 2


def test_conflicting_legacy_fields_cannot_change_parallel_plan_behavior():
    canonical = resolve_scan_contract(
        budget_profile="balanced",
        policy={"active_testing": True},
    ).option_metadata()
    clean = parallel_scan.plan_shards(
        dict(canonical), requested_shards=3, strategy="family", worker_count=3,
    )
    tainted = parallel_scan.plan_shards(
        {
            **canonical,
            "scan_type": "quick",
            "check_family": "bola",
            "asm_check_family": "auth",
            "xss": False,
            "sqli": False,
        },
        requested_shards=3,
        strategy="family",
        worker_count=3,
    )

    def behavior(plan):
        return [
            (
                shard.label,
                shard.options.get("coverage_attempt_family"),
                shard.options.get("no_early_stop", False),
            )
            for shard in plan.shards
        ]

    assert clean.strategy == tainted.strategy == "family"
    assert behavior(clean) == behavior(tainted)


@pytest.mark.parametrize(
    ("field_parts", "value"),
    [
        (("scan", "_type"), "smart"),
        (("legacy", "_scan_type"), "deep"),
        (("qui", "ck"), False),
        (("thor", "ough"), False),
    ],
)
def test_worker_behavior_rejects_indirectly_constructed_legacy_authority(
    field_parts,
    value,
):
    options = resolve_scan_contract(
        budget_profile="balanced",
        policy={"active_testing": False},
    ).option_metadata()
    options["".join(field_parts)] = value

    with pytest.raises(WorkerScanContractError, match="legacy Scan authority"):
        resolve_worker_scan_admission(options)


def test_normal_scheduler_has_no_digestless_queue_fallback():
    source = api_tree_source()
    scheduler = source[
        source.index("async def run_due_schedules"):
        source.index("async def schedule_runner")
    ]

    assert '"normal schedule did not compile canonical Scan authority"' in scheduler
    assert "canonical_job.queue_payload(" in scheduler
    assert "'scheduled': True" not in scheduler
    assert '"v2" if canonical_schedule else "legacy"' not in scheduler


def test_scan_placement_uses_budget_profiles_not_legacy_scan_tiers():
    sources = {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "api/api.py",
            "api/job_queue.py",
            "api/scan/jobs.py",
            "api/worker.py",
            "scripts/fleet_cli.py",
        )
    }
    combined = "\n".join(sources.values())

    assert "budget_profiles" in combined
    assert "budget_profile" in combined
    assert "scan_tiers" not in combined
    assert "scan_tier" not in combined
    assert "--scan-tier" not in combined
    assert "HISTORICAL_DAST_SCAN_TYPES" not in combined
    assert "LEGACY_DAST_SCAN_TYPE_LABELS" not in combined
