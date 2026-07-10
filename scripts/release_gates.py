#!/usr/bin/env python3
"""Run named release/test gates from the roadmap.

The gate names intentionally match docs/proposed-next-steps.md. Each gate is a
focused pytest slice over existing deterministic tests; this script is the stable
entry point CI, agents, and operators can call without remembering selectors.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

GATES: dict[str, tuple[str, ...]] = {
    "test:no-phantom-tools": (
        "tests/test_command_arsenal.py::test_tool_status_release_gate_passes_current_catalog_without_probe",
        "tests/test_command_arsenal.py::test_tool_status_release_gate_blocks_phantom_runnable_adapter",
    ),
    "test:no-benchmark-fitting": (
        "tests/test_benchmark_assertions.py::test_benchmark_requires_and_forbids_specific_findings",
        "tests/test_benchmark_assertions.py::test_benchmark_fails_missing_required_and_forbidden_findings",
        "tests/test_benchmark_assertions.py::test_benchmark_tracks_expected_recall",
        "tests/test_benchmark_rescore.py::test_benchmark_artifact_metadata_is_explicit_about_pass_fail",
    ),
    "test:no-ai-verified": (
        "tests/test_report_verification_gating.py",
        "tests/test_report_invariants.py::test_invariants_catch_ai_only_verified",
        "tests/test_worker_ai_merge.py::test_ai_exploited_on_inconclusive_becomes_likely_vulnerable_not_verified",
        "tests/test_ai_classifier_provenance.py::test_classification_meta_all_fallback_when_provider_unavailable",
    ),
    "test:evidence-provenance": (
        "tests/test_evidence_objects.py",
        "tests/test_command_arsenal.py::test_tool_receipt_and_evidence_instance_commands_are_record_only",
        "tests/test_command_arsenal.py::test_contracts_encode_planner_and_secret_boundaries",
    ),
    "test:fleet-current": (
        "tests/test_worker_freshness.py",
        "tests/test_fleet_truth.py",
        "tests/test_benchmark_rescore.py::test_fleet_gate_blocks_mixed_fleet",
        "tests/test_benchmark_rescore.py::test_fleet_gate_allows_uniform_fleet",
    ),
    "test:planner-scope": (
        "tests/test_action_scope.py",
        "tests/test_planner_evals.py::test_planner_eval_rejects_scope_broadening_and_shell",
        "tests/test_planner_evals.py::test_shipping_planner_never_violates_safety_invariants_on_any_fixture",
        "tests/test_planner_evals.py::test_shipping_planner_stays_read_only_and_within_context_scope",
    ),
    "test:planner-risk": (
        "tests/test_command_arsenal.py::test_state_changing_commands_are_gated_not_executable_shortcuts",
        "tests/test_planner_evals.py::test_planner_eval_rejects_scope_broadening_and_shell",
        "tests/test_planner_evals.py::test_shipping_planner_never_violates_safety_invariants_on_any_fixture",
        "tests/test_planner_evals.py::test_shipping_planner_stays_read_only_and_within_context_scope",
    ),
    "test:planner-no-shell": (
        "tests/test_command_arsenal.py::test_no_raw_shell_or_generic_execution_commands_are_exposed",
        "tests/test_planner_evals.py::test_planner_eval_rejects_scope_broadening_and_shell",
        "tests/test_planner_evals.py::test_shipping_planner_never_violates_safety_invariants_on_any_fixture",
    ),
    "test:mcp-read-only": (
        "tests/test_read_only_mcp.py",
        "tests/test_command_arsenal.py::test_no_raw_shell_or_generic_execution_commands_are_exposed",
        "tests/test_command_arsenal.py::test_state_changing_commands_are_gated_not_executable_shortcuts",
    ),
}


def gate_names() -> list[str]:
    return sorted(GATES)


def selectors_for(requested: list[str]) -> list[str]:
    selectors: list[str] = []
    unknown = sorted(set(requested) - set(GATES))
    if unknown:
        known = ", ".join(gate_names())
        raise ValueError(f"unknown release gate(s): {', '.join(unknown)}. Known gates: {known}")
    for gate in requested:
        selectors.extend(GATES[gate])
    return selectors


def _selector_path(selector: str) -> Path:
    return REPO_ROOT / selector.split("::", 1)[0]


def _defined_function_names(path: Path) -> set[str]:
    """All function/method names defined in a Python file (best-effort via AST)."""
    import ast

    names: set[str] = set()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return names
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
    return names


def validate_gate_mapping() -> list[str]:
    errors: list[str] = []
    for gate, selectors in GATES.items():
        if not selectors:
            errors.append(f"{gate}: no selectors configured")
        for selector in selectors:
            path = _selector_path(selector)
            if not path.exists():
                errors.append(f"{gate}: selector path does not exist: {selector}")
                continue
            # A stale ::test_name would otherwise pass file-only validation and
            # only fail (as a pytest error) at run time. Verify the referenced
            # test function actually exists.
            if "::" in selector:
                test_name = selector.rsplit("::", 1)[1]
                if test_name not in _defined_function_names(path):
                    errors.append(f"{gate}: selector test not found: {selector}")
    return errors


def run_gates(requested: list[str], *, extra_pytest_args: list[str] | None = None) -> int:
    selectors_for(requested)
    print(f"Running {len(requested)} release gate(s): {', '.join(requested)}")
    for gate in requested:
        selectors = list(GATES[gate])
        cmd = [sys.executable, "-m", "pytest", "-q", *selectors, *(extra_pytest_args or [])]
        print(f"\n== {gate} ==")
        status = subprocess.call(cmd, cwd=REPO_ROOT)
        if status != 0:
            return status
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gates", nargs="*", help="Gate names to run. Omit to run all gates.")
    parser.add_argument("--list", action="store_true", help="List available gates and exit.")
    parser.add_argument("--validate", action="store_true", help="Validate gate mapping and exit.")
    parser.add_argument("--pytest-arg", action="append", default=[], help="Extra argument passed to pytest.")
    args = parser.parse_args(argv)

    if args.list:
        for name in gate_names():
            print(name)
        return 0

    errors = validate_gate_mapping()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 2
    if args.validate:
        print(f"Validated {len(GATES)} release gate(s).")
        return 0

    requested = args.gates or gate_names()
    try:
        return run_gates(requested, extra_pytest_args=args.pytest_arg)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
