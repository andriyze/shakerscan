from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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
    planner = (ROOT / "api" / "parallel_scan.py").read_text(encoding="utf-8")
    worker = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    handler = worker[
        worker.index("async def process_scan_plan_job("):
        worker.index("\n\nasync def process_scan_shard_job", worker.index(
            "async def process_scan_plan_job("
        ))
    ]

    for forbidden in (
        "ACTIVE_SCAN_TYPES",
        'get("scan_type")',
        "get('scan_type')",
        'get("check_family")',
        'get("asm_check_family")',
        'get("xss")',
        'get("sqli")',
        "resolve_scan_budget(",
    ):
        assert forbidden not in planner
    assert "parallel planning requires a canonical Scan policy snapshot" in planner
    assert "parallel planning requires a canonical Scan queue payload" in handler
    assert "CanonicalScanJob.from_queue_payload(canonical_source)" in handler
    assert "'scan_generation' or 'legacy'" not in handler
    assert "'v2' if child_job else 'legacy'" not in handler


def test_normal_scheduler_has_no_digestless_queue_fallback():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
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
