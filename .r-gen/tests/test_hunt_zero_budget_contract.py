from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from hunt.start_contract import (
    HUNT_BUDGET_SCHEMA,
    HuntStartPolicy,
    hunt_start_public_contract,
)


def test_server_contract_publishes_dimension_specific_minimums():
    contract = hunt_start_public_contract()
    dimensions = {item["name"]: item for item in contract["budget_dimensions"]}

    assert contract["budget_schema_version"] == HUNT_BUDGET_SCHEMA
    assert dimensions["max_state_changing_requests"]["minimum"] == 0
    assert dimensions["max_browser_actions"]["minimum"] == 0
    assert dimensions["max_tcp_ports"]["minimum"] == 0
    assert dimensions["max_udp_ports"]["minimum"] == 0
    assert dimensions["max_hosts"]["minimum"] == 0
    assert dimensions["max_oob_interactions"]["minimum"] == 0
    assert dimensions["max_device_fragility_points"]["minimum"] == 0
    assert dimensions["max_active_actions"]["minimum"] == 0
    assert dimensions["max_duration_seconds"]["minimum"] == 1
    assert dimensions["max_capability_calls"]["minimum"] == 1


def test_one_hunt_policy_model_is_canonical():
    contracts = (ROOT / "api" / "hunt" / "contracts.py").read_text()
    assert "class HuntPolicy" not in contracts
    assert "resolve_hunt_policy" not in contracts
    assert HuntStartPolicy.__module__.endswith("hunt.start_contract")


def test_api_ui_contract_generation_and_migration_defaults_stay_in_sync():
    completed = subprocess.run(
        [sys.executable, "scripts/generate_hunt_contract.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    router = (ROOT / "api" / "hunt" / "run_router.py").read_text()
    migration = (ROOT / "api" / "retest_contract.py").read_text()
    initial_schema = (ROOT / "db" / "init.sql").read_text()
    hunt_table = initial_schema[initial_schema.index("CREATE TABLE hunt_runs ("):]
    hunt_table = hunt_table[:hunt_table.index("CREATE INDEX idx_hunt_runs_web")]
    assert '@router.get("/hunts/contract", tags=["Hunt"])' in router
    assert "allow_oob_interactions: bool = False" in router
    assert "hunt_start_public_contract()" in router
    assert "'{allow_oob_interactions}'" in migration
    assert "'false'::jsonb" in migration
    assert "policy_json JSONB NOT NULL DEFAULT " \
        "'{\"allow_oob_interactions\":false}'::jsonb" in hunt_table
