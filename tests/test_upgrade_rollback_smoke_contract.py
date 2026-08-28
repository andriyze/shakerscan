"""The rollback leg must actually be able to boot the previous-stable stack.

`scripts/upgrade_smoke.sh` started the baseline API image with no command. That image carries no
default command -- v0.8.18's compose file supplies `command: ["python3", "/app/api.py"]` -- so the
container exited immediately and the health loop below it could only ever time out. The worker in
the same function already passed its command explicitly; the API did not, so the rollback leg could
never pass and the qualification it represents was unreachable.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "scripts" / "upgrade_smoke.sh"
COMPOSE = ROOT / "docker-compose.yml"


def _source() -> str:
    return SMOKE.read_text(encoding="utf-8")


def test_the_smoke_is_valid_shell():
    subprocess.run(["sh", "-n", str(SMOKE)], check=True)


def test_every_rollback_service_is_started_with_an_explicit_command():
    source = _source()
    start = source.index("run_operational_rollback() {")
    end = source.index("\n}", start)
    body = source[start:end]
    for image_var in ("$BASELINE_API_IMAGE", "$BASELINE_IMAGE"):
        pattern = re.compile(re.escape(f'"{image_var}"') + r"\s+(\S+)")
        match = pattern.search(body)
        assert match, f"{image_var} is not started in the rollback function"
        assert match.group(1) != ">/dev/null", (
            f"{image_var} is started with no command; the image has no default and exits at once"
        )


def test_the_api_command_matches_what_compose_supplies():
    # The smoke must boot the service the way the release actually runs it, or it qualifies a
    # configuration nobody deploys.
    source = _source()
    assert '"$BASELINE_API_IMAGE" python3 /app/api.py' in source
    compose = COMPOSE.read_text(encoding="utf-8")
    assert 'command: ["python3", "/app/api.py"]' in compose


def test_the_health_check_still_requires_both_api_and_ui():
    source = _source()
    assert "curl -sf http://127.0.0.1:8080/health" in source
    assert "curl -sf http://127.0.0.1:3000/" in source


def test_a_failed_rollback_still_fails_the_smoke():
    source = _source()
    assert 'echo "previous-stable API/UI did not become healthy after rollback" >&2' in source
    assert source.count("exit 1") >= 2


# --- The candidate must run on the database it just upgraded ----------------------------------
# Applying candidate migrations through helper code proves the schema moves; it does not prove the
# release runs on it. The smoke booted only the PREVIOUS stack, so an upgrade that migrated cleanly
# and then could not serve would have passed.

def test_the_candidate_stack_boots_against_the_upgraded_database():
    source = _source()
    assert "run_operational_candidate()" in source
    body = source[source.index("run_operational_candidate()"):]
    for image_var in ("$CANDIDATE_API_IMAGE", "$CANDIDATE_UI_IMAGE", "$SCANNER_IMAGE"):
        assert image_var in body[:4000], image_var
    # Against the dirty upgraded database, not a clean one: that is the operator's real case.
    assert "scanner_dirty" in body[:4000]


def test_the_candidate_is_health_checked_on_both_api_and_ui():
    body = _source()[_source().index("run_operational_candidate()"):]
    assert "curl -sf http://127.0.0.1:8080/health" in body[:4000]
    assert "curl -sf http://127.0.0.1:3000/" in body[:4000]
    assert "candidate API/UI did not become healthy" in body[:4000]


def test_pre_upgrade_rows_are_still_served_by_the_candidate():
    body = _source()[_source().index("run_operational_candidate()"):]
    assert "upgrade.example.test" in body[:4000], (
        "a migration that loses historical rows must fail here"
    )


def test_queued_and_leased_redis_work_must_survive_the_upgrade():
    source = _source()
    assert "seed_redis_upgrade_work()" in source
    assert "assert_redis_work_survived()" in source
    body = source[source.index("assert_redis_work_survived()"):]
    # Work may be claimed by the candidate worker, but it must not simply vanish.
    assert "queued work disappeared across the upgrade without being leased" in body[:1500]
    # An existing lease belongs to the worker that took it.
    assert "an existing worker lease was overwritten by the candidate" in body[:1500]


def test_the_candidate_runs_before_the_rollback_leg():
    # Rollback restores a pre-upgrade dump, so the candidate has to be exercised first or it never
    # sees the upgraded state at all.
    source = _source()
    assert source.index("run_operational_candidate\n") < source.index("run_scenario scanner_dirty rollback")


def test_every_candidate_container_is_cleaned_up():
    source = _source()
    cleanup = source[source.index("cleanup() {"):source.index("trap cleanup")]
    for name in ("$CANDIDATE_WORKER_CONTAINER", "$CANDIDATE_UI_CONTAINER",
                 "$CANDIDATE_API_CONTAINER", "$CANDIDATE_REDIS_CONTAINER"):
        assert name in cleanup, name
