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
