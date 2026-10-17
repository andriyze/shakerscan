"""Workflow defaults are read-only and CI tool installs are hash-pinned (code scanning)."""

from __future__ import annotations

from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
WRITE = "write"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def test_every_workflow_defaults_to_read_only_permissions():
    # A top-level write grant reaches every job, including ones added later that never asked
    # for it; jobs that write declare that themselves.
    offenders = []
    for path in WORKFLOWS:
        workflow = _load(path)
        permissions = workflow.get("permissions")
        if permissions is None:
            offenders.append(f"{path.name}: no top-level permissions")
        elif permissions == "write-all" or (
            isinstance(permissions, dict) and WRITE in permissions.values()
        ):
            offenders.append(f"{path.name}: top-level {permissions}")
    assert offenders == []


def test_ci_tool_installs_are_hash_pinned():
    # A version pin still trusts whatever the index serves for that version; --require-hashes
    # with a lock does not.
    loose = []
    for path in WORKFLOWS:
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if not re.search(r"\bpip install\b", line) or line.rstrip().endswith("\\"):
                continue
            if "--require-hashes" in line or re.search(r"(dist/\*\.whl|\.whl)\b", line):
                continue
            loose.append(f"{path.name}:{number}: {line.strip()}")
    assert loose == []


def test_ci_tool_locks_carry_hashes_for_every_requirement():
    locks = sorted((ROOT / ".github" / "requirements").glob("*.lock"))
    assert {lock.name for lock in locks} >= {"pytest.lock", "client-build.lock", "pip-audit.lock"}
    for lock in locks:
        blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", lock.read_text())
        pins = [block for block in blocks if re.match(r"[A-Za-z0-9_.-]+==", block)]
        assert pins, lock.name
        assert all("--hash=sha256:" in block for block in pins), lock.name


# Manually dispatched acceptance workflows check out an operator-supplied SHA with a read-only
# token; the checked-out code never needs that token in .git/config.
CANDIDATE_ACCEPTANCE_WORKFLOWS = (
    "e2e.yml",
    "v2-scan-parity.yml",
    "device-physical-acceptance.yml",
    "model-intake-physical-acceptance.yml",
)


def test_candidate_acceptance_checkouts_do_not_keep_the_token():
    for name in CANDIDATE_ACCEPTANCE_WORKFLOWS:
        workflow = _load(ROOT / ".github" / "workflows" / name)
        assert workflow["permissions"] == {"contents": "read"}, name
        checkouts = [
            step
            for job in workflow["jobs"].values()
            for step in job.get("steps") or []
            if str(step.get("uses") or "").startswith("actions/checkout@")
            and "inputs.candidate_sha" in str((step.get("with") or {}).get("ref") or "")
        ]
        assert checkouts, name
        for step in checkouts:
            assert step["with"].get("persist-credentials") is False, name
