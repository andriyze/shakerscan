"""Pull-request CI pulls from Docker Hub with a read-only login, never with the release secrets.

Anonymous Docker Hub pulls are rate limited per runner IP, and smoke shards, PostgreSQL service
jobs and metadata jobs failed with 429 toomanyrequests. PR jobs that pull therefore log in with
DOCKERHUB_READ_USERNAME / DOCKERHUB_READ_TOKEN (a "Public Repo Read-only" access token). The
login is a no-op when those secrets are absent, as for forks and Dependabot, so such runs pull
anonymously exactly as before. The release push secrets DOCKERHUB_USERNAME / DOCKERHUB_TOKEN must
never reach a pull-request path.

Job `services:` are pulled before any step runs, so they carry `credentials:` instead of a login
step; the runner skips the registry login when either credential is empty
(actions/runner ContainerOperationProvider.ContainerRegistryLogin).
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
LOGIN_ACTION = "docker/login-action@dbcb813823bdd20940b903addbd779551569679f"
HAS_DH_READ = "${{ secrets.DOCKERHUB_READ_USERNAME != '' && secrets.DOCKERHUB_READ_TOKEN != '' }}"
READ_CREDENTIALS = {
    "username": "${{ secrets.DOCKERHUB_READ_USERNAME }}",
    "password": "${{ secrets.DOCKERHUB_READ_TOKEN }}",
}
RELEASE_SECRET = re.compile(r"\bDOCKERHUB_(USERNAME|TOKEN)\b")
PR_EVENTS = {"pull_request", "pull_request_target", "merge_group"}

# (workflow, job, predicate for the first step that pulls from Docker Hub)
STEP_PULLERS = [
    ("authenticated-assurance.yml", "acceptance", lambda s: "docker run" in s.get("run", "")),
    ("e2e-pr.yml", "smoke-shard", lambda s: "docker/bake-action" in s.get("uses", "")
     or "scanner.sh" in s.get("run", "")),
    ("installed-upgrade.yml", "installed-upgrade", lambda s: "installed_upgrade_smoke.sh" in s.get("run", "")),
    ("postgres-upgrade.yml", "postgres-upgrade-smoke", lambda s: "postgres_upgrade_smoke.sh" in s.get("run", "")),
    ("release-sbom.yml", "registry-smoke", lambda s: "docker/setup-buildx-action" in s.get("uses", "")),
    ("verify-rc-native-tools.yml", "verify", lambda s: "docker/setup-buildx-action" in s.get("uses", "")),
]


def _load(path):
    doc = yaml.safe_load(path.read_text())
    # PyYAML reads the bare `on:` key as boolean True.
    return doc, doc.get("on", doc.get(True)) or {}


def _pr_workflows():
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        doc, triggers = _load(path)
        events = set(triggers) if isinstance(triggers, dict) else set(triggers if isinstance(triggers, list) else [triggers])
        if events & PR_EVENTS:
            found.append((path, doc))
    return found


def _is_login(step):
    return step.get("uses", "").startswith("docker/login-action@")


def test_pr_workflows_are_found():
    names = {path.name for path, _ in _pr_workflows()}
    assert {name for name, _, _ in STEP_PULLERS} <= names
    assert {"data-lifecycle.yml", "maintenance-regressions.yml", "hunt-ssh-acceptance.yml"} <= names


def test_pr_workflows_never_reference_the_release_docker_hub_secrets():
    for path, doc in _pr_workflows():
        text = path.read_text()
        assert not RELEASE_SECRET.search(text), path.name
        # A reusable workflow called from a PR path must not receive every secret either.
        for name, job in doc["jobs"].items():
            assert job.get("secrets") != "inherit", (path.name, name)


def test_every_pr_docker_hub_login_is_read_only_and_guarded():
    for path, doc in _pr_workflows():
        for name, job in doc["jobs"].items():
            for step in job.get("steps", []):
                if not _is_login(step):
                    continue
                assert step["uses"] == LOGIN_ACTION, (path.name, name)
                assert step["with"] == READ_CREDENTIALS, (path.name, name)
                assert step["if"].startswith("env.HAS_DH_READ == 'true'"), (path.name, name)
                assert job["env"]["HAS_DH_READ"] == HAS_DH_READ, (path.name, name)


@pytest.mark.parametrize("workflow,job_name,pulls", STEP_PULLERS)
def test_step_pulls_follow_the_read_login(workflow, job_name, pulls):
    _, doc = next((p, d) for p, d in _pr_workflows() if p.name == workflow)
    steps = doc["jobs"][job_name]["steps"]
    logins = [i for i, step in enumerate(steps) if _is_login(step)]
    first_pull = next(i for i, step in enumerate(steps) if pulls(step))
    assert len(logins) == 1 and logins[0] < first_pull, (workflow, job_name)


def test_pr_service_containers_pull_with_read_credentials():
    services = 0
    for path, doc in _pr_workflows():
        for name, job in doc["jobs"].items():
            for service_name, service in (job.get("services") or {}).items():
                services += 1
                assert service.get("credentials") == READ_CREDENTIALS, (path.name, name, service_name)
            assert "container" not in job, (path.name, name)
    assert services >= 10
