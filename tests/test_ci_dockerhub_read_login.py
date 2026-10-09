"""Pull-request CI pulls from Docker Hub with a read-only login, never with the release secrets.

Anonymous Docker Hub pulls are rate limited per runner IP, and smoke shards, PostgreSQL service
jobs and metadata jobs failed with 429 toomanyrequests. PR jobs that pull therefore log in with
DOCKERHUB_READ_USERNAME / DOCKERHUB_READ_TOKEN (a "Public Repo Read-only" access token). The
login is a no-op when those secrets are absent, as for forks and Dependabot, so such runs pull
anonymously exactly as before. The release push secrets DOCKERHUB_USERNAME / DOCKERHUB_TOKEN must
never reach a pull-request path.

Job `services:` are pulled before any step runs, so a login step cannot cover them. Service
`credentials:` were tried and refused: with the secrets absent GitHub rejects the template
("Unexpected value ''") and the job fails at "Set up job". Services therefore pull Docker Hub's
official images through Google's pull-through mirror, mirror.gcr.io/library/<image>:<same tag>,
which served the same index digests as Docker Hub for every tag when this was introduced.

Jobs that pull in steps also route Docker Hub through that mirror, so they pass before the read
token exists: .github/actions/docker-hub-mirror adds mirror.gcr.io to the daemon's
registry-mirrors (dockerd falls back to Docker Hub itself), and every docker-container builder
from docker/setup-buildx-action gets the same mirror in its buildkitd config, which BuildKit and
`buildx imagetools` read. The read-only login stays for anything the mirror cannot serve.

The hosted runner image ships a docker.io login ("githubactions"). dockerd reuses docker.io
credentials for docker.io mirrors, mirror.gcr.io rejects them with 401, and dockerd then falls
back to Docker Hub (seen on PR #380), so the mirror action logs that out first. The read-only
login runs after it. CI-only commands name the mirror directly: the disposable PostgreSQL 16
fixture, the buildx builder image and the digest-pinned Go builder of the native-tools build.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
MIRROR_ACTION = "./.github/actions/docker-hub-mirror"
BUILDKIT_MIRROR = '[registry."docker.io"]\n  mirrors = ["mirror.gcr.io"]\n'
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


@pytest.mark.parametrize("workflow,job_name,pulls", STEP_PULLERS)
def test_step_pulls_go_through_the_mirror(workflow, job_name, pulls):
    _, doc = next((p, d) for p, d in _pr_workflows() if p.name == workflow)
    steps = doc["jobs"][job_name]["steps"]
    mirrors = [i for i, step in enumerate(steps) if step.get("uses") == MIRROR_ACTION]
    first_pull = next(i for i, step in enumerate(steps) if pulls(step))
    assert len(mirrors) == 1 and mirrors[0] < first_pull, (workflow, job_name)
    # The mirror action logs out of docker.io; the read-only login must come after it.
    login = next(i for i, step in enumerate(steps) if _is_login(step))
    assert mirrors[0] < login, (workflow, job_name)
    # A failed pull leaves dockerd's endpoint fallbacks in the job log.
    diagnostics = [step for step in steps if step.get("name") == "Show Docker daemon registry fallbacks"]
    assert len(diagnostics) == 1 and diagnostics[0]["if"] == "failure()", (workflow, job_name)
    assert "journalctl -u docker" in diagnostics[0]["run"], (workflow, job_name)
    # The daemon restart must not race a step that already uses Docker.
    assert not any("docker" in step.get("run", "") for step in steps[:mirrors[0]]), (workflow, job_name)
    if any("docker/setup-buildx-action" in step.get("uses", "") for step in steps):
        buildx = next(i for i, step in enumerate(steps) if "docker/setup-buildx-action" in step.get("uses", ""))
        assert mirrors[0] < buildx, (workflow, job_name)


def test_every_pr_buildx_builder_uses_the_mirror():
    builders = 0
    for path, doc in _pr_workflows():
        for name, job in doc["jobs"].items():
            for step in job.get("steps", []):
                if step.get("uses", "").startswith("docker/setup-buildx-action@"):
                    builders += 1
                    assert re.fullmatch(r"docker/setup-buildx-action@[0-9a-f]{40}", step["uses"]), (path.name, name)
                    assert step["with"]["buildkitd-config-inline"] == BUILDKIT_MIRROR, (path.name, name)
                    assert step["with"]["driver-opts"] == "image=mirror.gcr.io/moby/buildkit:buildx-stable-1", (path.name, name)
    assert builders == 2


def test_mirror_action_merges_the_daemon_config_and_waits_for_it():
    action = yaml.safe_load((ROOT / ".github/actions/docker-hub-mirror/action.yml").read_text())
    run = "\n".join(step["run"] for step in action["runs"]["steps"])
    # Merges with the runner's existing daemon.json rather than replacing it.
    assert 'current="$(sudo cat "$config")"' in run
    assert '."registry-mirrors" = ((."registry-mirrors" // []) + ["https://mirror.gcr.io"] | unique)' in run
    assert "sudo systemctl restart docker" in run
    # The runner's docker.io login is removed so dockerd does not send it to the mirror (401),
    # and only key names of the client config are printed, never values.
    assert "docker logout" in run
    assert run.index("docker logout") < run.index("sudo systemctl restart docker")
    assert "jq -c '{auths: ((.auths // {}) | keys), credsStore, credHelpers}'" in run
    logout_step = action["runs"]["steps"][0]["run"]
    assert "docker logout" in logout_step and 'cat "$config"' not in logout_step
    # Fails loudly if the daemon did not pick the mirror up, instead of silently pulling anonymously.
    assert "RegistryConfig.Mirrors" in run and "exit 1" in run


def test_smoke_containerd_switch_keeps_the_mirror():
    _, doc = next((p, d) for p, d in _pr_workflows() if p.name == "e2e-pr.yml")
    steps = doc["jobs"]["smoke-shard"]["steps"]
    switch = next(step for step in steps if step.get("name", "").startswith("Use the containerd image store"))
    # It edits the same daemon.json after the mirror step, so it must merge, not overwrite.
    assert "jq '.features = ((.features // {})" in switch["run"] and 'current="$(sudo cat "$config")"' in switch["run"]


def test_pr_service_containers_pull_through_the_mirror_without_credentials():
    services = 0
    for path, doc in _pr_workflows():
        for name, job in doc["jobs"].items():
            for service_name, service in (job.get("services") or {}).items():
                services += 1
                where = (path.name, name, service_name)
                # Same official image and tag, not Docker Hub's anonymous rate limit.
                assert re.fullmatch(r"mirror\.gcr\.io/library/(postgres|redis):[\w.-]+", service["image"]), where
                # Empty credentials (no secrets, forks, Dependabot) make the job template invalid.
                assert "credentials" not in service, where
            assert "container" not in job, (path.name, name)
    assert services >= 11


def test_ci_only_commands_name_the_mirror_directly():
    docs = {p.name: d for p, d in _pr_workflows()}
    fixture = next(step for step in docs["authenticated-assurance.yml"]["jobs"]["acceptance"]["steps"]
                   if step.get("name") == "Start explicitly disposable restore fixture")
    assert "shakerscan_assurance_test mirror.gcr.io/library/postgres:16\n" in fixture["run"]
    build = next(step for step in docs["verify-rc-native-tools.yml"]["jobs"]["verify"]["steps"]
                 if step.get("name") == "Build and verify patched native scanners")
    assert "sed -n 's/^ARG MODEL_INTAKE_GO_BUILDER=//p' scanner/Dockerfile.model-intake" in build["run"]
    assert '--build-arg "MODEL_INTAKE_GO_BUILDER=mirror.gcr.io/library/$builder"' in build["run"]
    # The mirrored builder stays the Dockerfile's digest-pinned official image.
    dockerfile = (ROOT / "scanner/Dockerfile.model-intake").read_text()
    builder = re.search(r"^ARG MODEL_INTAKE_GO_BUILDER=(\S+)$", dockerfile, re.MULTILINE).group(1)
    assert re.fullmatch(r"[a-z0-9._-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}", builder)
