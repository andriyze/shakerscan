"""PR checks do not depend on the runner's Ubuntu mirror, and a slow image build is visible.

On 2026-10-07 GitHub's Ubuntu mirror stopped answering and its fallback crawled. Browser jobs
spent their whole timeout in `playwright install --with-deps`, which only re-fetches fonts and a
mesa update the runner image does not strictly need: Chromium's libraries are already installed
and the browser itself comes from Playwright's CDN. Two smoke shards were cancelled at the job
limit inside a build whose log was only printed after it finished, so the time left no trace.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
# The release candidate certifies an exact source with its full browser toolchain.
UNCHANGED = {"release-candidate.yml"}


def test_pr_browser_jobs_install_chromium_without_system_packages():
    installs = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        if path.name in UNCHANGED:
            continue
        installs += [(path.name, line.strip()) for line in path.read_text().splitlines()
                     if "playwright install" in line]
    assert {name for name, _ in installs} >= {
        "browser-login-qa.yml", "data-lifecycle.yml", "e2e-pr.yml", "e2e.yml",
        "hunt-aisvs-regressions.yml", "maintenance-regressions.yml", "python-suite.yml",
        "v2-contracts.yml",
    }
    for name, command in installs:
        assert "--with-deps" not in command, (name, command)
        assert command.endswith("playwright install chromium"), (name, command)


def _smoke_steps():
    jobs = yaml.safe_load((WORKFLOWS / "e2e-pr.yml").read_text())["jobs"]
    return jobs["smoke-shard"]["steps"]


def test_smoke_build_streams_its_log_and_fails_before_the_job_limit():
    steps = _smoke_steps()
    build = next(step for step in steps if step.get("name") == "Build ShakerScan images")
    run = build["run"]
    # The log is streamed while the background build runs, not printed only at the end.
    assert 'tail -n +1 -f "$log" &' in run
    # A bound below the job timeout fails with the build's last output.
    assert "35 * 60" in run and "did not finish within 35 minutes" in run
    assert 'tail -n 200 "$log"' in run and "exit 1" in run
    # The build's own exit status still decides the step.
    assert 'exit "$status"' in run


def test_smoke_build_log_is_kept_even_when_the_shard_is_cancelled():
    steps = _smoke_steps()
    upload = next(step for step in steps
                  if step.get("name", "").startswith("Upload this shard's E2E scorecard"))
    assert upload["if"].startswith("always()")
    assert "${{ runner.temp }}/scanner-build.log" in upload["with"]["path"]
