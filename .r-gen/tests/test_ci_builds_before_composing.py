"""A workflow that composes this stack must build the scanner runtime first.

The API image copies FROM `shakerscan-worker:local`. That is a Dockerfile stage, not a
compose dependency, so `docker compose up --build` does not build it -- on a clean runner
it tries to PULL it and fails with "pull access denied, repository does not exist". The
E2E release gate died there before running a single check, and the failure looks like a
registry permissions problem rather than a build-order one.

`scanner.sh build` builds the shared runtime once, then derives the sandbox and slim API
images from that exact content-addressed source.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _runnable(text):
    """Drop comment lines: prose describing the defect is not the defect."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def _composing_workflows():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = _runnable(path.read_text(encoding="utf-8"))
        if re.search(r"docker compose[^\n]*\bup\b", text):
            yield path, text


def test_the_api_image_still_derives_from_the_worker_image():
    """If this stops being true, the rule below is no longer needed."""
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "SCANNER_RUNTIME_IMAGE" in compose
    assert "shakerscan-worker:local" in compose


def test_every_composing_workflow_builds_the_runtime_first():
    offenders = []
    for path, text in _composing_workflows():
        build = text.find("scanner.sh build")
        up = re.search(r"docker compose[^\n]*\bup\b", text)
        if up is None:
            continue
        if build == -1 or build > up.start():
            offenders.append(path.name)
    assert not offenders, (
        "these workflows compose the stack without building the scanner runtime first, "
        f"so a clean runner cannot resolve shakerscan-worker:local: {offenders}"
    )


def test_no_composing_workflow_relies_on_compose_to_build_the_api():
    """`up --build` is the exact form that produced the pull failure."""
    offenders = [
        path.name for path, text in _composing_workflows()
        if re.search(r"docker compose[^\n]*\bup\b[^\n]*--build", text)
    ]
    assert not offenders, (
        f"`docker compose up --build` cannot build this stack from scratch: {offenders}"
    )
