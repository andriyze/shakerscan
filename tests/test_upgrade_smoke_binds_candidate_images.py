"""The upgrade smoke must qualify the images the release actually ships.

`scripts/upgrade_smoke.sh` took only `SCANNER_IMAGE` from the release workflow and fell
back to the bare names `shakerscan-api` / `shakerscan-ui` -- which Docker resolves to
`:latest`, i.e. whatever happens to sit on the host. Worse, the workflow built the
candidate UI image *after* invoking the smoke, so on a clean runner that image did not
exist at all. Either way the step could pass while testing something other than the
candidate.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "scripts" / "upgrade_smoke.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "release-candidate.yml"

CANDIDATE_VARS = ("SCANNER_IMAGE", "CANDIDATE_API_IMAGE", "CANDIDATE_UI_IMAGE")


def test_no_candidate_default_resolves_to_latest():
    source = SMOKE.read_text(encoding="utf-8")
    for name in ("CANDIDATE_API_IMAGE", "CANDIDATE_UI_IMAGE", "SCANNER_IMAGE"):
        match = re.search(rf'^{name}="\$\{{{name}:-([^}}"]+)\}}"', source, re.MULTILINE)
        assert match, f"{name} has no defaulted assignment"
        default = match.group(1)
        assert ":" in default or "@" in default, (
            f"{name} defaults to the untagged {default!r}, which Docker resolves to :latest"
        )


def test_the_smoke_refuses_to_run_without_the_candidate_images():
    source = SMOKE.read_text(encoding="utf-8")
    assert "docker image inspect" in source
    for name in CANDIDATE_VARS:
        assert f'"${name}"' in source, f"{name} is never checked for presence"
    # The guard must exit rather than warn.
    guard = source[source.index("candidate image is not built locally") :]
    assert "exit 1" in guard[:600]


def test_the_release_workflow_names_every_candidate_image():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    invocation = re.search(
        r"- name: Verify clean and dirty schema upgrades\n(?:.*\n)*?(?=\n      - name: )",
        workflow,
    )
    assert invocation, "the upgrade smoke step was renamed or removed"
    step = invocation.group(0)
    for name in CANDIDATE_VARS:
        assert f"{name}=" in step, f"the smoke step does not bind {name}"
        assert "release-candidate" in step
    assert "shakerscan-ui:release-candidate" in step


def test_the_candidate_ui_image_is_built_before_the_smoke_runs():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    built = workflow.index("-t shakerscan-ui:release-candidate")
    smoked = workflow.index("- name: Verify clean and dirty schema upgrades")
    assert built < smoked, (
        "the smoke runs before the candidate UI image exists, so it can only test "
        "some other image or fail on a clean runner"
    )
