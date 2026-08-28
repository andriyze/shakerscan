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


def test_the_candidate_boots_on_the_upgraded_database_before_the_baseline_is_restored():
    """The rollback leg could not pass while a healthy candidate existed.

    The pre-upgrade dump was restored BEFORE the candidate stack booted, so the candidate
    ran against the baseline schema, re-applied its V2 migrations, and the rollback
    assertions that follow -- which require the V2 tables and migration markers to be
    absent -- were then guaranteed to fail. A successful boot broke the next check by
    construction. The restore belongs between the two.
    """
    source = SMOKE.read_text(encoding="utf-8")
    boot = source.index("run_operational_candidate\n")
    restore = source.index("pg_restore", boot)
    rollback = source.index("run_scenario scanner_dirty rollback")
    assert boot < restore < rollback, (
        "the pre-upgrade restore must happen after the candidate proves it serves the "
        "upgraded database and before the rollback assertions require the baseline schema"
    )


def test_the_upgraded_database_is_verified_before_the_candidate_boots():
    source = SMOKE.read_text(encoding="utf-8")
    verify = source.index("run_scenario scanner_dirty verify_dirty")
    boot = source.index("run_operational_candidate\n")
    assert verify < boot
