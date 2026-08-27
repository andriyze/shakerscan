from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from model_intake_agent import ACTION_CATALOG  # noqa: E402


def test_shipped_skill_routes_admission_away_from_legacy_preflight():
    skill = (ROOT / "skills/shakerscan/SKILL.md").read_text()
    reference = (ROOT / "skills/shakerscan/references/model-intake.md").read_text()

    assert "`POST /model-intake/scan` is always\n  non-deployable technical preflight" in skill
    assert "use the controlled `/model-intake/submissions/*` workflow" in skill
    assert "preflight-only" in reference
    assert "never deployable" in reference


def test_model_intake_skill_covers_the_same_controlled_api_and_planner_catalog():
    reference = (ROOT / "skills/shakerscan/references/model-intake.md").read_text()
    api_source = api_tree_source()
    required_routes = (
        "/model-intake/submissions",
        "/static-runs",
        "/runner-jobs",
        "/agent/session",
        "/agent/sessions",
        "/cancel",
        "/freeze-evidence",
        "/approvals",
        "/policy-decisions",
        "/promote",
        "/report",
        "/model-intake/checks",
    )
    for route in required_routes:
        assert route in reference
        assert route in api_source
    for action in ACTION_CATALOG:
        assert f"`{action}`" in reference
    assert "`run_command`" not in reference
    for report_format in ("json", "html", "sarif"):
        assert f"/report?format={report_format}" in reference
    assert 'pattern="^(json|html|sarif)$"' in api_source


def test_model_intake_skill_preserves_fail_closed_firecracker_and_report_semantics():
    reference = (ROOT / "skills/shakerscan/references/model-intake.md").read_text()

    assert "Do not substitute the container sandbox, QEMU, Docker" in reference
    assert "any outbound IP/DNS attempt" in reference
    assert "Local Unix IPC and socket creation" in reference
    assert "What ShakerScan checks" in reference
    assert "`ALLOW`, `BLOCK`, `INCOMPLETE`, or `REVIEW`" in reference
    assert "Kubernetes is not required" in reference
    assert "conformance fixtures, not a hard-coded allowlist" in reference
    assert "cryptographically reverifies an active DSSE admission" in reference
    assert "current-record mismatch is `BLOCK`" in reference
    assert "printable/PDF source" in reference
    assert "report's `presentation` object" in reference
    assert "Do not mix later admission stages into the technical failure count" in reference
    assert "single **deployment follow-up** appendix" in reference
