from pathlib import Path


def test_pending_retest_keeps_last_terminal_verdict_visible_without_reusing_its_mode():
    source = (
        Path(__file__).resolve().parents[1] / "api" / "finding_routes" / "router.py"
    ).read_text(encoding="utf-8")

    assert "COALESCE(latest_retest.verdict, f.last_verification_verdict) AS latest_retest_verdict" in source
    assert "CASE WHEN latest_retest.verdict IS NOT NULL THEN latest_retest.verification_mode END AS latest_retest_mode" in source
