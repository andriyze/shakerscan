import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import honey_calibration  # noqa: E402
sys.path.pop(0)


def test_scanner_reachable_url_rewrites_localhost_for_container():
    rewritten = honey_calibration.scanner_reachable_url(
        "http://localhost:18080/path?x=1",
        "http://host.docker.internal:18080",
        "run-1",
        "scenario-1",
    )

    assert rewritten.startswith("http://host.docker.internal:18080/path?")
    assert "calibration_run=run-1" in rewritten
    assert "calibration_scenario=scenario-1" in rewritten


def test_scanner_reachable_url_keeps_external_honey_target():
    url = "https://honey.shakerscan.com/"

    assert honey_calibration.scanner_reachable_url(url, "http://host.docker.internal:18080", "run-1") == url
