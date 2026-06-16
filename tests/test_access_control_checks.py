import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.access_control_checks import determine_severity  # noqa: E402


def test_forced_browsing_debug_dev_metrics_is_high_not_critical():
    assert determine_severity(200, "debug_dev", "/metrics") == "high"


def test_forced_browsing_sensitive_files_and_admin_stay_critical():
    assert determine_severity(200, "sensitive_files", "/.env") == "critical"
    assert determine_severity(200, "admin_panels", "/admin") == "critical"

