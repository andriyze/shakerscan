import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.access_control_checks import determine_severity  # noqa: E402


def test_forced_browsing_debug_dev_metrics_is_high_not_critical():
    assert determine_severity(200, "debug_dev", "/metrics") == "high"


def test_forced_browsing_sensitive_files_and_admin_stay_critical():
    assert determine_severity(200, "sensitive_files", "/.env") == "critical"
    assert determine_severity(200, "admin_panels", "/admin") == "critical"



def test_authz_guard_rejects_id_ignored_endpoint_returning_own_object():
    """Regression: /rest/saveLoginIp-style endpoints ignore the requested id and
    echo the caller's OWN object. The attacker requested owner id=685 but received
    their own object id=686 -> NOT cross-principal access, must not be confirmed BOLA."""
    from scanner_tools.access_control_checks import _resource_ids_from_response
    attacker_body = '{"id":686,"username":"","email":"shaker.fin2@example.com","role":"customer"}'
    returned = _resource_ids_from_response(attacker_body)
    assert "686" in returned
    # The owner object (685) was NOT received -> guard rejects the BOLA claim.
    assert "685" not in returned

    # Positive control: a genuine cross-principal hit returns the owner's object id.
    owner_body = '{"id":685,"email":"shaker.fin1@example.com","role":"customer"}'
    assert "685" in _resource_ids_from_response(owner_body)
