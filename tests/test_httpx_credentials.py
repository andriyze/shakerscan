import base64
import json
import os
import stat

import pytest

import agent_tools
from runtime.httpx_credentials import HttpxCredentialConfiguration
from scanner.redaction import redact_sensitive, redact_text


def test_reflected_identity_values_are_removed_before_export():
    headers = {"Authorization": "Basic " + base64.b64encode(b"fixture-user:fixture-password").decode(),
        "Cookie": "session=fixture-cookie; secondary=other-cookie", "X-Api-Key": "fixture-api-value"}
    values = agent_tools.scanner_credential_redaction_values(headers)
    payload = {"records": [{"title": "fixture-user fixture-password fixture-cookie other-cookie fixture-api-value",
                            "status_code": 200}]}
    safe = redact_sensitive(payload, redact_strings=True, scrub_text=True, known_values=values)
    assert safe["records"][0]["status_code"] == 200
    assert "fixture-" not in json.dumps(safe) and "other-cookie" not in json.dumps(safe)
    assert "fixture-password" not in redact_text("failure: fixture-password", known_values=values)


def test_sealed_configuration_lifetime_and_permissions():
    if not hasattr(os, "memfd_create"):
        with pytest.raises(ValueError, match="unavailable"):
            HttpxCredentialConfiguration(b'{}')
        return
    content = agent_tools.httpx_credential_config_bytes({"Authorization": "Bearer fixture-secret"})
    config = HttpxCredentialConfiguration(content)
    descriptor = config.descriptor
    try:
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600
        assert not os.get_inheritable(descriptor)
        assert "fixture-secret" not in repr(config)
        assert os.read(descriptor, 65_536) == content
        with pytest.raises(OSError):
            os.write(descriptor, b"overwrite")
    finally:
        config.close()
    config.close()
    with pytest.raises(OSError):
        os.fstat(descriptor)



def test_a_short_cookie_value_does_not_rewrite_every_url_in_the_output():
    """A target's own one-character session cookie (``sess=1``) was masked wherever a "1"
    appeared, so the output's URLs read ``http://***0.***0.***0.***03:***8999/`` and the Scan's
    finalization failed on the port. Pieces shorter than MIN_REDACTION_PIECE protect nothing and
    are left alone; real secrets are still masked."""
    headers = {"Cookie": "sess=1; session=fixture-cookie-value"}
    values = agent_tools.scanner_credential_redaction_values(headers)
    assert "1" not in values and "fixture-cookie-value" in values
    payload = {"records": [{"url": "http://10.10.10.103:18999/login", "note": "fixture-cookie-value"}]}
    safe = redact_sensitive(payload, redact_strings=True, scrub_text=True, known_values=values)
    assert safe["records"][0]["url"] == "http://10.10.10.103:18999/login"
    assert "fixture-cookie-value" not in json.dumps(safe)
