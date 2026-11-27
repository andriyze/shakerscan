"""A recorded key or cookie NAME is evidence, not a secret.

Unit fixtures modelled on recorded scan evidence: a session cookie named ``sessionid`` was stored
as ``cookie_name: "***"`` (the page then printed ``grep -i '^set-cookie: ***='``), and a served
settings file's ``SECRET_KEY`` was stored as ``field: "***"`` and listed as ``*** keys: ***``,
because the receipt redactor read the names as secret values.
"""

from __future__ import annotations

import pytest

from api.capabilities.exposure_probe import classify_exposure, redacted_exposure_excerpt
from api.runtime import receipts
from api.runtime.v2_runtime_hardening import _redact_receipt_value as hardened_redact

SETTINGS_PY = (
    b"DEBUG = True\nSECRET_KEY = 'django-insecure-zq8!m3l#t6v9x2a5c1e4g7j0k'\n"
    b"DATABASES = {'default': {'PASSWORD': 'Zr7#qLm2!vXp9Tn4'}}\n"
)
PROVIDER_KEY = "AKIA" + "ZOOFIXTUREVALUE1"  # split: a synthetic fixture, not a real key
REDACTORS = [receipts.redact_receipt_value, hardened_redact]


@pytest.mark.parametrize("redact", REDACTORS)
def test_a_cookie_name_survives_and_a_cookie_value_does_not(redact):
    assert redact({"cookie_name": "sessionid"}) == {"cookie_name": "sessionid"}
    assert redact({"cookie_name": "token_session"}) == {"cookie_name": "token_session"}
    # Not a cookie name: whitespace or "=" means a value or a header line reached the key.
    assert redact({"cookie_name": "sessionid=abc123"}) == {"cookie_name": "***"}
    assert redact({"cookie_name": "Bearer abc"}) == {"cookie_name": "***"}
    assert redact({"cookie": "sessionid"}) == {"cookie": "***"}


@pytest.mark.parametrize("redact", REDACTORS)
def test_a_fingerprinted_field_name_survives_but_a_provider_secret_never_does(redact):
    out = redact({"exposure_fingerprints": [{"field": "SECRET_KEY"}, {"field": "token_url"},
                                            {"field": PROVIDER_KEY}]})
    fields = [entry["field"] for entry in out["exposure_fingerprints"]]
    assert fields[:2] == ["SECRET_KEY", "token_url"]
    assert PROVIDER_KEY not in repr(out)
    # Prose under the same key is still read as prose.
    assert "secret-abc123" not in repr(redact({"field": "see secret-abc123 here"}))


@pytest.mark.parametrize("redact", REDACTORS)
def test_the_withheld_notice_keeps_the_key_names_it_lists(redact):
    signature = classify_exposure(path="/settings.py", status=200,
                                  headers={"Content-Type": "text/x-python"}, body=SETTINGS_PY)
    assert signature is not None
    observation = {"redacted_excerpt": redacted_exposure_excerpt(SETTINGS_PY, signature),
                   "exposure_fingerprints": signature.secret_evidence()}
    stored = redact(observation)
    assert "***" not in stored["redacted_excerpt"], stored["redacted_excerpt"]
    assert "SECRET_KEY" in stored["redacted_excerpt"]
    assert "SECRET_KEY" in [entry["field"] for entry in stored["exposure_fingerprints"]]
    assert "django-insecure" not in repr(stored) and "Zr7#qLm2" not in repr(stored)


@pytest.mark.parametrize("redact", REDACTORS)
def test_a_provider_secret_in_the_notice_is_still_masked(redact):
    notice = ("[configuration_secret_file detected - content withheld; 1 secret value(s) fingerprinted; "
              f"keys named as secrets: SECRET_KEY, {PROVIDER_KEY}]")
    stored = redact({"redacted_excerpt": notice})["redacted_excerpt"]
    assert "SECRET_KEY" in stored and PROVIDER_KEY not in stored
