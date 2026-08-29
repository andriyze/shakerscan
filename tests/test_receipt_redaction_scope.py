"""The receipt redactor must remove secret values without erasing evidence.

Every capability observation passes through ``redact_receipt_value`` on its way to
durable storage. The rule that decided "is this key a secret" matched on the bare
word parts ``key``, ``api``, ``access`` and ``signature``, so it masked the entire
TLS certificate posture block, the name of the detector that fired, and the storage
key of the observation manifest -- and it replaced ``secret_values_visible: False``
with the truthy ``"***"``, inverting the safety claim that field exists to record.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from runtime.receipts import key_is_sensitive, redact_receipt_value  # noqa: E402

MASK = "***"

# The exact observation a TLS inspection emits for one handshake.
CERTIFICATE_OBSERVATION = {
    "kind": "tls_protocol",
    "certificate_subject": "CN=target.test",
    "certificate_issuer": "CN=Example CA,O=Example,C=US",
    "certificate_signature_algorithm": "1.2.840.113549.1.1.11",
    "certificate_signature_hash": "sha256",
    "certificate_weak_signature": False,
    "certificate_public_key_type": "RSAPublicKey",
    "certificate_public_key_bits": 2048,
    "certificate_weak_public_key": False,
    "certificate_days_remaining": 67,
}


def test_certificate_posture_survives_redaction():
    redacted = redact_receipt_value(dict(CERTIFICATE_OBSERVATION))
    assert redacted == CERTIFICATE_OBSERVATION, "certificate posture is evidence, not a secret"


def test_a_boolean_safety_claim_is_never_masked_into_truth():
    # "***" is truthy: masking `False` here reversed the claim the field records.
    assert redact_receipt_value({"secret_values_visible": False}) == {
        "secret_values_visible": False,
    }


def test_the_detector_that_fired_is_kept():
    assert redact_receipt_value({"matched_signature": "aws_access_key_id"}) == {
        "matched_signature": "aws_access_key_id",
    }


def test_the_observation_storage_key_is_kept():
    key = "scan-observations/6f1c0f6e-0000-4000-8000-000000000001.json"
    assert redact_receipt_value({"object_key": key}) == {"object_key": key}


def test_only_the_valid_cors_credentials_policy_value_is_preserved():
    key = "Access-Control-Allow-Credentials"
    assert redact_receipt_value({key: "true"}) == {key: "true"}
    assert redact_receipt_value({key: "TRUE"}) == {key: "TRUE"}
    assert redact_receipt_value({key: "Bearer reflected-secret"}) == {key: MASK}
    assert redact_receipt_value({key: "arbitrary-target-value"}) == {key: MASK}


SECRET_KEYS = (
    "authorization", "api_key", "apikey", "x-api-key", "private_key", "ssh_private_key",
    "signing_key", "access_key", "access_key_id", "aws_access_key_id", "access_token",
    "refresh_token", "session_token", "sessionToken", "client_secret", "secret",
    "password", "passwd", "password_hash", "cookie", "set-cookie", "bearer_token",
    "credential", "credentials", "auth_header", "signature", "key",
)


def test_every_secret_shaped_key_is_still_masked():
    for name in SECRET_KEYS:
        assert key_is_sensitive(name, item="value-that-must-not-persist"), name
        assert redact_receipt_value({name: "s3cret"})[name] == MASK, name


def test_a_nested_secret_is_masked_at_any_depth():
    payload = {"request": {"headers": {"Authorization": "Bearer abc"}, "path": "/a"}}
    redacted = redact_receipt_value(payload)
    assert redacted["request"]["headers"]["Authorization"] == MASK
    assert redacted["request"]["path"] == "/a"


def test_a_secret_string_is_masked_even_under_a_descriptor_name():
    # The descriptor exemption must not become a way to smuggle a secret out: a
    # strongly-named key holding a string is masked whatever its suffix.
    assert redact_receipt_value({"password_hash": "$2b$12$abcdef"})["password_hash"] == MASK


def test_the_descriptor_exemption_is_deliberately_narrow():
    """Numbers lost their free pass under a strongly-named key.

    They used to get one, and the same rule exempted `observed_access_key`, which stored
    an AWS key in the clear. Masking a length loses information; not masking a credential
    loses the secret, so the ambiguous case now resolves toward masking. A name that
    qualifies nothing -- `certificate_public_key_bits` -- is still kept, because "public"
    is not a credential qualifier.
    """
    assert key_is_sensitive("certificate_public_key_bits", item=2048) is False
    assert key_is_sensitive("secret_length", item=32) is True
    assert key_is_sensitive("secret_length", item="32-chars-of-actual-material") is True


def test_empty_values_are_left_alone_rather_than_masked():
    assert redact_receipt_value({"password": ""}) == {"password": ""}
    assert redact_receipt_value({"token": None}) == {"token": None}


# A descriptor marker must never outrank the qualifier that identifies a credential.
# With the checks in the wrong order these were stored in the clear: the leading
# adjective exempted the key before anything looked at "access" or "api".
ADJECTIVE_PREFIXED_SECRETS = (
    "observed_access_key", "matched_api_key", "expected_private_key",
    "weak_api_key", "observed_client_secret", "matched_bearer_token",
    "matched_session_key", "observed_password", "expected_secret",
)


def test_a_descriptor_prefix_does_not_exempt_a_credential():
    for name in ADJECTIVE_PREFIXED_SECRETS:
        assert key_is_sensitive(name, item="AKIAEXAMPLE"), name
        assert redact_receipt_value({name: "AKIAEXAMPLE"})[name] == MASK, name


def test_a_descriptor_prefix_still_exempts_a_fact_about_a_secret():
    # The exemption exists for these and must keep working.
    assert redact_receipt_value({"matched_signature": "rule-name"}) == {
        "matched_signature": "rule-name",
    }
    assert redact_receipt_value({"certificate_weak_signature": False}) == {
        "certificate_weak_signature": False,
    }
    assert redact_receipt_value({"secret_values_visible": False}) == {
        "secret_values_visible": False,
    }


def test_only_a_bool_gets_the_descriptor_exemption_over_a_secret_name():
    """A number under a credential name is not automatically a fact about it."""
    assert key_is_sensitive("observed_access_key", item=1234) is True
    assert key_is_sensitive("secret_values_visible", item=False) is False
