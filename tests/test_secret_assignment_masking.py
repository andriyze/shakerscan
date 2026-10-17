"""A ``NAME=value`` assignment keeps its name and loses its whole value; a ``secret://`` reference
survives the free-text redactor (B18: an exposed ``.env`` read as ``***`` for ``SECRET_KEY`` and the
rest of the value after its first ``%`` stayed in clear)."""

from __future__ import annotations

import time

import pytest

from api.runtime.archive_body_masking import mask_credential_shaped
from scanner.redaction import redact_text

# A Django-style key: its token run ends at ``%``, the tail after it is still secret.
DJANGO_KEY = "django-insecure-%*)bdp=m(@)q%=uyxe5xlnz*x0rg8qd&z+%u95)e2fhb2vu"
API_KEY = "Qx7rT2mV9pL4wZ8sK3nB6yH1cF5gJ0dA"
REFERENCE = "secret://0b6c4d55-7d0e-4a8e-9a43-1f0e5b7a9c21"


def test_an_env_assignment_keeps_its_name_and_withholds_the_whole_value():
    text = f"SECRET_KEY={DJANGO_KEY}\nAI_API_KEY={API_KEY}\nAPP_ENV=prod\n"
    masked = mask_credential_shaped(text)
    assert "SECRET_KEY=" in masked and "AI_API_KEY=" in masked and "APP_ENV=prod" in masked
    for piece in ("uyxe5xlnz", "x0rg8qd", "e2fhb2vu", API_KEY):
        assert piece not in masked


def test_a_query_value_ends_at_the_next_parameter():
    masked = mask_credential_shaped(f"https://app.test/cb?page=2&token={API_KEY}&lang=en")
    assert "page=2" in masked and "&lang=en" in masked and "token=" in masked
    assert API_KEY not in masked


def test_a_url_value_keeps_its_name_and_scheme_and_loses_the_credential():
    masked = mask_credential_shaped(f"CALLBACK=https://app.test/{API_KEY}/done")
    assert masked.startswith("CALLBACK=https:")
    assert API_KEY not in masked


def test_plain_words_and_names_are_left_alone():
    text = "MODE=production LEVEL=info a=b"
    assert mask_credential_shaped(text) == text


def test_assignment_masking_stays_linear_on_hostile_input():
    started = time.monotonic()
    mask_credential_shaped("A=" * 50_000)
    mask_credential_shaped(("x" * 20 + "=") * 20_000)
    assert time.monotonic() - started < 5


def test_a_secret_reference_survives_the_free_text_redactor():
    text = f"value kept as [{REFERENCE}]; secret: hunter2hunter2"
    redacted = redact_text(text)
    assert REFERENCE in redacted
    assert "hunter2hunter2" not in redacted


def test_a_reference_shaped_value_is_not_a_way_around_masking():
    # Only the exact reference grammar is held back; anything longer is masked as before.
    assert "and-more" not in redact_text(f"secret: {REFERENCE}x-and-more")
    assert "hunter2hunter2" not in redact_text(f"{REFERENCE} password=hunter2hunter2")


# Review sweep M2: a reference shields nothing joined to it.
@pytest.mark.parametrize("tail", [".hunter2Pass", ":S3cretValue123", "/sk_" + "live_" + "abcdefghijklmnop1234"])
def test_a_value_joined_to_a_reference_is_masked_and_the_reference_kept(tail):
    redacted = redact_text(f"stored as {REFERENCE}{tail} today")
    assert tail.lstrip(".:/") not in redacted
    assert REFERENCE in redacted and redacted.endswith(" today")


@pytest.mark.parametrize("text", [
    f"see {REFERENCE}.", f"({REFERENCE})", f'{{"ref": "{REFERENCE}"}}', f"[{REFERENCE}];", REFERENCE,
    f"'{REFERENCE}'", f"{REFERENCE}, then {REFERENCE}!",
])
def test_a_reference_that_ends_stays_readable(text):
    assert redact_text(text) == text


# Synthetic, format-only values, assembled at run time so no literal in the source looks like a
# live credential to a secret scanner.
PROVIDER_KEYS = (
    "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "sk_" + "test_" + "51HxYzAbCdEfGhIjKlMnOp",
    "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    "gho" + "_16C7e42F292c6912E7710c838347Ae178B4a",
    "github" + "_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
    "AKIA" + "IOSFODNN7EXAMPLE",
    "xox" + "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
)


@pytest.mark.parametrize("key", PROVIDER_KEYS)
def test_a_standalone_provider_key_is_masked_in_free_text(key):
    redacted = redact_text(f"the page leaked {key} in a comment")
    assert key not in redacted and "the page leaked" in redacted and redacted.endswith("in a comment")


def test_provider_key_detection_leaves_references_and_words_alone():
    text = f"kept as {REFERENCE}; ask_live_mode and skeleton_test_case and AKIA-docs stay"
    assert redact_text(text) == text


# Review sweep (informational): mask_credential_shaped is safe on its own for secret-named
# assignments whose value is not credential-shaped by itself.
@pytest.mark.parametrize("text, secret", [
    ("PASSWORD=hunter2", "hunter2"),
    ("API_KEY=a1b2c3d4e5f6a7b8", "a1b2c3d4e5f6a7b8"),
    ("SESSION=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
     "dozjgNryP4J3jVmNHl0w5N"),
    ("https://app.test/cb?token=abcd1234&lang=en", "abcd1234"),
])
def test_a_secret_named_assignment_is_withheld_by_mask_credential_shaped_alone(text, secret):
    masked = mask_credential_shaped(text)
    assert secret not in masked
    assert masked.split("=", 1)[0] == text.split("=", 1)[0]


def test_name_aware_masking_keeps_locations_markers_and_plain_settings():
    text = "TOKEN_URL=https://idp.test/oauth/token PASSWORD=[withheld:2] TOKEN_TYPE=bearer MODE=prod"
    assert mask_credential_shaped(text) == text
