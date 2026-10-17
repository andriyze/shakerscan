"""A ``NAME=value`` assignment keeps its name and loses its whole value; a ``secret://`` reference
survives the free-text redactor (B18: an exposed ``.env`` read as ``***`` for ``SECRET_KEY`` and the
rest of the value after its first ``%`` stayed in clear)."""

from __future__ import annotations

import time

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
