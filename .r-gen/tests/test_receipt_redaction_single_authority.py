"""Every receipt redactor must share one rule.

Three copies of "is this key a secret" existed. Two were unified; the third, in
`api/worker.py`, was missed because nothing looked for a third -- and it matched exact
names only, so worker tool receipts persisted `api_key`, `access_token`,
`aws_secret_access_key`, `refresh_token`, `client_secret` and `session_token` in the
clear. A commit message claimed there was "now one implementation" while two more
existed.

This test enumerates the copies instead of trusting that claim.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from runtime.receipts import key_is_sensitive  # noqa: E402

# Credential names that any receipt path must mask.
MUST_MASK = (
    "api_key", "apikey", "x-api-key", "access_token", "access_key", "access_key_id",
    "aws_access_key_id", "aws_secret_access_key", "refresh_token", "session_token",
    "client_secret", "bearer_token", "authorization", "cookie", "set-cookie",
    "password", "private_key", "ssh_private_key", "signing_key", "credential",
    "credentials", "secret", "signature", "observed_access_key", "matched_api_key",
)


def test_the_shared_rule_masks_every_credential_name():
    missed = [name for name in MUST_MASK if not key_is_sensitive(name, item="value")]
    assert not missed, f"the shared rule does not mask: {missed}"


# Modules that legitimately keep their own vocabulary, and why. Each is a DETECTOR or a
# different contract, not a receipt redactor -- and for a detector over-matching is safe
# (it rejects) while for a redactor under-matching leaks, so they must not be merged.
_SEPARATE_BY_DESIGN = {
    # Documented in scanner/redaction.py: a more aggressive provider-bound redactor with a
    # different sentinel and purpose (what is safe to send to an external AI provider).
    "api/ai_verifier.py",
    # Fail-closed detection of raw secret material at queue boundaries; it rejects rather
    # than masks, so a broad set is the safe direction.
    "api/runtime/secret_material.py",
    # Which scan OPTIONS may carry secrets -- a request-contract question, not redaction.
    "api/api.py",
    # Which request fields a mutation experiment must not touch.
    "api/workflow_experiment.py",
    # Which discovered parameter NAMES look secret-bearing, used to rank candidates.
    "api/scan/work_manifests.py",
}


def test_no_receipt_redactor_carries_its_own_sensitive_key_set():
    """A private key-set inside a redactor is how the three copies drifted apart."""
    offenders = []
    for path in sorted((ROOT / "api").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = str(path.relative_to(ROOT))
        if path.name == "receipts.py" or relative in _SEPARATE_BY_DESIGN:
            continue
        source = path.read_text(encoding="utf-8", errors="ignore")
        if "redact" not in source:
            continue
        for match in re.finditer(
            r"^_?[A-Z_]*(?:SENSITIVE|SECRET)[A-Z_]*(?:KEYS|PARTS|FIELDS)\s*[:=]",
            source, re.MULTILINE,
        ):
            offenders.append(f"{relative}: {match.group(0).strip()}")
    assert not offenders, (
        "these redacting modules define their own secret-key vocabulary instead of "
        "importing the shared one:\n" + "\n".join(offenders)
    )


def test_the_worker_uses_the_shared_rule():
    source = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    assert "redact_receipt_value as _redact_receipt_value" in source
    assert "def _redact_receipt_value" not in source
    assert "_RECEIPT_SENSITIVE_KEYS" not in source, (
        "worker.py still carries its own exact-match key set"
    )


def test_coverage_auth_state_labels_are_not_secrets_but_unknown_values_still_are():
    # The public scan result carries which principal contexts ran; the release benchmark reads
    # them back. Masking them to "***" made two minted principals look missing.
    assert not key_is_sensitive("auth_states_tested", item=["user1", "user2"])
    assert not key_is_sensitive("auth_states_tested", item=["anonymous"])
    assert not key_is_sensitive("auth_states_tested", item=[])
    assert not key_is_sensitive("auth_state", item="user2")
    # Anything that is not a known label under these keys is still masked, and the key
    # without a value is masked because the value cannot be inspected.
    assert key_is_sensitive("auth_states_tested", item=["Bearer eyJhbGci"])
    assert key_is_sensitive("auth_states_tested", item=["user1", "x-secret"])
    assert key_is_sensitive("auth_states_tested")
    assert key_is_sensitive("auth_header", item="Bearer abc")
    assert key_is_sensitive("auth_headers_json", item='{"x": "y"}')


def test_runtime_hardening_redactor_preserves_auth_state_labels():
    from runtime import v2_runtime_hardening as hardening

    redacted = hardening._redact_receipt_value({
        "smart_coverage": {"auth_states_tested": ["user1", "user2"]},
        "options": {"auth_header": "Bearer abc", "auth_states_tested": ["user1", "Bearer abc"]},
    })
    assert redacted["smart_coverage"]["auth_states_tested"] == ["user1", "user2"]
    assert redacted["options"]["auth_header"] == "***"
    assert redacted["options"]["auth_states_tested"] == "***"
