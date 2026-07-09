"""Encryption-at-rest for AI and DAST target credential secrets (R2b).

Opt-in and backward compatible:

- Encryption is enabled only when ``AI_CREDENTIAL_ENC_KEY`` (a Fernet key) is set.
  With no key, ``encrypt_secret`` returns plaintext and ``decrypt_secret`` is a
  no-op, so existing installs are unchanged.
- Encrypted values are tagged with the ``enc:fernet:`` prefix, so ``decrypt_secret``
  transparently handles a mix of legacy plaintext and encrypted rows during a
  rollout, and ``encrypt_secret`` never double-encrypts.

Generate a key with:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

import os
from typing import Any

_PREFIX = "enc:fernet:"
_fernet: Any = None
_loaded = False


def _get_fernet() -> Any:
    global _fernet, _loaded
    if _loaded:
        return _fernet
    _loaded = True
    key = str(os.environ.get("AI_CREDENTIAL_ENC_KEY", "") or "").strip()
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
        _fernet = Fernet(key.encode())
    except Exception:  # noqa: BLE001 - bad/missing key disables encryption rather than crashing
        _fernet = None
    return _fernet


def encryption_enabled() -> bool:
    return _get_fernet() is not None


def encrypt_secret(value: Any) -> Any:
    """Encrypt a secret for storage. Returns plaintext unchanged when disabled."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if not text or text.startswith(_PREFIX):
        return text
    fernet = _get_fernet()
    if fernet is None:
        return text
    return _PREFIX + fernet.encrypt(text.encode()).decode()


def decrypt_secret(value: Any) -> Any:
    """Decrypt a stored secret. Plaintext/legacy values pass through unchanged."""
    if not isinstance(value, str) or not value.startswith(_PREFIX):
        return value
    fernet = _get_fernet()
    if fernet is None:
        return value
    try:
        return fernet.decrypt(value[len(_PREFIX):].encode()).decode()
    except Exception:  # noqa: BLE001 - undecryptable value returned as-is rather than crashing auth
        return value
