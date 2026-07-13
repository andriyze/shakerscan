"""Encryption-at-rest for AI and DAST target credential secrets (R2b).

On by default, backward compatible:

- The Fernet key is ``AI_CREDENTIAL_ENC_KEY`` when the operator sets it; otherwise it is
  auto-generated once and persisted to a durable, shared path (``RESULTS_DIR``, host-mounted and
  shared by api + worker) so encryption-at-rest works with zero configuration. A STABLE key is
  essential -- a changed key would orphan every previously-encrypted secret -- so the persisted key
  is reused across restarts and created race-safely across concurrent api/worker starts.
- Encrypted values are tagged with the ``enc:fernet:`` prefix, so ``decrypt_secret`` transparently
  handles a mix of legacy plaintext and encrypted rows, and ``encrypt_secret`` never double-encrypts.
- If the key cannot be loaded or persisted (e.g. cryptography missing), it degrades to plaintext
  rather than crashing.
"""

from __future__ import annotations

import os
from typing import Any

_PREFIX = "enc:fernet:"
_fernet: Any = None
_loaded = False


def _key_file_path() -> str:
    override = str(os.environ.get("AI_CREDENTIAL_ENC_KEY_FILE", "") or "").strip()
    if override:
        return override
    results_dir = str(os.environ.get("RESULTS_DIR", "") or "").strip() or "/results"
    return os.path.join(results_dir, ".credential_enc.key")


def _load_key_material() -> str:
    """Return the Fernet key: the env var if set, else a persisted auto-generated key."""
    env_key = str(os.environ.get("AI_CREDENTIAL_ENC_KEY", "") or "").strip()
    if env_key:
        return env_key
    key_path = _key_file_path()
    try:
        if os.path.exists(key_path):
            with open(key_path, "r", encoding="utf-8") as handle:
                existing = handle.read().strip()
            if existing:
                return existing
        from cryptography.fernet import Fernet
        os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
        generated = Fernet.generate_key().decode()
        # Create-exclusively so a concurrent api/worker start cannot split-brain the key: whoever
        # wins the create keeps its key; every loser reads the winner's key back.
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, generated.encode())
            finally:
                os.close(fd)
            return generated
        except FileExistsError:
            with open(key_path, "r", encoding="utf-8") as handle:
                return handle.read().strip()
    except Exception:  # noqa: BLE001 - never let key persistence crash the app; degrade to plaintext
        return ""


def _get_fernet() -> Any:
    global _fernet, _loaded
    if _loaded:
        return _fernet
    _loaded = True
    key = _load_key_material()
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
