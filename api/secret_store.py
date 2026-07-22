"""Encryption-at-rest for AI and DAST target credential secrets (R2b).

On by default, backward compatible:

- The Fernet key is ``AI_CREDENTIAL_ENC_KEY`` when the operator sets it; otherwise it is
  auto-generated once and persisted to a durable, shared path (``RESULTS_DIR``, host-mounted and
  shared by api + worker) so encryption-at-rest works with zero configuration. A STABLE key is
  essential -- a changed key would orphan every previously-encrypted secret -- so the persisted key
  is reused across restarts and created race-safely across concurrent api/worker starts.
- Encrypted values are tagged with the ``enc:fernet:`` prefix, so ``decrypt_secret`` transparently
  handles a mix of legacy plaintext and encrypted rows, and ``encrypt_secret`` never double-encrypts.
- If the key cannot be loaded or persisted, existing plaintext values remain readable but new secret
  writes fail closed instead of silently landing in plaintext.
"""

from __future__ import annotations

import os
import secrets
from typing import Any

import fcntl

_PREFIX = "enc:fernet:"
_fernet: Any = None
_loaded = False


class SecretStoreUnavailable(RuntimeError):
    """Raised when a caller tries to store/use encrypted material without a stable key."""


def _key_file_path() -> str:
    override = str(os.environ.get("AI_CREDENTIAL_ENC_KEY_FILE", "") or "").strip()
    if override:
        return override
    results_dir = str(os.environ.get("RESULTS_DIR", "") or "").strip() or "/results"
    return os.path.join(results_dir, ".credential_enc.key")


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _load_key_material() -> str:
    """Return the Fernet key: the env var if set, else a persisted auto-generated key.

    Creation is serialized with an adjacent flock file and published by fsync + atomic replace while
    holding that lock. This also works on filesystems where hard links are unavailable.
    """
    env_key = str(os.environ.get("AI_CREDENTIAL_ENC_KEY", "") or "").strip()
    if env_key:
        return env_key
    key_path = _key_file_path()
    try:
        from cryptography.fernet import Fernet
        os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
        lock_path = f"{key_path}.lock"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if os.path.exists(key_path):
                with open(key_path, "r", encoding="utf-8") as handle:
                    existing = handle.read().strip()
                if not existing:
                    raise ValueError("credential encryption key file is empty")
                Fernet(existing.encode())
                return existing
            generated = Fernet.generate_key().decode()
            tmp_path = f"{key_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
            try:
                with open(tmp_path, "w", encoding="utf-8") as handle:
                    handle.write(generated)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(tmp_path, 0o600)
                os.replace(tmp_path, key_path)
                _fsync_dir(os.path.dirname(key_path) or ".")
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            return generated
        finally:
            os.close(lock_fd)
    except Exception as exc:  # noqa: BLE001 - legacy reads survive; new secret writes fail closed
        print(f"[secret_store] encryption disabled (key load/persist failed: {type(exc).__name__}: {exc})", flush=True)
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
    """Encrypt a secret for storage, failing closed when no stable key is available."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if not text or text.startswith(_PREFIX):
        return text
    fernet = _get_fernet()
    if fernet is None:
        raise SecretStoreUnavailable("credential encryption is unavailable")
    return _PREFIX + fernet.encrypt(text.encode()).decode()


def decrypt_secret(value: Any) -> Any:
    """Decrypt a stored secret. Plaintext/legacy values pass through unchanged."""
    if not isinstance(value, str) or not value.startswith(_PREFIX):
        return value
    fernet = _get_fernet()
    if fernet is None:
        raise SecretStoreUnavailable("credential decryption is unavailable")
    try:
        return fernet.decrypt(value[len(_PREFIX):].encode()).decode()
    except Exception as exc:
        raise SecretStoreUnavailable("credential ciphertext cannot be decrypted with the active key") from exc
