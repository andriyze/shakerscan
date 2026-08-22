"""Worker-only resolution for target-bound V2 credential profiles.

The resolver is deliberately an async context manager: decryption happens only after
target and approval authority validation, and plaintext references are scrubbed as soon
as the executable capability leaves the context.  No public representation includes a
username, token, password, key, header value, or ciphertext.
"""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import tempfile
from typing import Any, AsyncIterator, Callable, Iterator, Mapping

from .credential_store import (
    CredentialProfileMetadata,
    CredentialStoreError,
    PostgresCredentialProfileStore,
)
from .credentials import (
    CredentialContractError,
    IMMEDIATE_HTTP_HEADER_KINDS,
    immediate_http_headers,
    parse_credential_secret,
)
from .models import TargetBinding

try:
    from secret_store import SecretStoreUnavailable, decrypt_secret
except ModuleNotFoundError:
    from api.secret_store import SecretStoreUnavailable, decrypt_secret


class CredentialResolutionError(RuntimeError):
    """Credential authority, ciphertext, or decrypted material failed closed."""


@dataclass(frozen=True)
class CredentialResolutionAuthority:
    owner_kind: str
    owner_id: str
    credential_access_allowed: bool
    approval_validated: bool
    approval_receipt_id: str | None
    scope_receipt_id: str | None

    def validate(self, target: TargetBinding) -> None:
        if self.owner_kind not in {"scan", "hunt"} or not str(self.owner_id or "").strip():
            raise CredentialResolutionError("credential owner authority is invalid")
        if not self.credential_access_allowed:
            raise CredentialResolutionError("credential access is not allowed by policy")
        if not self.approval_validated or not str(self.approval_receipt_id or "").strip():
            raise CredentialResolutionError(
                "credential access requires a validated target-bound approval"
            )
        scope_id = str(self.scope_receipt_id or "").strip()
        target_scope_id = str(target.scope_receipt_id or "").strip()
        if not scope_id or not target_scope_id or scope_id != target_scope_id:
            raise CredentialResolutionError(
                "credential approval scope does not match the target binding"
            )


@dataclass(frozen=True, repr=False)
class SecretHTTPHeaders:
    values: Mapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return f"SecretHTTPHeaders(names={sorted(self.values)}, values_visible=False)"

    def as_dict(self) -> dict[str, str]:
        return dict(self.values)


@dataclass(frozen=True, repr=False)
class InteractiveHTTPCredential:
    auth_kind: str
    username: str | None = field(repr=False)
    secret: str = field(repr=False)
    endpoint_url: str
    client_id: str | None = field(repr=False)
    scopes: tuple[str, ...]

    def __repr__(self) -> str:
        return (
            f"InteractiveHTTPCredential(auth_kind={self.auth_kind!r}, "
            f"endpoint_configured={bool(self.endpoint_url)}, scope_count={len(self.scopes)}, "
            "values_visible=False)"
        )


@dataclass(frozen=True, repr=False)
class SSHPasswordCredential:
    username: str = field(repr=False)
    password: str = field(repr=False)

    def __repr__(self) -> str:
        return "SSHPasswordCredential(username_configured=True, values_visible=False)"


@dataclass(frozen=True, repr=False)
class SSHPrivateKeyCredential:
    username: str = field(repr=False)
    private_key_path: str
    passphrase: str | None = field(repr=False)

    def __repr__(self) -> str:
        return (
            "SSHPrivateKeyCredential(username_configured=True, "
            f"private_key_path={self.private_key_path!r}, "
            f"passphrase_configured={bool(self.passphrase)}, values_visible=False)"
        )


@dataclass(repr=False)
class ResolvedCredential:
    profile: CredentialProfileMetadata
    authority: CredentialResolutionAuthority
    _material: dict[str, Any] = field(repr=False)
    _temporary_root: str = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __repr__(self) -> str:
        return (
            f"ResolvedCredential(profile_id={self.profile.profile_id!r}, "
            f"auth_kind={self.profile.auth_kind!r}, version={self.profile.current_version}, "
            f"closed={self._closed}, values_visible=False)"
        )

    def _require_open(self) -> None:
        if self._closed:
            raise CredentialResolutionError("resolved credential is closed")

    def http_headers(self) -> SecretHTTPHeaders:
        self._require_open()
        if self.profile.auth_kind not in IMMEDIATE_HTTP_HEADER_KINDS:
            raise CredentialResolutionError(
                "credential requires an interactive login or token exchange"
            )
        try:
            return SecretHTTPHeaders(immediate_http_headers(self._material))
        except CredentialContractError as exc:
            raise CredentialResolutionError(str(exc)) from exc

    def interactive_http(self) -> InteractiveHTTPCredential:
        self._require_open()
        if self.profile.auth_kind not in {
            "form_login", "oauth_client_credentials", "oauth_password",
        }:
            raise CredentialResolutionError("credential is not an interactive HTTP profile")
        return InteractiveHTTPCredential(
            auth_kind=self.profile.auth_kind,
            username=str(self._material.get("username") or "") or None,
            secret=str(self._material.get("secret") or ""),
            endpoint_url=str(self._material.get("endpoint_url") or ""),
            client_id=str(self._material.get("client_id") or "") or None,
            scopes=tuple(str(item) for item in self._material.get("scopes") or ()),
        )

    def ssh_password(self) -> SSHPasswordCredential:
        self._require_open()
        if self.profile.auth_kind != "ssh_password":
            raise CredentialResolutionError("credential is not an SSH password profile")
        return SSHPasswordCredential(
            username=str(self._material.get("username") or ""),
            password=str(self._material.get("secret") or ""),
        )

    @contextmanager
    def ssh_private_key(self) -> Iterator[SSHPrivateKeyCredential]:
        self._require_open()
        if self.profile.auth_kind not in {
            "ssh_private_key", "ssh_private_key_with_passphrase",
        }:
            raise CredentialResolutionError("credential is not an SSH private-key profile")
        root = Path(self._temporary_root)
        if not root.is_dir() or root.is_symlink():
            raise CredentialResolutionError("worker credential temporary directory is unavailable")
        descriptor, path = tempfile.mkstemp(prefix="credential-", suffix=".key", dir=str(root))
        try:
            os.fchmod(descriptor, 0o600)
            key = str(self._material.get("secret") or "").encode("utf-8")
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
            yield SSHPrivateKeyCredential(
                username=str(self._material.get("username") or ""),
                private_key_path=path,
                passphrase=str(self._material.get("secondary_secret") or "") or None,
            )
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                size = os.path.getsize(path)
                with open(path, "r+b", buffering=0) as handle:
                    handle.write(b"\0" * size)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                pass
            try:
                os.unlink(path)
            except OSError:
                pass

    def receipt_metadata(self) -> dict[str, Any]:
        return {
            "credential_profile_id": self.profile.profile_id,
            "credential_profile_version": self.profile.current_version,
            "auth_kind": self.profile.auth_kind,
            "principal_slot": self.profile.principal_slot,
            "target_kind": self.profile.target_kind,
            "approval_receipt_id": self.authority.approval_receipt_id,
            "scope_receipt_id": self.authority.scope_receipt_id,
            "secret_values_visible": False,
        }

    def close(self) -> None:
        if self._closed:
            return
        for key, value in list(self._material.items()):
            if isinstance(value, dict):
                value.clear()
            elif isinstance(value, list):
                value.clear()
            self._material[key] = None
        self._material.clear()
        self._closed = True


class WorkerCredentialResolver:
    def __init__(
        self,
        *,
        store: PostgresCredentialProfileStore | None = None,
        decryptor: Callable[[Any], Any] = decrypt_secret,
        temporary_root: str | None = None,
    ) -> None:
        self._store = store or PostgresCredentialProfileStore()
        self._decryptor = decryptor
        self._temporary_root = os.path.realpath(
            temporary_root
            or os.environ.get("SHAKERSCAN_CREDENTIAL_TMP_DIR")
            or tempfile.gettempdir()
        )

    def _decrypt(self, value: Any, *, name: str) -> str:
        try:
            decrypted = self._decryptor(value)
        except SecretStoreUnavailable as exc:
            raise CredentialResolutionError("credential decryption is unavailable") from exc
        except Exception as exc:
            raise CredentialResolutionError(f"{name} could not be decrypted") from exc
        result = str(decrypted or "")
        if not result or result.startswith("enc:fernet:"):
            raise CredentialResolutionError(f"{name} could not be decrypted")
        return result

    @asynccontextmanager
    async def resolve(
        self,
        conn: Any,
        *,
        profile_id: Any,
        target: TargetBinding,
        capability: str,
        authority: CredentialResolutionAuthority,
    ) -> AsyncIterator[ResolvedCredential]:
        # Authority is checked before even looking up the profile, and decryption comes
        # only after the exact target-bound query succeeds.
        authority.validate(target)
        try:
            stored = await self._store.load_for_worker(
                conn,
                profile_id=profile_id,
                target_kind=target.target_kind,
                target_id=target.target_id,
                capability=capability,
            )
        except CredentialStoreError as exc:
            raise CredentialResolutionError(str(exc)) from exc
        envelope = self._decrypt(stored.encrypted_secret, name="credential secret")
        private_metadata = self._decrypt(
            stored.encrypted_metadata, name="credential metadata"
        )
        try:
            material = parse_credential_secret(stored.metadata.auth_kind, envelope)
            metadata = json.loads(private_metadata)
        except (CredentialContractError, json.JSONDecodeError) as exc:
            raise CredentialResolutionError("decrypted credential envelope is invalid") from exc
        if not isinstance(metadata, Mapping) or metadata.get("schema_version") != (
            "credential-private-metadata/v1"
        ):
            raise CredentialResolutionError("decrypted credential metadata is invalid")
        resolved = ResolvedCredential(
            profile=stored.metadata,
            authority=authority,
            _material=material,
            _temporary_root=self._temporary_root,
        )
        try:
            yield resolved
        finally:
            resolved.close()
