"""Worker-private selected credentials for Hunt authorization proof."""
from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, Mapping

try:
    from runtime.credential_refs import CredentialReferenceError, select_hunt_immediate_principal_reference
    from runtime.credential_resolver import CredentialResolutionError, WorkerCredentialResolver
except ModuleNotFoundError:
    from ..runtime.credential_refs import CredentialReferenceError, select_hunt_immediate_principal_reference
    from ..runtime.credential_resolver import CredentialResolutionError, WorkerCredentialResolver


@dataclass(frozen=True, repr=False)
class AuthzPrincipalHeaders:
    primary_headers: Mapping[str, str] = field(repr=False)
    secondary_headers: Mapping[str, str] = field(repr=False)
    primary_profile_id: str
    secondary_profile_id: str


async def resolve_hunt_authz_principals(
    conn: Any,
    *,
    context: Mapping[str, Any],
    target: Any,
    authority: Any,
    credential_stack: AsyncExitStack,
    resolver: WorkerCredentialResolver | None = None,
) -> AuthzPrincipalHeaders:
    """Resolve two distinct admitted header profiles after approval revalidation."""
    primary = select_hunt_immediate_principal_reference(context, "primary")
    secondary = select_hunt_immediate_principal_reference(context, "secondary")
    if primary["profile_id"] == secondary["profile_id"]:
        raise CredentialReferenceError(
            "authorization proof requires distinct primary and secondary profiles"
        )
    worker_resolver = resolver or WorkerCredentialResolver()
    headers: dict[str, dict[str, str]] = {}
    for slot, reference in (("primary", primary), ("secondary", secondary)):
        resolved = await credential_stack.enter_async_context(worker_resolver.resolve(
            conn, profile_id=reference["profile_id"], target=target,
            capability="authz.verify", authority=authority,
        ))
        if (
            resolved.profile.principal_slot != slot
            or resolved.profile.profile_id != reference["profile_id"]
            or resolved.profile.current_version != reference["profile_version"]
            or resolved.profile.auth_kind != reference["auth_kind"]
        ):
            raise CredentialResolutionError(
                "managed authorization proof principal changed after admission"
            )
        headers[slot] = resolved.http_headers().as_dict()
    return AuthzPrincipalHeaders(
        primary_headers=headers["primary"], secondary_headers=headers["secondary"],
        primary_profile_id=primary["profile_id"], secondary_profile_id=secondary["profile_id"],
    )
