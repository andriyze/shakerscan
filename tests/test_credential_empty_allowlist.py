import pytest

from runtime.credential_refs import CredentialReferenceError, select_hunt_principal_reference
from runtime.scan_credentials import (
    scan_credential_allows_capability,
    scan_credential_resolution_capability,
)


def test_empty_runtime_allowlist_grants_nothing():
    assert scan_credential_resolution_capability((), auth_kind="bearer_token") is None
    assert scan_credential_allows_capability((), "http.request") is False
    with pytest.raises(CredentialReferenceError, match="exactly one usable"):
        select_hunt_principal_reference({
            "credential_refs": [{
                "profile_id": "profile-a",
                "profile_version": 1,
                "principal_slot": "primary",
                "allowed_capabilities": [],
                "source": "credential_profiles",
            }],
        }, "primary")
