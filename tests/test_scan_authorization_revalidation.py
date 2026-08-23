from __future__ import annotations

import pytest


@pytest.mark.xfail(
    strict=True,
    reason="V2-P1-08: privileged Scan actions do not yet reload approval authority at dispatch",
)
def test_privileged_action_dispatch_requires_fresh_scope_and_approval_authority():
    from scan.authorization import ActionAuthorityDecision, revalidate_action_authority

    decision = revalidate_action_authority(
        action={"capability_name": "web.active.xss"},
        approval_receipt={"status": "revoked"},
        target_binding={"status": "active"},
    )
    assert decision is ActionAuthorityDecision.REJECTED_REVOKED
