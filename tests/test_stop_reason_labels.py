"""Every stop reason a batch or tool can state is wired into its readers.

`http_request_budget_exhausted`, `state_changing_budget_exhausted`, `process_killed`
and `cancelled` were stated reasons with operator labels in the explanation, yet the
diagnostic class the operator log and public receipt projection read classed them as an
`unclassified_adapter_error`, and the scan page fell back to the raw code for them and
for `discovery_truncated`.
"""

from __future__ import annotations

import pytest

from scan.activity import action_diagnostic_error_class, diagnostic_error_class
from scan.explanation import _REASON_LABELS

STOP_REASONS = (
    "http_request_budget_exhausted",
    "state_changing_budget_exhausted",
    "process_killed",
    "cancelled",
)


@pytest.mark.parametrize("reason", STOP_REASONS)
def test_a_stated_stop_reason_is_its_own_diagnostic_class(reason):
    # The batch prepends its stated reason ahead of per-attempt tool noise.
    assert diagnostic_error_class([reason, "some tool noise"]) == reason
    assert action_diagnostic_error_class(
        status="partial", reason=reason, execution_started=True, errors=[reason],
    ) == reason


def test_a_more_specific_attempt_error_still_wins_over_a_generic_label():
    assert diagnostic_error_class(["adapter_failed", "connection_limit_exceeded"]) == (
        "connection_limit_exceeded"
    )


@pytest.mark.parametrize("reason", (*STOP_REASONS, "discovery_truncated"))
def test_every_stop_reason_has_an_operator_label(reason):
    assert _REASON_LABELS.get(reason)
