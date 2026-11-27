"""An explicit zero is an exhausted limit, not an undeclared/unlimited dimension."""
import pytest

from runtime.budgets import BudgetError, BudgetExceeded, BudgetLedger, reserve_budget_snapshot


@pytest.mark.parametrize("dimension", ["active_actions", "state_changing_requests", "device_fragility_points"])
def test_zero_limit_preserves_other_work_and_reports_typed_exhaustion(dimension):
    limits = {dimension: 0, "http_requests": 2}
    assert reserve_budget_snapshot(limits, {}, {"http_requests": 1}) == {dimension: 0, "http_requests": 1}
    with pytest.raises(BudgetExceeded) as error:
        reserve_budget_snapshot(limits, {}, {dimension: 1})
    assert error.value.shortages == {dimension: 1}
    ledger = BudgetLedger(limits)
    request = ledger.reserve({"http_requests": 1})
    ledger.commit(request)
    assert ledger.remaining("http_requests") == 1 and ledger.remaining(dimension) == 0
    with pytest.raises(BudgetExceeded) as error:
        ledger.reserve({dimension: 1})
    assert error.value.shortages == {dimension: 1}
    assert ledger.remaining("http_requests") == 1


def test_missing_dimension_stays_distinct_from_an_explicit_zero():
    with pytest.raises(BudgetError, match="declared explicitly"):
        reserve_budget_snapshot({"http_requests": 1}, {}, {"active_actions": 1})
    with pytest.raises(BudgetError, match="declared explicitly"):
        BudgetLedger({"http_requests": 1}).reserve({"active_actions": 1})
