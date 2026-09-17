"""Regression pins for semantics that #137 and corrected main both require."""

from api.scan.capability_result import CapabilityResultReason


def test_dependency_incomplete_and_authentication_uncertain_are_distinct_reasons():
    """Neither #136 coverage semantics nor #137 assurance may overwrite the other."""
    assert CapabilityResultReason.DEPENDENCY_INCOMPLETE.value == "dependency_incomplete"
    assert CapabilityResultReason.AUTHENTICATION_UNCERTAIN.value == "authentication_uncertain"
    assert CapabilityResultReason.DEPENDENCY_INCOMPLETE is not CapabilityResultReason.AUTHENTICATION_UNCERTAIN


def test_corrected_main_asm_backoff_regression_is_present_after_sync():
    """The #135 regression module must survive future #137 rebases/merges."""
    from tests import test_asm_dispatch_backoff

    assert callable(test_asm_dispatch_backoff.test_dispatch_failure_records_a_backoff_decision)
    assert callable(test_asm_dispatch_backoff.test_target_inside_dispatch_backoff_is_skipped)
