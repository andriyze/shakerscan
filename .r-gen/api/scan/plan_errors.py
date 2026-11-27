"""Scan action-plan error types.

A leaf module so that plan collaborators (health_plan) can raise the plan's own error
without importing action_plan, which calls into them. action_plan re-exports both
names, so every existing importer is unchanged.
"""


class ScanActionPlanError(ValueError):
    """Action authority is malformed, ambiguous, or not content-addressed."""


class ScanActionPlacementError(ScanActionPlanError):
    """No selected backend can execute the complete deterministic action plan."""
