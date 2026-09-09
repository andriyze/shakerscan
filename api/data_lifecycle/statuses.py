"""Deletion blockers follow each owning subsystem, not a universal status list.

Unknown states remain blocked. These describe durable run/job lifecycle status,
not a verification verdict (inconclusive, fixed, etc.).
"""
try:
    from research_agent import TERMINAL_EPISODE_STATUSES
except ModuleNotFoundError:
    from ..research_agent import TERMINAL_EPISODE_STATUSES

TERMINAL_BY_TABLE = {
    # Canonical Scan and historical completed-quality states.
    'scans': frozenset({'completed', 'partial', 'degraded', 'failed', 'cancelled'}),
    # hunt/run_service.py; created/active/awaiting_planner remain nonterminal.
    'hunt_runs': frozenset({'completed', 'cancelled', 'failed', 'budget_exhausted'}),
    # The legacy run CHECK constraints in retest_contract.py.
    'agent_hunt_runs': frozenset({'completed', 'cancelled', 'failed'}),
    'device_agent_runs': frozenset({'completed', 'cancelled', 'failed'}),
    'research_episodes': frozenset(TERMINAL_EPISODE_STATUSES),
    # campaigns_status_check: paused is resumable, not terminal.
    'campaigns': frozenset({'completed', 'cancelled'}),
    'scan_campaigns': frozenset({'completed', 'failed', 'cancelled'}),
    # Worker verification job status, deliberately not result_status/verdict.
    'finding_verifications': frozenset({'completed', 'failed', 'cancelled'}),
}