"""Run attribution over existing finding, verification and observation records.

These are read predicates, not another finding/proof store. A later Hunt seeing
an old candidate does not inherit another run's verification result.
"""


def finding_hunt_predicate(parameter: int) -> str:
    """Include direct creations and actual deterministic verifications by this run."""
    if type(parameter) is not int or parameter < 1:
        raise ValueError("parameter must be a positive SQL bind position")
    return f"""(
        f.hunt_run_id = ${parameter} OR EXISTS (
            SELECT 1 FROM finding_verifications hv
            JOIN hunt_runs hr ON hr.id = ${parameter}
            WHERE hv.finding_id = f.id
              AND hv.requested_by = 'hunt_v2:' || CAST(hr.id AS TEXT)
              AND hv.status = 'completed' AND hv.verdict = 'exploited'
              AND hv.verification_mode = 'deterministic'
              AND hv.target_id IS NOT DISTINCT FROM f.target_id
              AND hv.device_target_id IS NOT DISTINCT FROM f.device_target_id
              AND hr.target_id IS NOT DISTINCT FROM f.target_id
              AND hr.device_target_id IS NOT DISTINCT FROM f.device_target_id
        )
    )"""


def candidate_hunt_predicate(parameter: int) -> str:
    """Scope the opt-in candidate list without confusing an observation with proof."""
    if type(parameter) is not int or parameter < 1:
        raise ValueError("parameter must be a positive SQL bind position")
    return f"""(c.hunt_run_id = ${parameter} OR EXISTS (
        SELECT 1 FROM investigation_candidate_observations ho
        WHERE ho.candidate_id = c.id AND ho.hunt_run_id = ${parameter}
    ))"""
