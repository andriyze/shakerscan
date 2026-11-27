"""Run attribution over existing finding, verification and observation records.

These are read predicates, not another finding/proof store. A later Hunt seeing
an old candidate does not inherit another run's verification result.
"""


def finding_hunt_predicate(parameter: int) -> str:
    """Include direct creations and actual deterministic verifications by this run.

    A finding another Hunt owns is still this run's when this run verified it again
    (finding_hunt_verifications, D21).

    The run's findings are one set, computed once from three indexed reads (findings by
    ``hunt_run_id``, finding_hunt_verifications by run, finding_verifications by
    ``requested_by``), and the list tests membership in it. The previous form OR-ed two
    EXISTS correlated with ``f.id``: the planner had to visit every finding under the other
    filters and run both probes per row.
    """
    if type(parameter) is not int or parameter < 1:
        raise ValueError("parameter must be a positive SQL bind position")
    return f"""f.id IN (
        SELECT hf.id FROM findings hf WHERE hf.hunt_run_id = ${parameter}
        UNION
        SELECT fhv.finding_id FROM finding_hunt_verifications fhv WHERE fhv.hunt_run_id = ${parameter}
        UNION
        SELECT hv.finding_id
        FROM hunt_runs hr
        JOIN finding_verifications hv ON hv.requested_by = 'hunt_v2:' || CAST(hr.id AS TEXT)
        JOIN findings vf ON vf.id = hv.finding_id
        WHERE hr.id = ${parameter}
          AND hv.status = 'completed' AND hv.verdict = 'exploited'
          AND hv.verification_mode = 'deterministic'
          AND hv.target_id IS NOT DISTINCT FROM vf.target_id
          AND hv.device_target_id IS NOT DISTINCT FROM vf.device_target_id
          AND hr.target_id IS NOT DISTINCT FROM vf.target_id
          AND hr.device_target_id IS NOT DISTINCT FROM vf.device_target_id
    )"""


def candidate_hunt_predicate(parameter: int) -> str:
    """Scope the opt-in candidate list without confusing an observation with proof."""
    if type(parameter) is not int or parameter < 1:
        raise ValueError("parameter must be a positive SQL bind position")
    return f"""(c.hunt_run_id = ${parameter} OR EXISTS (
        SELECT 1 FROM investigation_candidate_observations ho
        WHERE ho.candidate_id = c.id AND ho.hunt_run_id = ${parameter}
    ))"""
