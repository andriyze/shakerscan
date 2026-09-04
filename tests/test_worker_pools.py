from api.worker_pools import worker_pool_summaries


def _readiness(*, status="ready", count=1, current=1, workers=None, reason=None):
    return {
        "status": status,
        "reason": reason,
        "worker_count": count,
        "capable_worker_count": current,
        "workers": workers or [],
    }


def test_worker_pool_summaries_keep_web_dast_and_specialized_counts_separate():
    pools = worker_pool_summaries(
        {"count": 5, "current_count": 4, "stale_count": 1, "pending_count": 0},
        agent_tool=lambda: _readiness(),
        device=lambda: _readiness(status="disabled", count=0, current=0, reason="feature_disabled"),
        model_intake=lambda: _readiness(
            status="not_ready",
            count=2,
            current=1,
            workers=[{"build_current": True}, {"build_current": False}],
            reason="model_intake_worker_build_stale",
        ),
    )

    assert pools["web_dast"] == {
        "count": 5,
        "current": 4,
        "stale": 1,
        "pending": 0,
        "status": "not_ready",
        "reason": "web_dast_pool_not_uniform",
    }
    assert pools["agent_tool"]["current"] == 1
    assert pools["device"]["status"] == "disabled"
    assert pools["model_intake"]["stale"] == 1


def test_worker_pool_summaries_classify_unidentified_workers_as_pending():
    pools = worker_pool_summaries(
        {"count": 2, "current_count": 1, "stale_count": 0},
        agent_tool=lambda: _readiness(status="not_ready", count=2, current=1),
        device=lambda: _readiness(status="disabled", count=0, current=0),
        model_intake=lambda: _readiness(),
    )

    assert pools["web_dast"]["pending"] == 1
    assert pools["agent_tool"]["pending"] == 1


def test_worker_pool_summaries_fail_closed_when_specialized_readiness_raises():
    def unavailable():
        raise RuntimeError("registry unavailable")

    pools = worker_pool_summaries(
        {"count": 1, "current_count": 1},
        agent_tool=unavailable,
        device=lambda: _readiness(status="disabled", count=0, current=0),
        model_intake=lambda: _readiness(),
    )

    assert pools["agent_tool"] == {
        "count": 0,
        "current": 0,
        "stale": 0,
        "pending": 0,
        "status": "not_ready",
        "reason": "worker_readiness_unavailable",
    }
