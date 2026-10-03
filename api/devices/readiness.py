"""Operator-facing network capacity states, independent of scan authorization."""
import time

STARTED_AT = time.monotonic()
STARTUP_GRACE_SECONDS = 120


def capacity_state(*, enabled, configured, reports, capable_count, elapsed=None):
    """Startup is bounded; a missing heartbeat after grace is an actionable fault."""
    if not enabled:
        return dict(status='disabled', reason='feature_disabled',
                    message='Network scanning is disabled by your operator.',
                    remedy='Set DEVICE_POSTURE_ENABLED=true and run shakerscan restart.')
    if capable_count:
        return dict(status='ready', reason=None, message='Network scanning is ready.', remedy=None)
    if not configured:
        return dict(status='disabled', reason='network_worker_disabled',
                    message='Network scanning capacity is disabled on this installation.',
                    remedy='Run shakerscan devices start to enable it.')
    if reports:
        stale = any(report['build_current'] is False for report in reports)
        return dict(status='not_ready',
                    reason='device_worker_build_stale' if stale else 'device_worker_missing_nmap_naabu_or_build_identity',
                    message='Network scanning needs attention.',
                    remedy='Run shakerscan devices restart. If it remains unavailable, check shakerscan devices logs.')
    elapsed = time.monotonic() - STARTED_AT if elapsed is None else elapsed
    if elapsed < STARTUP_GRACE_SECONDS:
        return dict(status='starting', reason='network_worker_starting',
                    message='Network scanning is starting. This page will update automatically.', remedy=None)
    return dict(status='not_ready', reason='no_fresh_device_worker',
                message='Network scanning is unavailable. Your saved targets and results are still accessible.',
                remedy='Run shakerscan devices start. If startup fails, check shakerscan devices logs.')
