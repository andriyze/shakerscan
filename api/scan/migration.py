"""Time-bounded compatibility policy for pre-V2 deterministic Scan jobs."""

from __future__ import annotations

from datetime import datetime, timezone
import os


# Old queue payloads may drain only during the explicit V2 migration window.
# This is deliberately a code-owned deadline rather than an environment default:
# deployments cannot accidentally keep digest-less execution enabled forever.
LEGACY_SCAN_EXECUTION_CUTOFF = datetime(2026, 9, 1, tzinfo=timezone.utc)


class LegacyScanExecutionExpired(ValueError):
    """A digest-less deterministic Scan reached a worker after V2 cutover."""


def require_legacy_scan_execution_window(
    *, now: datetime | None = None,
) -> None:
    """Reject legacy deterministic execution once its bounded drain expires."""
    disabled = str(
        os.getenv("SHAKERSCAN_DISABLE_LEGACY_SCAN_EXECUTION", "")
    ).strip().lower() in {"1", "true", "yes", "on"}
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    if disabled or current >= LEGACY_SCAN_EXECUTION_CUTOFF:
        raise LegacyScanExecutionExpired(
            "legacy deterministic Scan execution expired at "
            f"{LEGACY_SCAN_EXECUTION_CUTOFF.isoformat()}; submit a digest-bound "
            "canonical V2 Scan job"
        )
