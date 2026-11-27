"""Action-local interruption signals shared with existing adapter stop callbacks."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class ActionInterruption:
    reason: str | None = None
    last_confirmed_at: str | None = None
    observed_at: str | None = None

    def record(self, reason: str | None) -> None:
        if self.reason is not None:
            return  # A late successful check cannot erase an interruption.
        now = datetime.now(timezone.utc).isoformat()
        if reason is None:
            self.last_confirmed_at = now
        else:
            self.reason, self.observed_at = reason, now


_current: ContextVar[ActionInterruption | None] = ContextVar("scan_action_interruption", default=None)


def action_interrupted() -> bool:
    signal = _current.get()
    return signal is not None and signal.reason is not None


@contextmanager
def interruption_scope(signal: ActionInterruption):
    token = _current.set(signal)
    try:
        yield
    finally:
        _current.reset(token)
