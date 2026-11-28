"""Server-owned provenance for automatic Hunt work; never supplied by a planner."""
from contextlib import contextmanager
from contextvars import ContextVar

_ENGINE_WORK = ContextVar("hunt_engine_work", default=False)


def is_engine_work() -> bool:
    return _ENGINE_WORK.get()


@contextmanager
def engine_work():
    token = _ENGINE_WORK.set(True)
    try:
        yield
    finally:
        _ENGINE_WORK.reset(token)
