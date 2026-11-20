"""TtlMemo: the expected build fingerprint is hashed once per TTL, not on every /health read
(the API wiring is tested in test_api_helpers.py)."""
from __future__ import annotations

from api.runtime.ttl_memo import TtlMemo


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_memo_computes_once_within_ttl_and_again_after():
    calls = []
    clock = Clock()
    memo = TtlMemo(lambda: calls.append(1) or f"fp-{len(calls)}", 30.0, clock=clock)
    assert memo() == "fp-1"
    clock.now += 29.9
    assert memo() == "fp-1"
    assert len(calls) == 1
    clock.now += 0.2
    assert memo() == "fp-2"
    assert len(calls) == 2


def test_memo_remembers_none_but_not_a_failure():
    clock = Clock()
    answers = iter([RuntimeError("unreadable"), None, "late"])

    def compute():
        value = next(answers)
        if isinstance(value, Exception):
            raise value
        return value

    memo = TtlMemo(compute, 30.0, clock=clock)
    try:
        memo()
    except RuntimeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("the failure must reach the caller")
    assert memo() is None  # computed again after the failure
    assert memo() is None  # a None answer is a real answer and is remembered
    memo.clear()
    assert memo() == "late"
