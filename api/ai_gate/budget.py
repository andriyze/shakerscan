from __future__ import annotations

from typing import Any


CHARS_PER_TOKEN_ESTIMATE = 4


class TokenBudget:
    """Tracks estimated token consumption and enforces a hard cap."""

    def __init__(self, limit: int | None) -> None:
        self.limit = limit
        self.input_tokens = 0
        self.output_tokens = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def exceeded(self) -> bool:
        return self.limit is not None and self.total >= self.limit

    def record(self, *, input_chars: int, output_chars: int) -> None:
        self.input_tokens += max(input_chars // CHARS_PER_TOKEN_ESTIMATE, 1)
        self.output_tokens += max(output_chars // CHARS_PER_TOKEN_ESTIMATE, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_tokens_estimated": self.input_tokens,
            "output_tokens_estimated": self.output_tokens,
            "total_tokens_estimated": self.total,
            "token_budget": self.limit,
            "stopped_by_budget": self.exceeded,
        }


class RequestBudget:
    """Tracks outbound HTTP requests and enforces a hard cap."""

    def __init__(self, limit: int | None) -> None:
        self.limit = limit
        self.attempted_requests = 0
        self.successful_requests = 0
        self.rejected_requests = 0
        self.events: list[dict[str, Any]] = []

    @property
    def exhausted(self) -> bool:
        return self.limit is not None and self.attempted_requests >= self.limit

    @property
    def remaining(self) -> int | None:
        if self.limit is None:
            return None
        return max(0, self.limit - self.attempted_requests)

    def consume(self, *, phase: str) -> None:
        if self.exhausted:
            self.rejected_requests += 1
            raise RuntimeError(
                f"AI Gate request budget exhausted before {phase} request "
                f"({self.attempted_requests}/{self.limit})"
            )
        self.attempted_requests += 1
        self.events.append({
            "phase": phase,
            "request_index": self.attempted_requests,
        })

    def record_response(self, *, status_code: int | None) -> None:
        if status_code is not None and 200 <= status_code < 400:
            self.successful_requests += 1
        if self.events:
            self.events[-1]["status_code"] = status_code

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_budget": self.limit,
            "requests_attempted": self.attempted_requests,
            "requests_successful": self.successful_requests,
            "requests_rejected": self.rejected_requests,
            "requests_remaining": self.remaining,
            "stopped_by_request_budget": self.exhausted,
            "request_events": self.events[-50:],
        }
