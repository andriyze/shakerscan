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
