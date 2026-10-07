"""The one error type every AI boundary contract parser raises."""
from __future__ import annotations


class ContractError(ValueError):
    """A boundary contract, hypothesis or provenance value is not acceptable."""
