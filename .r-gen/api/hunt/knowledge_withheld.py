"""Knowledge texts an operator withheld from Hunts, by digest; free of product imports.

``targets/skill.py`` reads and preserves the set; ``hunt/interpretations.py`` adds to it when an
operator retracts a knowledge note.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def withheld_digests(value: Any) -> dict[str, Any]:
    """The withheld knowledge texts by digest (also reads the single-entry shape of earlier builds)."""
    if not isinstance(value, Mapping):
        return {}
    if isinstance(value.get("digests"), Mapping):
        return {str(key): dict(item) for key, item in value["digests"].items() if isinstance(item, Mapping)}
    if isinstance(value.get("body_sha256"), str):
        return {value["body_sha256"]: dict(value)}
    return {}
