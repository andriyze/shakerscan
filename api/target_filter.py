"""A list filter naming several targets at once: a repeated (or comma-separated) ``target_id``.

A caller that keeps its own grouping of targets (an application, a team's assets) reads one list
for all of them instead of one request per target and a merge it has to page itself.
"""
from __future__ import annotations

import uuid
from typing import Iterable, Optional, Union

from fastapi import HTTPException

#: The most target ids one request may name.
MAX_TARGET_IDS = 500

TargetIdsParam = Optional[Union[str, Iterable[str]]]


def parse_target_ids(value: TargetIdsParam, name: str = "target_id", *, status_code: int = 400,
                     limit: int = MAX_TARGET_IDS) -> Optional[list[uuid.UUID]]:
    """The distinct ids named by ``value`` (None or empty: no filter), in the order given.

    Accepts one id, a comma-separated list, or a repeated parameter (each item may itself be
    comma-separated). A value that is not a UUID, or more than ``limit`` ids, is refused.
    """
    # A route function called directly (not through FastAPI) receives its ``Query(...)`` default.
    if value is None or not isinstance(value, (str, list, tuple, set)):
        return None
    items = [value] if isinstance(value, str) else list(value)
    ids: list[uuid.UUID] = []
    for item in items:
        for part in str(item or "").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ids.append(uuid.UUID(part))
            except ValueError:
                raise HTTPException(status_code=status_code, detail=f"{name} must be a UUID") from None
    ids = list(dict.fromkeys(ids))
    if len(ids) > limit:
        raise HTTPException(status_code=status_code, detail=f"{name}: at most {limit} values")
    return ids or None


def target_ids_sql(column: str, ids: list[uuid.UUID], placeholder: str) -> str:
    """``column = $n`` for one id, ``column = ANY($n::uuid[])`` for several (``placeholder`` is $n
    bound to the id or the list, see ``target_ids_value``)."""
    return f"{column} = {placeholder}" if len(ids) == 1 else f"{column} = ANY({placeholder}::uuid[])"


def target_ids_value(ids: list[uuid.UUID]):
    return ids[0] if len(ids) == 1 else ids
