"""Immutable JSON condition snapshots for the existing experiment identity."""

import math
from collections.abc import Mapping
from types import MappingProxyType


def freeze(value, *, depth=0):
    if depth > 16:
        raise ValueError("experiment conditions exceed nesting limit")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("experiment condition keys must be strings")
        return MappingProxyType({key: freeze(item, depth=depth + 1) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item, depth=depth + 1) for item in value)
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("experiment conditions must be finite JSON values")


def thaw(value):
    """Return a detached JSON value for storage/export, never the internal snapshot."""
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value
