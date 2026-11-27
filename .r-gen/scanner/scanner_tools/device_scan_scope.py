"""An explicit UDP scope changes coverage, never the requested authority or safety class."""
from __future__ import annotations
from dataclasses import replace
from typing import Any


def normalize_udp_ports(value: Any) -> list[int] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 1024:
        raise ValueError('UDP scope must be a list of at most 1024 ports')
    if any(type(port) is not int or not 1 <= port <= 65535 for port in value):
        raise ValueError('UDP ports must be integers between 1 and 65535')
    return list(dict.fromkeys(value))


def with_udp_scope(profile: Any, requested: Any) -> Any:
    ports = normalize_udp_ports(requested)
    return profile if ports is None else replace(profile, udp_ports=tuple(ports))
