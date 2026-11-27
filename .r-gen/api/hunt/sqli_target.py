"""What a Hunt ``sqli.verify`` call asks sqlmap to test.

sqlmap tests the query parameters of the URL it is given (and a request body, when one is
declared). Given a URL with neither, ``--batch`` answers its own question "do you want to try URI
injections in the target URL itself?" with yes and appends its injection marker to the path. A
Hunt call naming ``/search`` therefore spent its whole hold (about 515 requests) injecting into
the path ``/search`` and never tested the page's ``q`` parameter. Such a call is refused before
anything is reserved, and the refusal says how to name what to test: a query parameter
(``/reports?filter=x``), or a path segment marked with ``*`` (``/products/1*``), sqlmap's own
explicit marker, when the path itself is the input.
"""
from __future__ import annotations

import urllib.parse
from collections.abc import Mapping
from typing import Any

# At its level 2, sqlmap also tests the request's cookies beside the query parameters; given a
# segment marked with *, it tests only what is marked. A call that wants the cookies tested names
# a query parameter, which a bare path (whose path sqlmap marked itself) also got.
NO_INJECTION_POINT = (
    "sqli.verify needs an input to test: name the parameter in the path's query (for example "
    "/reports?filter=x), or mark the path segment to test with * (for example /products/1*). "
    "Without either, sqlmap tests only the URL path itself. With a query parameter named, sqlmap "
    "also tests the request's cookies; a path marked with * has only the marked segment tested."
)


def sqli_injection_point_refusal(url: str, options: Mapping[str, Any]) -> str | None:
    """The refusal for a call that names no injection point, or None when it names one."""
    if any(options.get(key) for key in ("body_field_names", "injection_field", "injection_fields")):
        return None
    parsed = urllib.parse.urlsplit(str(url or ""))
    if "*" in parsed.path or "*" in parsed.query:
        return None
    if any(name for name, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)):
        return None
    return NO_INJECTION_POINT


__all__ = ["NO_INJECTION_POINT", "sqli_injection_point_refusal"]
