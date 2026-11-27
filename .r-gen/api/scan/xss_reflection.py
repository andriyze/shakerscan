"""A one-request reflection check before the reflected-XSS tool runs on a candidate.

Dalfox sends its whole payload set to a request whether or not any of its inputs comes back in
the response: about 1,350 requests for a two-field form at its paced rate, more than seven
minutes per candidate, and on a slow target the attempt is wall-killed with no verdict. Reflected
XSS needs the input back in the response. This check sends the candidate's request once with an
inert alphanumeric canary in every tested input; when the canary appears nowhere in the response,
no input reflects and the tool is not run (a negative verdict for reflected XSS, ``no_reflection``).
When any input reflects, or the check gets no answer, the tool runs exactly as before.

The canary is letters and digits only, so no encoding the application applies hides it.
"""
from __future__ import annotations

import secrets
import urllib.parse
from typing import Any, Mapping, Sequence

NO_REFLECTION = "no_reflection"
# The canary came back, but in a response no browser renders as a page: a JSON document. Script
# in it cannot run where it is, so the reflected-XSS tool has nothing to prove there (a value an
# application later writes into a page is stored or DOM XSS, which this tool does not test).
NOT_A_PAGE = "response_not_a_page"


def new_canary() -> str:
    return "ssx" + secrets.token_hex(6) + "q"


def canary_request_parts(
    url: str, body_request: Mapping[str, Any], canary: str, *, nested_json_body: Any,
) -> tuple[str, str, bytes, str | None]:
    """``(method, url, body, content_type)`` of the candidate's request with every input set to
    ``canary``: each body field of a body candidate, else each query parameter of the URL."""
    fields: Sequence[str] = [str(item) for item in body_request.get("body_field_names") or () if str(item)]
    if fields:
        method = str(body_request.get("method") or "POST").upper()
        content_type = str(body_request.get("content_type") or "").lower()
        if "json" in content_type:
            import json
            body = json.dumps(nested_json_body(fields, placeholder=canary), separators=(",", ":"))
            return method, url, body.encode("utf-8"), "application/json"
        body = "&".join(f"{urllib.parse.quote(field, safe='')}={canary}" for field in fields)
        return method, url, body.encode("utf-8"), "application/x-www-form-urlencoded"
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query = urllib.parse.urlencode([(name, canary) for name, _value in pairs])
    return "GET", urllib.parse.urlunsplit(parts._replace(query=query)), b"", None


def has_inputs(url: str, body_request: Mapping[str, Any]) -> bool:
    if body_request.get("body_field_names"):
        return True
    return bool(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))


def not_a_page(headers: Mapping[str, Any] | None) -> bool:
    """True when the response declares a JSON media type (``application/json``, ``+json``).

    Only JSON: a browser never renders it as HTML whatever its body holds. Plain text, XML,
    JavaScript (JSONP) and a missing or unknown type all stay candidates.
    """
    for name, value in (headers or {}).items():
        if str(name).lower() == "content-type":
            media = str(value).split(";", 1)[0].strip().lower()
            return media == "application/json" or media.endswith("+json")
    return False


def reflects(status: Any, body: bytes | None, canary: str) -> bool | None:
    """True/False when the answer shows whether the canary came back; None for no answer."""
    if status is None:
        return None
    return canary.encode("ascii") in bytes(body or b"")
