"""The requests an external verifier sent, read from its own wire log, for the Scan archive.

sqlmap (``-t traffic.log``) and Dalfox (``--har-file-path requests.har``) record every HTTP
transaction they send; the worker already reads those logs to settle the wire reservation
(``agent_tools.SCANNER_WIRE_LOG_FILES``). Over HTTPS their traffic is ciphertext to the engine's
pinned tunnel, so these logs are the only record of what the tool sent: a seeded login POST and
every payload it carried. Each transaction is returned for the archive with its method, URL,
request headers and body, and its response status and headers, with the response body cut to a
short prefix. Values are kept as sent: the archive seals raw payloads and masks every export
(credentials, secret-named fields), as it does for the engine's own calls.

Only transactions to the tunnel's one origin are kept (a tool's log could name another host it
was refused); at most ``MAX_TRANSACTIONS`` per run, the rest counted as dropped.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping
import urllib.parse

MAX_TRANSACTIONS = 2_000
MAX_REQUEST_BODY_BYTES = 16 * 1024
MAX_RESPONSE_BODY_BYTES = 4 * 1024

_SQLMAP_BLOCK = re.compile(
    r"^HTTP (request|response) \[#(\d{1,9})\](?: \((\d{3})[^\n]*\))?:[ \t]*\r?\n", re.MULTILINE,
)
_REQUEST_LINE = re.compile(r"^([A-Z]{3,10}) (\S+) HTTP/\d(?:\.\d)?\s*$")


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None
    return parts.scheme.lower(), parts.hostname.lower().rstrip("."), port


def _cut(text: str, limit: int) -> tuple[str, bool]:
    data = text.encode("utf-8", "replace")
    if len(data) <= limit:
        return text, False
    return data[:limit].decode("utf-8", "ignore"), True


def _split_head(block: str) -> tuple[list[str], str]:
    head, _sep, body = block.partition("\n\n")
    return [line.rstrip("\r") for line in head.splitlines() if line.strip()], body.rstrip("\r\n")


def _headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        name, sep, value = line.partition(":")
        if sep and name.strip() and " " not in name.strip():
            headers[name.strip().lower()[:120]] = value.strip()[:2_000]
    return headers


def _transaction(
    *, method: str, url: str, request_headers: Mapping[str, str], request_body: str,
    status: int | None, response_headers: Mapping[str, str], response_body: str,
) -> dict[str, Any]:
    request_body, request_cut = _cut(request_body, MAX_REQUEST_BODY_BYTES)
    response_body, response_cut = _cut(response_body, MAX_RESPONSE_BODY_BYTES)
    return {
        "method": method.upper()[:16], "url": url[:8_000],
        "request_headers": dict(request_headers), "request_body": request_body or None,
        "request_body_truncated": request_cut,
        "status_code": status if status and 100 <= status <= 599 else None,
        "response_headers": dict(response_headers), "response_body": response_body or None,
        "response_body_truncated": response_cut,
    }


def sqlmap_transactions(text: str, origin: str) -> list[dict[str, Any]]:
    """The transactions of a sqlmap ``-t`` log, joined to ``origin`` (``scheme://host[:port]``)."""
    blocks = list(_SQLMAP_BLOCK.finditer(str(text or "")))
    requests: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for index, marker in enumerate(blocks):
        end = blocks[index + 1].start() if index + 1 < len(blocks) else len(text)
        lines, body = _split_head(text[marker.end():end])
        kind, number = marker.group(1), marker.group(2)
        if kind == "request":
            match = _REQUEST_LINE.match(lines[0]) if lines else None
            if match is None:
                continue
            target = match.group(2)
            url = target if target.startswith(("http://", "https://")) else origin + (
                target if target.startswith("/") else "/" + target)
            requests[number] = _transaction(
                method=match.group(1), url=url, request_headers=_headers(lines[1:]),
                request_body=body, status=None, response_headers={}, response_body="",
            )
            order.append(number)
        elif number in requests and requests[number]["status_code"] is None:
            # A redirect is logged as a second response under the same number: the first counts.
            response = _transaction(
                method="GET", url="", request_headers={}, request_body="",
                status=int(marker.group(3)) if marker.group(3) else None,
                response_headers=_headers(lines), response_body=body,
            )
            requests[number].update({
                key: response[key] for key in (
                    "status_code", "response_headers", "response_body", "response_body_truncated")
            })
    return [requests[number] for number in order]


_ENTRIES_START = re.compile(r'"entries"\s*:\s*\[')


def _har_entries(text: str) -> list[Any]:
    """A HAR's entries. Dalfox writes the document as it goes, so a run its wall stopped leaves it
    unterminated: every entry it finished is still read, one complete object at a time."""
    try:
        entries = json.loads(text)["log"]["entries"]
        return entries if isinstance(entries, list) else []
    except (TypeError, ValueError, KeyError):
        pass
    start = _ENTRIES_START.search(text)
    if start is None:
        return []
    decoder = json.JSONDecoder()
    found: list[Any] = []
    position = start.end()
    while True:
        while position < len(text) and text[position] in " \t\r\n,":
            position += 1
        if position >= len(text) or text[position] != "{":
            return found
        try:
            entry, position = decoder.raw_decode(text, position)
        except ValueError:
            return found  # the entry the stop cut off
        found.append(entry)


def har_transactions(text: str) -> list[dict[str, Any]]:
    """The transactions of a HAR document (Dalfox's ``--har-file-path``), complete or cut off."""
    entries = _har_entries(str(text or ""))
    found: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), Mapping) else {}
        response = entry.get("response") if isinstance(entry.get("response"), Mapping) else {}
        if not request.get("url"):
            continue

        def pairs(value: Any) -> dict[str, str]:
            return {
                str(item.get("name") or "").lower()[:120]: str(item.get("value") or "")[:2_000]
                for item in value or () if isinstance(item, Mapping) and item.get("name")
            }

        post = request.get("postData") if isinstance(request.get("postData"), Mapping) else {}
        content = response.get("content") if isinstance(response.get("content"), Mapping) else {}
        try:
            status = int(response.get("status") or 0) or None
        except (TypeError, ValueError):
            status = None
        found.append(_transaction(
            method=str(request.get("method") or "GET"), url=str(request["url"]),
            request_headers=pairs(request.get("headers")), request_body=str(post.get("text") or ""),
            status=status, response_headers=pairs(response.get("headers")),
            response_body=str(content.get("text") or ""),
        ))
    return found


def wire_log_transactions(tool: str, text: str, origin: str) -> tuple[list[dict[str, Any]], int]:
    """``(transactions, dropped)``: the tool's logged requests to ``origin``, bounded."""
    name = str(tool or "").strip().lower()
    if name == "sqlmap":
        found = sqlmap_transactions(text, origin)
    elif name == "dalfox":
        found = har_transactions(text)
    else:
        return [], 0
    want = _origin(origin)
    kept = [item for item in found if want is not None and _origin(item["url"]) == want]
    return kept[:MAX_TRANSACTIONS], max(0, len(kept) - MAX_TRANSACTIONS)


__all__ = ["MAX_TRANSACTIONS", "har_transactions", "sqlmap_transactions", "wire_log_transactions"]
