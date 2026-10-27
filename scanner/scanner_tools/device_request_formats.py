"""Encrypted request-document formats for connected-device Web/API assessment.

This module extends the original Postman pipeline with HAR 1.2 and
OpenAPI/Swagger inputs.  It deliberately produces the same resolved-request
contract, so destination pinning and state-changing authorization remain in
``device_web`` rather than being reimplemented per format.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from collections import Counter
from typing import Any

from .url_redaction import (
    drop_matrix_parameters, is_sensitive_label, redact_url, token_like_query_name, token_like_segment,
)
from .device_postman import (
    MAX_BODY_BYTES,
    MAX_COLLECTION_BYTES,
    MAX_HEADERS,
    MAX_REQUESTS,
    HARD_MAX_COLLECTION_BYTES,
    HARD_MAX_REQUESTS,
    SAFE_METHODS,
    STATE_CHANGING_METHODS,
    SUPPORTED_METHODS,
    PostmanCollectionError,
    public_request_url,
    resolve_requests as resolve_postman_requests,
    validate_and_summarize as validate_postman,
)


IMPORT_FORMATS = {"auto", "postman_collection", "har", "openapi"}
HTTP_METHODS = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}
_SENSITIVE_NAME_RE = re.compile(
    r"(?:authorization|api[-_]?key|token|secret|password|passwd|cookie|session|credential|private[-_]?key)",
    re.I,
)
_SERVER_VARIABLE_RE = re.compile(r"\{([^{}]+)\}")
# A browser capture (``format = "capture"``) is a HAR document the recorder wrote from a live
# session. Its cookies, authorization and token headers are what the browser held, and they are
# never replayed: authentication comes only from the target's credential profiles.
CAPTURE_FORMAT = "capture"
CAPTURE_CREDENTIAL_HEADER_NAMES = frozenset({
    "cookie", "authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "csrf-token", "xsrf-token", "x-csrftoken",
})
_CAPTURE_CREDENTIAL_NAME_RE = re.compile(r"(?:auth|csrf|xsrf|bearer|signature)", re.I)
# The marker a capture document's log carries (api/capture/flows.py): a capture stays a capture
# even if its row were relabelled, because re-validation keeps the log.
CAPTURE_LOG_SCHEMA = "browser-capture/v1"
# A capture request whose recorded path carries a credential (a session id, a reset, magic-login
# or invitation token, a one-time code): the path is the credential, so it is not replayed.
CAPTURED_PATH_CREDENTIAL_WITHHELD = "captured_path_credential_withheld"


class RequestImportError(ValueError):
    """A request document is invalid, unsupported, or exceeds safe bounds."""


def _json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise RequestImportError("Request import must be valid JSON data") from exc


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _port_hint(url: str) -> int | None:
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.port:
            return int(parsed.port)
        if parsed.scheme == "https":
            return 443
        if parsed.scheme == "http":
            return 80
    except ValueError:
        return None
    return None


def _header_rows(raw: Any) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("key") or "").strip()
        value = str(item.get("value") or "")
        if not name or any(ch in name for ch in "\r\n:") or "\r" in value or "\n" in value:
            continue
        result.append((name[:500], value))
        if len(result) >= MAX_HEADERS:
            break
    return result


def _request_id(prefix: str, index: int, method: str, url: str) -> str:
    return hashlib.sha256(
        json.dumps([prefix, index, method, url], separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()[:24]


def detect_format(document: Any) -> str:
    if not isinstance(document, dict):
        raise RequestImportError("Request import must be one JSON object")
    if isinstance(document.get("log"), dict) and isinstance(document["log"].get("entries"), list):
        return "har"
    if isinstance(document.get("openapi"), str) or isinstance(document.get("swagger"), str):
        return "openapi"
    if isinstance(document.get("item"), list) or isinstance(document.get("info"), dict) and "schema" in document.get("info", {}):
        return "postman_collection"
    raise RequestImportError("Could not detect Postman, HAR 1.2, OpenAPI, or Swagger JSON")


def validate_request_document(
    document: Any,
    environment: Any = None,
    *,
    requested_name: str | None = None,
    import_format: str = "auto",
    base_url: str | None = None,
    max_requests: int = MAX_REQUESTS,
    max_document_bytes: int = MAX_COLLECTION_BYTES,
) -> tuple[dict[str, Any], dict[str, Any]]:
    max_requests = int(max_requests)
    max_document_bytes = int(max_document_bytes)
    if not 1 <= max_requests <= HARD_MAX_REQUESTS:
        raise RequestImportError(f"request limit must be between 1 and {HARD_MAX_REQUESTS}")
    if not 1 <= max_document_bytes <= HARD_MAX_COLLECTION_BYTES:
        raise RequestImportError(
            f"document limit must be between 1 and {HARD_MAX_COLLECTION_BYTES} bytes"
        )
    requested_format = str(import_format or "auto").strip().lower()
    if requested_format not in IMPORT_FORMATS:
        raise RequestImportError("format must be auto, postman_collection, har, or openapi")
    actual = detect_format(document) if requested_format == "auto" else requested_format
    if actual == "postman_collection":
        try:
            return validate_postman(
                document, environment, requested_name=requested_name,
                max_requests=max_requests, max_collection_bytes=max_document_bytes,
            )
        except PostmanCollectionError as exc:
            raise RequestImportError(str(exc)) from exc
    if environment is not None:
        raise RequestImportError("Environment JSON is supported only for Postman collections")
    if actual == "har":
        if base_url:
            raise RequestImportError("base_url is supported only for OpenAPI and Swagger imports")
        return _validate_har(
            document, requested_name=requested_name, max_requests=max_requests,
            max_document_bytes=max_document_bytes,
        )
    return _validate_openapi(
        document, requested_name=requested_name, base_url=base_url,
        max_requests=max_requests, max_document_bytes=max_document_bytes,
    )


def resolve_imported_requests(
    payload: dict[str, Any], *, max_requests: int = MAX_REQUESTS
) -> list[dict[str, Any]]:
    """Resolve a worker-only encrypted payload into the shared replay contract."""
    if not isinstance(payload, dict):
        raise RequestImportError("Encrypted request payload is invalid")
    format_name = str(payload.get("format") or "")
    if not format_name and isinstance(payload.get("collection"), dict):
        return resolve_postman_requests(payload, max_requests=max_requests)  # legacy payloads
    if format_name == "postman_collection":
        return resolve_postman_requests(
            {"collection": payload.get("document"), "environment": payload.get("environment")},
            max_requests=max_requests,
        )
    if format_name == CAPTURE_FORMAT or (format_name == "har" and is_capture_document(payload.get("document"))):
        return strip_captured_credentials(
            _resolve_har(payload.get("document"), max_requests=max_requests)
        )
    if format_name == "har":
        return _resolve_har(payload.get("document"), max_requests=max_requests)
    if format_name == "openapi":
        requests, _metadata = _openapi_requests(
            payload.get("document"), base_url=payload.get("base_url"), max_requests=max_requests
        )
        return requests
    raise RequestImportError("Encrypted request payload has an unsupported format")


def is_capture_document(document: Any) -> bool:
    """A HAR log written by a browser capture, whatever format its payload is labelled with."""
    log = document.get("log") if isinstance(document, dict) else None
    if not isinstance(log, dict):
        return False
    creator = log.get("creator") if isinstance(log.get("creator"), dict) else {}
    return log.get("_shakerscanCapture") == CAPTURE_LOG_SCHEMA or creator.get("version") == CAPTURE_LOG_SCHEMA


def is_captured_credential_header(name: str) -> bool:
    """A header whose recorded value authenticated the browser: never replayed from a capture."""
    lowered = str(name or "").strip().lower()
    return (
        lowered in CAPTURE_CREDENTIAL_HEADER_NAMES
        or bool(_SENSITIVE_NAME_RE.search(lowered))
        or bool(_CAPTURE_CREDENTIAL_NAME_RE.search(lowered))
    )


# Names a credential travels under as a query parameter or a ``name=value`` path segment: a
# credential label, a name containing a credential word, or ``sig``/``code``/``auth``/``jwt``/
# ``sid``/``key`` as a whole word of the name.
_CREDENTIAL_NAME_RE = re.compile(
    r"(?:authorization|api[-_]?key|token|secret|password|passwd|passcode|passphrase|cookie"
    r"|session|credential|private[-_]?key|otp|csrf|xsrf)"
    r"|(?:^|[-_.])(?:sig|code|auth|jwt|sid|key)(?:$|[-_.])",
    re.I,
)


def is_credential_name(name: str) -> bool:
    """A parameter name whose recorded value is a credential (``token``, ``access_key``,
    ``x-sig``, ``sessionid``): a capture's replay withholds it from a query string and from a
    ``name=value`` path segment."""
    text = str(name or "")
    return is_sensitive_label(text) or bool(_CREDENTIAL_NAME_RE.search(text))


def is_captured_secret_query(name: str, value: str) -> bool:
    """A query parameter a recorded session used as a credential: named like a token, secret,
    session, signature, code or key (``is_credential_name``), or with a token-like value (a JWT,
    a long hex or opaque string, a random-looking one)."""
    text = str(name or "")
    return (
        is_credential_name(text)
        or token_like_segment(urllib.parse.unquote(str(value or "")))
        # A bare parameter (``?<token>``) is its own value: a JWT or random token, an AWS access
        # key id or standard base64 (``token_like_query_name``).
        or token_like_segment(urllib.parse.unquote(text))
        or token_like_query_name(text)
    )


def withheld_query_label(name: str, pieces: frozenset[str] = frozenset()) -> str:
    """The label a withheld query parameter is listed under: its name, or ``<redacted>`` when the
    name is itself a credential (``?<token>``, a token-like or base64 name, an AWS access key id,
    or a recorded credential value), so the list of what was withheld never carries it."""
    text = str(name or "")
    if (token_like_query_name(text) or token_like_segment(urllib.parse.unquote(text))
            or _holds_recorded_credential(text, pieces)):
        return "<redacted>"
    return text[:160]


def captured_secret_query_name(name: str, bare: bool) -> bool:
    """A query name a display masks: token-like, or a bare parameter (``?<name>``, its own
    value) that ``is_captured_secret_query`` treats as a credential."""
    return token_like_query_name(name, bare) or (bare and is_captured_secret_query(name, ""))


# What a capture's replay withholds from a recorded path.
#
# ``url_redaction.redact_path`` is the display mask of every request list, receipt and endpoint
# inventory, and the scanner's sensitive-path gate. It errs towards hiding (any value after
# ``auth`` or ``session``, every UUID, any 28-character slug), which costs nothing in a list but
# would stop ordinary requests from being replayed. A capture's replay therefore decides with its
# own rule, written for credentials, and leaves the shared mask alone. A path segment carries a
# credential when it is:
#
# - an ASP.NET cookieless session or ticket: ``(S(<session-id>))``, ``(X(1)F(<ticket>))``;
# - a ``name=value`` pair named like a credential (``is_credential_name``: ``token=<v>``,
#   ``sessionid=<v>``, ``x-sig=<v>``), or a ``name:value`` one whose value is value-shaped;
# - wherever it appears, a JWT, 32 or more hex characters (a dashless UUID, an MD5 or SHA digest
#   and a git commit id included), or a random token of 32 or more characters. A UUID written
#   with dashes and a ``sha256-<hex>`` digest name resources;
# - a value-shaped segment right after a credential or share word (``_CREDENTIAL_PATH_LABELS``,
#   or a compound or plural of one of ``_CREDENTIAL_PATH_WORDS``): ``/s/<session-id>/``,
#   ``/share/<token>``, ``/reset/<token>``, ``/verify-email/<token>``, ``/otp/482913``. A route
#   word there (``/auth/login``, ``/session/current``, ``/token/refresh``, ``/verify/v2``) is
#   not a value; a number is (``/share/1234``);
# - a random token (``url_redaction.token_like_segment``) right after a download or short-link
#   word (``_LINK_PATH_LABELS``): ``/download/<token>``, ``/m/<token>``.
#
# A segment that repeats a credential value recorded in a URL of the same capture (a share
# page's token in the path of an API call it makes) is withheld too (``_withheld_path_segments``).
# A capture's request list masks every segment replay withholds as well as what the display mask
# hides (``redact_captured_url``).
_CREDENTIAL_PATH_LABELS = frozenset({
    # The display mask's credential words (``url_redaction``), in label form.
    "access-token", "accesstoken", "api-key", "apikey", "auth", "authorization", "bearer",
    "code", "confirm", "confirmation", "credential", "credentials", "invite", "invitation",
    "key", "magic", "nonce", "otp", "password", "recover", "recovery", "reset", "secret",
    "session", "signature", "signed", "sso", "token", "verify", "verification",
    # Sessions, share links, sign-in links and one-time codes.
    "s", "sid", "share", "shared", "login", "signin", "sign-in", "activate", "activation",
    "unsubscribe", "passwordless", "one-time", "onetime", "2fa", "mfa",
})
# A label of up to three words with one of these words (or its plural) is a credential label
# too: ``verify-email``, ``confirm_account``, ``session-id``, ``reset-password``, ``sessions``.
_CREDENTIAL_PATH_WORDS = frozenset({
    "token", "otp", "reset", "magic", "invite", "invitation", "nonce", "verify",
    "verification", "confirm", "confirmation", "activate", "activation", "session", "secret",
    "password", "passwordless", "unsubscribe", "share", "recover", "recovery", "sso",
})
_LINK_PATH_LABELS = frozenset({"d", "dl", "download", "downloads", "l", "link", "links", "m"})
_PATH_PAIR_RE = re.compile(r"^([^=:]{1,80})([:=])(.*)$")
_COOKIELESS_SESSION_RE = re.compile(r"^\((?:[A-Za-z]\([^()]*\))+\)$")
_JWT_SEGMENT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}$")
_HEX_SEGMENT_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_TOKEN_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_~+=-]{32,}$")
_TOKEN_RUN_SPLIT_RE = re.compile(r"[-_.~+=]+")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DIGEST_RE = re.compile(r"^(?:md5|sha1|sha224|sha256|sha384|sha512|blake2b|blake3)[-_:]", re.I)
_VERSION_RE = re.compile(r"^[vV]\d{1,3}(?:\.\d{1,3}){0,2}$")
_PROTOCOL_WORD_RE = re.compile(r"^(?:[a-z]{2,10}|[A-Z]{2,10})\d$")
_WORD_RE = re.compile(r"^[^\W\d_]+(?:[-_.][^\W\d_]+)*$")


def _path_label(segment: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", segment.strip().lower()).strip("-")


def _case_switches(run: str) -> int:
    return sum(
        1 for left, right in zip(run, run[1:], strict=False)
        if left.isalpha() and right.isalpha() and left.isupper() != right.isupper()
    )


def _letter_digit_switches(run: str) -> int:
    return sum(1 for left, right in zip(run, run[1:], strict=False) if left.isdigit() != right.isdigit())


def _route_word(value: str) -> bool:
    """Route structure, not a value: letters (``login``, ``check-otp``, ``report.pdf``) whose
    case does not change at random, a version (``v3``) or a one-case word with one digit
    (``oauth2``)."""
    if _VERSION_RE.fullmatch(value) or _PROTOCOL_WORD_RE.fullmatch(value):
        return True
    return bool(_WORD_RE.fullmatch(value)) and not any(
        len(run) >= 8 and _case_switches(run) * 2 >= len(run) for run in re.split(r"[-_.]", value)
    )


def _value_shaped(value: str) -> bool:
    """Four or more characters that are not a route word: with a digit or another character,
    or letters whose case changes at random."""
    return len(value) >= 4 and not _route_word(value)


def _standalone_credential(value: str) -> bool:
    """A segment that is a credential whatever precedes it (see the rule above)."""
    if (
        _COOKIELESS_SESSION_RE.fullmatch(value)
        or _JWT_SEGMENT_RE.fullmatch(value)
        or _HEX_SEGMENT_RE.fullmatch(value)
    ):
        return True
    if not _TOKEN_SEGMENT_RE.fullmatch(value) or _UUID_RE.fullmatch(value) or _DIGEST_RE.match(value):
        return False
    # A random run switches between letters and digits, or letter case, far more often than a
    # word slug with numbers (``release-notes-2026-10-19``) does.
    return any(
        len(run) >= 8 and (
            _letter_digit_switches(run) >= 3
            or (len(run) >= 12 and _case_switches(run) * 3 >= len(run))
        )
        for run in _TOKEN_RUN_SPLIT_RE.split(value)
    )


def _label_kind(label: str) -> str | None:
    """``"credential"`` when a value after this path word is a credential, ``"link"`` when a
    random token after it is, ``None`` otherwise."""
    if label in _CREDENTIAL_PATH_LABELS:
        return "credential"
    words = label.split("-")
    if len(words) <= 3 and any(
        word in _CREDENTIAL_PATH_WORDS
        or (word.endswith("s") and word[:-1] in _CREDENTIAL_PATH_WORDS)
        for word in words
    ):
        return "credential"
    return "link" if label in _LINK_PATH_LABELS else None


def _path_credentials(path: str) -> list[tuple[int, str]]:
    """``(position, shown prefix)`` for each segment of ``path`` (positions in
    ``path.split("/")``) that carries a credential: the prefix is ``name=`` for a credential
    pair, whose name may still be shown, and empty when the whole segment is the credential."""
    found: list[tuple[int, str]] = []
    previous: str | None = None
    for position, segment in enumerate(str(path or "").split("/")):
        decoded = urllib.parse.unquote(drop_matrix_parameters(segment))
        if not decoded:
            previous = None
            continue
        pair = _PATH_PAIR_RE.fullmatch(decoded)
        if (
            pair and pair.group(3) and is_credential_name(pair.group(1))
            and (pair.group(2) == "=" or _value_shaped(pair.group(3)))
        ):
            found.append((position, pair.group(1) + pair.group(2)))
        elif (
            _standalone_credential(decoded)
            or (previous == "credential" and _value_shaped(decoded))
            or (
                previous == "link" and token_like_segment(decoded)
                and not _UUID_RE.fullmatch(decoded)
            )
        ):
            found.append((position, ""))
        previous = _label_kind(_path_label(decoded))
    return found


def _withheld_path_segments(url: str, recorded: frozenset[str]) -> dict[int, str]:
    """``{position: shown prefix}`` for each segment of ``url``'s path that a capture's replay
    withholds: those the rule above marks (``_path_credentials``) and those that repeat a
    credential value recorded in a URL of the same capture (``recorded``, from
    ``captured_credential_values``: a share page's token in the path of an API call it makes)."""
    try:
        path = urllib.parse.urlsplit(str(url or "").strip()).path
    except ValueError:
        return {}
    found = {
        position: "" for position, segment in enumerate(path.split("/"))
        if recorded and _holds_recorded_credential(drop_matrix_parameters(segment), recorded)
    }
    found.update(_path_credentials(path))
    return found


def captured_path_credential_segments(url: str, recorded: frozenset[str] = frozenset()) -> list[int]:
    """Positions (``path.split("/")``, so a leading ``/`` makes the first segment 1) of the
    segments of a recorded ``url`` that carry a credential under the capture replay rule above:
    a session id after ``/s/``, a share, reset, magic-login or invitation token, a one-time code,
    ``token=<value>``, an ASP.NET cookieless session, a JWT or a long hex or random token; never
    a route word, a UUID with dashes or a short resource id with no credential word before it.
    With ``recorded`` (``captured_credential_values`` of the capture's requests), a segment that
    repeats one of those values is among them too. ``redact_captured_url`` masks each of them."""
    return sorted(_withheld_path_segments(url, recorded))


def redact_captured_url(url: str, recorded: frozenset[str] = frozenset()) -> str:
    """A recorded URL as a capture's request list shows it: the display mask every request list
    uses (``url_redaction.redact_url``) with each segment the capture replay withholds
    (``captured_path_credential_segments``) masked too, so the list never shows a value that
    replay treats as a credential. A URL whose path carries no credential is shown exactly as
    ``redact_url`` shows it."""
    text = str(url or "").strip()
    shown = redact_url(text, max_length=1 << 20, secret_query_name=captured_secret_query_name)
    found = _withheld_path_segments(text, recorded)
    if found:
        parts = urllib.parse.urlsplit(shown)
        segments = parts.path.split("/")
        for position, prefix in found.items():
            if position < len(segments):
                segments[position] = prefix + "<redacted>"
        shown = urllib.parse.urlunsplit(parts._replace(path="/".join(segments)))
    return shown[:2_000]


# Copies of the page's URL a browser puts in a request: the Referer, a path-bearing Origin,
# htmx's ``HX-Current-URL`` and the Next.js router's ``Next-Url`` (a path). Every header whose
# value is an absolute http(s) URL or path is read as one (``_looks_like_page_url``), as are URLs
# and paths in JSON and form bodies and in query values; a Referer that is not a URL is not sent.
_ABSOLUTE_URL_RE = re.compile(r"^\s*https?://", re.I)
_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
# The runs a recorded credential value is matched by elsewhere in a request.
_CREDENTIAL_PIECE_RE = re.compile(r"[A-Za-z0-9_~-]+")


def _query_carries_credential(query: str) -> bool:
    return any(
        is_captured_secret_query(name, item)
        for name, item in urllib.parse.parse_qsl(query, keep_blank_values=True)
    )


def _fragment_carries_credential(fragment: str) -> bool:
    """``#access_token=<v>`` (an implicit grant), or an SPA route whose path or query carries a
    credential (``#/s/<session-id>``, ``#/welcome?token=<v>``)."""
    route, _separator, query = fragment.partition("?")
    route = route[1:] if route.startswith("!") else route
    if route.startswith("/"):
        return bool(_path_credentials(route)) or _query_carries_credential(query)
    return _query_carries_credential(fragment)


def _page_url_without_credential(value: str, *, origin_form: bool = False) -> str | None:
    """A copy of a page URL (a Referer, an ``HX-Current-URL``, a ``Next-Url`` path, a URL in a
    body or a query value) as a capture replay sends it: ``value`` itself when it carries no
    credential; only its origin (``https://app.example/``, or without the ``/`` for an Origin
    header) when its userinfo, path (``captured_path_credential_segments``), ``;matrix``
    parameters, query or fragment held one, and ``/`` for a same-origin path that did; ``None``
    when it is neither an http(s) URL nor an absolute path."""
    text = str(value or "").strip()
    try:
        parts = urllib.parse.urlsplit(text)
        _port = parts.port  # an invalid port raises ValueError
    except ValueError:
        return None
    if parts.scheme or parts.netloc:
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        origin: str | None = f"{parts.scheme.lower()}://{parts.netloc.rsplit('@', 1)[-1]}"
    elif text.startswith("/") and not text.startswith("//"):
        origin = None
    else:
        return None
    carries_credential = (
        "@" in parts.netloc or ";" in parts.path
        or bool(_path_credentials(parts.path))
        or _query_carries_credential(parts.query)
        or _fragment_carries_credential(parts.fragment)
    )
    if not carries_credential:
        return value
    if origin is None:
        return "/"
    return origin if origin_form else origin + "/"


def _credential_pieces(value: str) -> set[str]:
    """The runs of a credential value that identify a copy of it: six or more characters that
    are not a route word."""
    return {
        piece for piece in _CREDENTIAL_PIECE_RE.findall(str(value or ""))
        if len(piece) >= 6 and not _route_word(piece)
    }


def _url_credential_pieces(url: str) -> set[str]:
    """The credential values a recorded URL or path carries, as ``_credential_pieces``: its
    withheld path segments, the userinfo password, and ``;matrix``, query and fragment parameters
    named like a credential (``is_credential_name``)."""
    try:
        parts = urllib.parse.urlsplit(str(url or "").strip())
    except ValueError:
        return set()
    route, _separator, fragment_query = parts.fragment.partition("?")
    route = route[1:] if route.startswith("!/") else route
    values = [urllib.parse.unquote(parts.password)] if parts.password else []
    for path in (parts.path, route if route.startswith("/") else ""):
        segments = path.split("/")
        values.extend(
            urllib.parse.unquote(drop_matrix_parameters(segments[position]))[len(prefix):]
            for position, prefix in _path_credentials(path)
        )
        for segment in segments:
            for parameter in segment.split(";")[1:]:
                name, _equals, value = parameter.partition("=")
                if is_credential_name(urllib.parse.unquote(name)):
                    values.append(urllib.parse.unquote(value))
    for query in (parts.query, fragment_query, "" if route.startswith("/") else route):
        values.extend(
            item for name, item in urllib.parse.parse_qsl(query, keep_blank_values=True)
            if is_credential_name(name)
        )
    pieces: set[str] = set()
    for value in values:
        pieces |= _credential_pieces(value)
    return pieces


def captured_credential_values(requests: list[dict[str, Any]]) -> frozenset[str]:
    """Every credential value the recorded URLs of a capture carry (as ``_credential_pieces``):
    the request URLs and the page URLs and paths in their headers. A copy of one of them
    anywhere else in a replayed request (another request's path, a router state header, a JSON
    field, a beacon body) is left out too."""
    pieces: set[str] = set()
    for request in requests:
        pieces |= _url_credential_pieces(str(request.get("url") or ""))
        pieces |= _url_credential_pieces(str(request.get("url_template") or ""))
        for _name, value in [
            *list(request.get("header_items") or []), *dict(request.get("headers") or {}).items(),
        ]:
            text = str(value or "")
            if _looks_like_page_url(text):
                pieces |= _url_credential_pieces(text)
    return frozenset(pieces)


def _holds_recorded_credential(text: str, pieces: frozenset[str]) -> bool:
    if not pieces or not text:
        return False
    candidates = [text, urllib.parse.unquote(text)] if "%" in text else [text]
    return any(
        piece in pieces for candidate in candidates for piece in _CREDENTIAL_PIECE_RE.findall(candidate)
    )


def _looks_like_page_url(text: str) -> bool:
    stripped = text.strip()
    return bool(_ABSOLUTE_URL_RE.match(stripped)) or (
        stripped.startswith("/") and not stripped.startswith("//")
    )


def _replayable_text(text: str, pieces: frozenset[str]) -> str:
    """A recorded value (a query value, a JSON or form field) as a capture replay sends it: a
    page URL or path without its credential (``_page_url_without_credential``), empty when it
    is a URL that does not parse or holds a recorded credential value, otherwise unchanged."""
    replayable = text
    if _looks_like_page_url(text):
        replayable = _page_url_without_credential(text) or ""
    return "" if _holds_recorded_credential(replayable, pieces) else replayable


def _replayable_capture_url(url: str, pieces: frozenset[str] = frozenset()) -> tuple[str, list[str], bool]:
    """``url`` without userinfo, path ``;name=value`` parameters (``;jsessionid=``) and its
    credential query parameters (named like a credential, token-like, or a copy of a page URL or
    of a recorded credential value); the names of the parameters left out, and whether userinfo
    was."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url, [], False
    netloc = parts.netloc.rsplit("@", 1)[-1]
    path = parts.path
    if ";" in path:
        path = "/".join(segment.split(";", 1)[0] for segment in path.split("/"))
    withheld: list[str] = []
    query = parts.query
    if query:
        kept = []
        for name, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
            if is_captured_secret_query(name, value) or _replayable_text(value, pieces) != value:
                label = withheld_query_label(name, pieces)
                if label not in withheld:
                    withheld.append(label)
            else:
                kept.append((name, value))
        if withheld:
            query = urllib.parse.urlencode(kept)
    if path == parts.path and not withheld and netloc == parts.netloc:
        return url, [], False
    return (
        urllib.parse.urlunsplit((parts.scheme, netloc, path, query, parts.fragment)),
        withheld,
        netloc != parts.netloc,
    )


_CAPTURE_SECRET_FIELD_RE = re.compile(
    r"(?:password|passwd|passcode|passphrase|secret|token|api[-_]?key|credential|private[-_]?key|otp|csrf|xsrf)",
    re.I,
)
# Short secret names, matched as a whole word of the field name (``pass``, ``new_pwd``,
# ``user-pin``) so that ``spinner`` or ``compass`` stay.
_CAPTURE_SECRET_WORDS = frozenset({"pass", "pwd", "pin", "passphrase", "secret", "otp", "pw", "mfa", "totp"})
_FIELD_WORD_RE = re.compile(r"[^a-z0-9]+")
# A body that names one of these anywhere, but cannot be parsed confidently, is not replayed.
_BODY_SECRET_HINT_RE = re.compile(
    r"(?:pass(?:word|wd|code|phrase)?|pwd|secret|token|otp|pin|api[-_]?key|credential)", re.I,
)


def is_captured_secret_field(name: str) -> bool:
    """A body field whose recorded value is a credential: ``password``, ``pass``, ``pwd``,
    ``pin``, ``otp``, ``passphrase``, token and secret names (by its last path component)."""
    text = str(name or "")
    last = re.split(r"[.\[\]]+", text.strip("[]."))[-1] if text else ""
    words = {word for word in _FIELD_WORD_RE.split(last.lower()) if word}
    return bool(_CAPTURE_SECRET_FIELD_RE.search(last) or words & _CAPTURE_SECRET_WORDS)


def _blank_all(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _blank_all(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_blank_all(item) for item in value]
    return "" if value is not None else None


def _blank_secret_fields(value: Any, withheld: set[str]) -> Any:
    """``value`` with everything under a secret-named key emptied: a scalar, every element of a
    list, every leaf of an object."""
    if isinstance(value, dict):
        blanked = {}
        for key, item in value.items():
            if is_captured_secret_field(str(key)) and item is not None:
                withheld.add(str(key)[:160])
                blanked[key] = _blank_all(item)
            else:
                blanked[key] = _blank_secret_fields(item, withheld)
        return blanked
    if isinstance(value, list):
        return [_blank_secret_fields(item, withheld) for item in value]
    return value


def _without_credential_copies(value: Any, pieces: frozenset[str], withheld: set[str], key: str = "") -> Any:
    """A parsed JSON body with every string that is a page URL carrying a credential reduced to
    its origin, and every string holding a recorded credential value emptied
    (``_replayable_text``); the field names changed go into ``withheld``."""
    if isinstance(value, dict):
        return {
            name: _without_credential_copies(item, pieces, withheld, str(name))
            for name, item in value.items()
        }
    if isinstance(value, list):
        return [_without_credential_copies(item, pieces, withheld, key) for item in value]
    if isinstance(value, str):
        replayable = _replayable_text(value, pieces)
        if replayable != value:
            withheld.add((key or "[]")[:160])
        return replayable
    return value


def _holds_credential_copy(text: str, pieces: frozenset[str]) -> bool:
    """Body text that cannot be parsed but holds a page URL carrying a credential or a recorded
    credential value."""
    return _holds_recorded_credential(text, pieces) or any(
        _page_url_without_credential(found) != found for found in _URL_IN_TEXT_RE.findall(text)
    )


_MULTIPART_NAME_RE = re.compile(rb'(?i)content-disposition:[^\r\n]*?\bname="([^"]*)"')


def _without_secret_multipart_fields(
    body: bytes, content_type: str, withheld: set[str], pieces: frozenset[str] = frozenset(),
) -> bytes | None:
    """A multipart/form-data body with the content of secret-named parts, and of parts that
    hold a copy of a recorded credential, emptied, or None when it cannot be parsed
    confidently."""
    match = re.search(r'boundary="?([^";]+)"?', content_type, re.I)
    if not match:
        return None
    delimiter = b"--" + match.group(1).strip().encode("latin-1")
    pieces_of_body = body.split(delimiter)
    if len(pieces_of_body) < 3 or not pieces_of_body[-1].startswith(b"--"):
        return None
    rebuilt = [pieces_of_body[0]]
    for piece in pieces_of_body[1:-1]:
        head, separator, content = piece.partition(b"\r\n\r\n")
        if not separator:
            return None
        name = _MULTIPART_NAME_RE.search(head)
        if name is None:
            return None
        field = name.group(1).decode("utf-8", "replace")
        if is_captured_secret_field(field) or _holds_credential_copy(content.decode("utf-8", "replace"), pieces):
            withheld.add(field[:160])
            content = b"\r\n" if content.endswith(b"\r\n") else b""
        rebuilt.append(head + separator + content)
    rebuilt.append(pieces_of_body[-1])
    return delimiter.join(rebuilt)


def _without_secret_body_fields(
    request: dict[str, Any], pieces: frozenset[str] = frozenset(),
) -> tuple[bytes, list[str]]:
    """A captured body with every password-, token- or secret-named field emptied (JSON, form,
    multipart): the password typed into a recorded login form is never sent again. A page URL in
    a JSON or form field that carries a credential is sent as its origin (or ``/``), and a field
    that holds a recorded credential value (``pieces``) is emptied. A body that cannot be parsed
    confidently but names a secret field anywhere, or holds such a URL or value, is withheld
    whole (``*``)."""
    body = request.get("body") if isinstance(request.get("body"), bytes) else b""
    if not body:
        return body, []
    raw_content_type = next(
        (str(value) for name, value in dict(request.get("headers") or {}).items()
         if str(name).lower() == "content-type"),
        str(request.get("body_mode") or ""),
    )
    content_type = raw_content_type.lower()
    withheld: set[str] = set()
    loose_text = body.decode("utf-8", "replace")
    hinted = bool(_BODY_SECRET_HINT_RE.search(loose_text)) or _holds_credential_copy(loose_text, pieces)
    if "multipart/form-data" in content_type:
        rebuilt = _without_secret_multipart_fields(body, raw_content_type, withheld, pieces)
        if rebuilt is None:
            return (b"", ["*"]) if hinted else (body, [])
        return (rebuilt, sorted(withheld)) if withheld else (body, [])
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return (b"", ["*"]) if hinted else (body, [])
    if "json" in content_type or text.lstrip()[:1] in {"{", "["}:
        try:
            parsed = json.loads(text)
        except ValueError:
            return (b"", ["*"]) if hinted else (body, [])
        blanked = _without_credential_copies(_blank_secret_fields(parsed, withheld), pieces, withheld)
        if not withheld:
            return body, []
        return json.dumps(blanked, separators=(",", ":"), ensure_ascii=False).encode("utf-8"), sorted(withheld)
    if "x-www-form-urlencoded" in content_type or (
        "=" in text and re.fullmatch(r"[^\s&=]+=[^\s&]*(?:&[^\s&=]+=[^\s&]*)*", text.strip())
    ):
        kept = []
        for name, item in urllib.parse.parse_qsl(text, keep_blank_values=True):
            replayable = "" if is_captured_secret_field(name) else _replayable_text(item, pieces)
            if replayable != item or is_captured_secret_field(name):
                withheld.add(name[:160])
            kept.append((name, replayable))
        if withheld:
            return urllib.parse.urlencode(kept).encode("utf-8"), sorted(withheld)
        return body, []
    return (b"", ["*"]) if hinted else (body, [])


def _replay_header_pairs(pairs: Any, pieces: frozenset[str]) -> tuple[list[tuple[str, str]], set[str]]:
    """Recorded headers as a capture replay sends them, and the names of those it changed or
    left out (besides credential headers): no credential header, no Content-Length (an emptied
    body field changes the length, and the replay computes it from the body it sends), every
    value that is an absolute URL or path (a Referer, an Origin, ``HX-Current-URL``,
    ``Next-Url``: copies of the page URL) without the credential it carried, no Referer that is
    not a URL and no URL that does not parse, and no header that holds a recorded credential
    value (``pieces``: the Next.js router state, for one)."""
    kept: list[tuple[str, str]] = []
    changed: set[str] = set()
    for name, value in pairs:
        lowered = str(name).lower()
        if is_captured_credential_header(name) or lowered == "content-length":
            continue
        text = str(value or "")
        replayable: str | None = text
        if text.strip() and (lowered == "referer" or _looks_like_page_url(text)):
            # ``None``: a Referer that is not a URL, or a URL that does not parse; neither is sent.
            replayable = _page_url_without_credential(text, origin_form=lowered == "origin")
        if replayable is not None and _holds_recorded_credential(replayable, pieces):
            replayable = None
        if replayable != text:
            changed.add(lowered)
        if replayable is not None:
            kept.append((name, replayable))
    return kept, changed


def strip_captured_credentials(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Resolved capture requests without a single recorded credential.

    Every consumer that replays a collection (Scan replay, Hunt ``collections.replay_*``, device
    requests) resolves it through ``resolve_imported_requests``, so this is the one place a
    capture's cookies and tokens are removed; a replay that needs a session gets it from a
    credential profile. Credential headers, userinfo, path ``;matrix`` parameters (a
    ``;jsessionid=`` session) and query parameters named like a credential or holding a
    token-like value are dropped from the replayed request, and password-, token- and
    secret-named JSON and form body fields are emptied. A request whose path itself carries a
    credential (``/s/<session>/``, ``/reset/<token>``, ``/api/token=<v>/``:
    ``captured_path_credential_segments``), or repeats a credential value recorded in any URL of
    the capture (``captured_credential_values``), cannot be sent without it, so it is not
    replayed at all: its URL is replaced by the form the capture's request list shows
    (``redact_captured_url``) and it carries ``error = CAPTURED_PATH_CREDENTIAL_WITHHELD``.
    Copies of a page URL that carries a credential (a Referer, Origin, ``HX-Current-URL`` or
    ``Next-Url``, a URL in a query value or a JSON or form field) are sent as its origin or
    ``/``, and a header, query value or field that holds a recorded credential value is left out
    or emptied. The names (and path positions) removed are kept
    (``captured_credentials_withheld``, ``captured_path_segments_withheld``,
    ``captured_query_parameters_withheld``, ``captured_body_fields_withheld``, and all of them in
    ``captured_withheld`` for the replay plan), never their values."""
    pieces = captured_credential_values(requests)
    stripped: list[dict[str, Any]] = []
    for request in requests:
        items, items_changed = _replay_header_pairs(request.get("header_items") or [], pieces)
        headers, headers_changed = _replay_header_pairs(dict(request.get("headers") or {}).items(), pieces)
        withheld = sorted({
            str(name).lower() for name in dict(request.get("headers") or {})
            if is_captured_credential_header(name)
        } | items_changed | headers_changed)
        body, body_fields = _without_secret_body_fields(request, pieces)
        recorded_url = str(request.get("url") or "")
        recorded_template = str(request.get("url_template") or "")
        url, query_withheld, userinfo_withheld = _replayable_capture_url(recorded_url, pieces)
        template, _query, _userinfo = _replayable_capture_url(recorded_template, pieces)
        path_withheld = sorted({
            *captured_path_credential_segments(recorded_url, pieces),
            *captured_path_credential_segments(recorded_template, pieces),
        })
        if path_withheld:
            url = redact_captured_url(url, pieces)
            template = redact_captured_url(template, pieces) if template else template
        stripped.append({
            **request,
            "body": body,
            "captured_body_fields_withheld": body_fields,
            "captured_path_segments_withheld": path_withheld,
            "captured_query_parameters_withheld": query_withheld,
            "captured_withheld": [
                *(f"header:{name}" for name in withheld),
                *(["url:userinfo"] if userinfo_withheld else []),
                *(f"path:{position}" for position in path_withheld),
                *(f"query:{name}" for name in query_withheld),
                *(f"body:{name}" for name in body_fields),
            ],
            "error": CAPTURED_PATH_CREDENTIAL_WITHHELD if path_withheld else request.get("error"),
            "url": url,
            "url_template": template,
            "headers": dict(headers),
            "header_items": items,
            "sensitive_header_names": [],
            "auth_type": "none",
            "has_sensitive_material": False,
            "captured_credentials_withheld": withheld,
        })
    return stripped


def _validate_har(
    document: Any, *, requested_name: str | None, max_requests: int = MAX_REQUESTS,
    max_document_bytes: int = MAX_COLLECTION_BYTES,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
        raise RequestImportError("HAR import must contain one log object")
    if _json_size(document) > max_document_bytes:
        raise RequestImportError(f"HAR import exceeds the {max_document_bytes}-byte limit")
    log = document["log"]
    version = str(log.get("version") or "")
    if version and version != "1.2":
        raise RequestImportError("Only HAR 1.2 is supported")
    entries = log.get("entries")
    if not isinstance(entries, list) or not entries:
        raise RequestImportError("HAR import contains no request entries")
    if len(entries) > max_requests:
        raise RequestImportError(f"HAR import exceeds the {max_requests}-request limit")
    resolved = _resolve_har(document, max_requests=max_requests)
    if not resolved:
        raise RequestImportError("HAR import contains no valid requests")
    creator = log.get("creator") if isinstance(log.get("creator"), dict) else {}
    name = str(requested_name or creator.get("name") and f"{creator.get('name')} HAR" or "Imported HAR traffic").strip()[:160]
    payload = {"format": "har", "document": document}
    summary = _summary(
        name=name,
        format_name="har",
        requests=resolved,
        digest=_digest(payload),
        extra={
            "har_version": version or "1.2",
            "captured_response_bodies_ignored": True,
            "scripts_ignored": 0,
            "environment_variable_names": [],
            "collection_variable_names": [],
        },
    )
    return payload, summary


def _resolve_har(document: Any, *, max_requests: int = MAX_REQUESTS) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
        raise RequestImportError("Encrypted HAR payload is invalid")
    entries = document["log"].get("entries")
    if not isinstance(entries, list):
        raise RequestImportError("Encrypted HAR entries are invalid")
    result: list[dict[str, Any]] = []
    for index, entry in enumerate(entries[:max_requests]):
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict):
            continue
        method = str(request.get("method") or "GET").strip().upper()
        url = str(request.get("url") or "").strip()
        header_items = _header_rows(request.get("headers"))
        headers = dict(header_items)
        cookies = []
        for cookie in request.get("cookies") or []:
            if isinstance(cookie, dict) and cookie.get("name"):
                cookies.append(f"{cookie['name']}={cookie.get('value', '')}")
        if cookies and not any(key.lower() == "cookie" for key in headers):
            headers["Cookie"] = "; ".join(cookies)
            header_items.append(("Cookie", headers["Cookie"]))
        post_data = request.get("postData") if isinstance(request.get("postData"), dict) else {}
        body = b""
        body_error = None
        if isinstance(post_data.get("text"), str):
            body_encoding = str(
                post_data.get("encoding") or post_data.get("_encoding") or ""
            ).strip().lower()
            if body_encoding in {"base64", "base64url"}:
                try:
                    encoded = post_data["text"]
                    if body_encoding == "base64url":
                        encoded += "=" * (-len(encoded) % 4)
                        body = base64.urlsafe_b64decode(encoded.encode("ascii"))
                    else:
                        body = base64.b64decode(encoded, validate=True)
                except (ValueError, UnicodeEncodeError, base64.binascii.Error):
                    body_error = "invalid_base64_request_body"
                    body = b""
            elif body_encoding:
                body_error = "unsupported_request_body_encoding"
            else:
                body = post_data["text"].encode("utf-8")
        elif isinstance(post_data.get("params"), list):
            pairs = [
                (str(item.get("name")), str(item.get("value") or ""))
                for item in post_data["params"] if isinstance(item, dict) and item.get("name")
            ]
            body = urllib.parse.urlencode(pairs).encode()
        mime_type = str(post_data.get("mimeType") or "").strip()
        if body and mime_type and not any(key.lower() == "content-type" for key in headers):
            headers["Content-Type"] = mime_type
            header_items.append(("Content-Type", mime_type))
        if len(body) > MAX_BODY_BYTES:
            body, body_error = b"", "request_body_exceeds_512_kib"
        has_sensitive = bool(cookies) or any(_SENSITIVE_NAME_RE.search(key) for key in headers)
        result.append({
            "id": _request_id("har", index, method, url),
            "name": str(entry.get("pageref") or f"Captured request {index + 1}")[:300],
            "folder": "HAR capture",
            "method": method,
            "url": url,
            "url_template": url,
            "headers": headers,
            "header_items": header_items,
            "sensitive_header_names": sorted(key.lower() for key in headers if _SENSITIVE_NAME_RE.search(key)),
            "body": body,
            "body_mode": mime_type or ("raw" if body else "none"),
            "auth_type": "captured" if has_sensitive else "none",
            "has_sensitive_material": has_sensitive,
            "unresolved_variables": [],
            "error": body_error,
        })
    return result


class _LocalRefResolver:
    def __init__(self, document: dict[str, Any]):
        self.document = document
        self.external_refs_ignored = 0
        self.invalid_refs_ignored = 0

    def resolve(self, value: Any, *, depth: int = 0) -> Any:
        if depth > 12 or not isinstance(value, dict) or "$ref" not in value:
            return value
        ref = str(value.get("$ref") or "")
        if not ref.startswith("#/"):
            self.external_refs_ignored += 1
            return {}
        current: Any = self.document
        try:
            for part in ref[2:].split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                current = current[key]
        except (KeyError, TypeError):
            self.invalid_refs_ignored += 1
            return {}
        return self.resolve(current, depth=depth + 1)


def _example(schema: Any, resolver: _LocalRefResolver, *, depth: int = 0) -> Any:
    if depth > 8:
        return None
    schema = resolver.resolve(schema, depth=depth)
    if not isinstance(schema, dict):
        return None
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    for key in ("oneOf", "anyOf", "allOf"):
        variants = schema.get(key)
        if isinstance(variants, list) and variants:
            if key == "allOf":
                merged: dict[str, Any] = {}
                for item in variants:
                    value = _example(item, resolver, depth=depth + 1)
                    if isinstance(value, dict):
                        merged.update(value)
                return merged
            return _example(variants[0], resolver, depth=depth + 1)
    kind = str(schema.get("type") or ("object" if schema.get("properties") else "string"))
    if kind == "object":
        return {
            str(name): _example(child, resolver, depth=depth + 1)
            for name, child in list((schema.get("properties") or {}).items())[:50]
        }
    if kind == "array":
        return [_example(schema.get("items") or {}, resolver, depth=depth + 1)]
    if kind == "integer":
        return int(schema.get("minimum") or 1)
    if kind == "number":
        return float(schema.get("minimum") or 1)
    if kind == "boolean":
        return True
    fmt = str(schema.get("format") or "")
    return {"uuid": "00000000-0000-4000-8000-000000000001", "date": "2026-01-01", "date-time": "2026-01-01T00:00:00Z"}.get(fmt, "sample")


def _parameter_value(parameter: dict[str, Any], resolver: _LocalRefResolver) -> Any:
    if "example" in parameter:
        return parameter["example"]
    examples = parameter.get("examples")
    if isinstance(examples, dict) and examples:
        first = resolver.resolve(next(iter(examples.values())))
        if isinstance(first, dict) and "value" in first:
            return first["value"]
    schema = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else parameter
    return _example(schema, resolver)


def _server_url(server: Any) -> tuple[str, list[str]]:
    if not isinstance(server, dict):
        return "", []
    url = str(server.get("url") or "").strip()
    variables = server.get("variables") if isinstance(server.get("variables"), dict) else {}
    unresolved: list[str] = []

    def replace(match: re.Match[str]) -> str:
        item = variables.get(match.group(1)) if isinstance(variables, dict) else None
        if isinstance(item, dict) and item.get("default") is not None:
            return str(item["default"])
        unresolved.append(match.group(1))
        return match.group(0)

    return _SERVER_VARIABLE_RE.sub(replace, url), unresolved


def _swagger_server(document: dict[str, Any]) -> str:
    host = str(document.get("host") or "").strip()
    if not host:
        return ""
    schemes = document.get("schemes") if isinstance(document.get("schemes"), list) else []
    scheme = str(schemes[0] if schemes else "http")
    base_path = "/" + str(document.get("basePath") or "").strip("/") if document.get("basePath") else ""
    return f"{scheme}://{host}{base_path}"


def _security_type(document: dict[str, Any], operation: dict[str, Any]) -> str:
    security = operation.get("security", document.get("security"))
    if security == []:
        return "none"
    if not isinstance(security, list) or not security:
        return "none"
    names = sorted({str(name) for requirement in security if isinstance(requirement, dict) for name in requirement})
    return "declared:" + ",".join(names[:10]) if names else "declared"


def _openapi_body(
    document: dict[str, Any], operation: dict[str, Any], parameters: list[dict[str, Any]], resolver: _LocalRefResolver,
) -> tuple[bytes, str, str | None]:
    request_body = resolver.resolve(operation.get("requestBody"))
    if isinstance(request_body, dict):
        content = request_body.get("content") if isinstance(request_body.get("content"), dict) else {}
        for mime in ("application/json", "application/x-www-form-urlencoded", "text/plain"):
            media = resolver.resolve(content.get(mime))
            if not isinstance(media, dict):
                continue
            value = media.get("example")
            if value is None and isinstance(media.get("examples"), dict) and media["examples"]:
                first = resolver.resolve(next(iter(media["examples"].values())))
                value = first.get("value") if isinstance(first, dict) else first
            if value is None:
                value = _example(media.get("schema") or {}, resolver)
            if mime == "application/json":
                body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
            elif mime == "application/x-www-form-urlencoded" and isinstance(value, dict):
                body = urllib.parse.urlencode(value, doseq=True).encode()
            else:
                body = str(value if value is not None else "").encode()
            return (b"", mime, "request_body_exceeds_512_kib") if len(body) > MAX_BODY_BYTES else (body, mime, None)
    body_parameter = next((item for item in parameters if str(item.get("in")) == "body"), None)
    if body_parameter:
        value = body_parameter.get("x-example", body_parameter.get("example"))
        if value is None:
            value = _example(body_parameter.get("schema") or {}, resolver)
        body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
        consumes = operation.get("consumes") or document.get("consumes") or ["application/json"]
        mime = str(consumes[0]) if isinstance(consumes, list) and consumes else "application/json"
        return (b"", mime, "request_body_exceeds_512_kib") if len(body) > MAX_BODY_BYTES else (body, mime, None)
    form = [(str(item.get("name")), _parameter_value(item, resolver)) for item in parameters if str(item.get("in")) == "formData" and item.get("name")]
    if form:
        body = urllib.parse.urlencode(form, doseq=True).encode()
        return body, "application/x-www-form-urlencoded", None
    return b"", "", None


def _openapi_requests(
    document: Any, *, base_url: Any = None, max_requests: int = MAX_REQUESTS
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(document, dict):
        raise RequestImportError("Encrypted OpenAPI payload is invalid")
    is_swagger = str(document.get("swagger") or "").startswith("2.")
    is_openapi = str(document.get("openapi") or "").startswith("3.")
    if not is_swagger and not is_openapi:
        raise RequestImportError("OpenAPI import must be OpenAPI 3.x or Swagger 2.0")
    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise RequestImportError("OpenAPI import contains no paths")
    override = str(base_url or "").strip().rstrip("/")
    if override:
        parsed_override = urllib.parse.urlsplit(override)
        if parsed_override.scheme not in {"http", "https"} or not parsed_override.hostname or parsed_override.query or parsed_override.fragment:
            raise RequestImportError("base_url must be one absolute HTTP(S) URL without a query or fragment")
    resolver = _LocalRefResolver(document)
    root_server, root_unresolved = ("", [])
    if is_openapi and isinstance(document.get("servers"), list) and document["servers"]:
        root_server, root_unresolved = _server_url(document["servers"][0])
    elif is_swagger:
        root_server = _swagger_server(document)
    requests: list[dict[str, Any]] = []
    for path_name, raw_path_item in paths.items():
        path_item = resolver.resolve(raw_path_item)
        if not isinstance(path_item, dict):
            continue
        for method_name, raw_operation in path_item.items():
            method_lower = str(method_name).lower()
            if method_lower not in HTTP_METHODS:
                continue
            operation = resolver.resolve(raw_operation)
            if not isinstance(operation, dict):
                continue
            if len(requests) >= max_requests:
                raise RequestImportError(f"OpenAPI import exceeds the {max_requests}-operation limit")
            server, unresolved = root_server, list(root_unresolved)
            if is_openapi and isinstance(path_item.get("servers"), list) and path_item["servers"]:
                server, unresolved = _server_url(path_item["servers"][0])
            if is_openapi and isinstance(operation.get("servers"), list) and operation["servers"]:
                server, unresolved = _server_url(operation["servers"][0])
            if override:
                server, unresolved = override, []
            parameters: list[dict[str, Any]] = []
            keyed: dict[tuple[str, str], dict[str, Any]] = {}
            for raw_parameter in list(path_item.get("parameters") or []) + list(operation.get("parameters") or []):
                parameter = resolver.resolve(raw_parameter)
                if isinstance(parameter, dict):
                    keyed[(str(parameter.get("name") or ""), str(parameter.get("in") or ""))] = parameter
            parameters = list(keyed.values())
            rendered_path = str(path_name)
            query: list[tuple[str, str]] = []
            headers: dict[str, str] = {}
            for parameter in parameters:
                name = str(parameter.get("name") or "")
                location = str(parameter.get("in") or "")
                if not name:
                    continue
                value = _parameter_value(parameter, resolver)
                value_text = str(value if value is not None else "sample")
                if location == "path":
                    rendered_path = rendered_path.replace("{" + name + "}", urllib.parse.quote(value_text, safe=""))
                elif location == "query":
                    query.append((name, value_text))
                elif location == "header" and not any(ch in name for ch in "\r\n:") and "\r" not in value_text and "\n" not in value_text:
                    headers[name] = value_text
            url = (server.rstrip("/") + "/" + rendered_path.lstrip("/")) if server else "/" + rendered_path.lstrip("/")
            if query:
                url += ("&" if "?" in url else "?") + urllib.parse.urlencode(query)
            body, content_type, body_error = _openapi_body(document, operation, parameters, resolver)
            if body and content_type:
                headers.setdefault("Content-Type", content_type)
            method = method_lower.upper()
            auth_type = _security_type(document, operation)
            unresolved += re.findall(r"\{([^{}]+)\}", rendered_path)
            requests.append({
                "id": _request_id("openapi", len(requests), method, f"{path_name}:{operation.get('operationId', '')}"),
                "name": str(operation.get("summary") or operation.get("operationId") or f"{method} {path_name}")[:300],
                "folder": "OpenAPI" if is_openapi else "Swagger",
                "method": method,
                "url": url,
                "url_template": str(path_name),
                "headers": headers,
                "sensitive_header_names": sorted(key.lower() for key in headers if _SENSITIVE_NAME_RE.search(key)),
                "body": body,
                "body_mode": content_type or "none",
                "auth_type": auth_type,
                "tags": [
                    str(tag).strip()[:120]
                    for tag in list(operation.get("tags") or [])[:200]
                    if str(tag).strip()
                ],
                "has_sensitive_material": any(_SENSITIVE_NAME_RE.search(key) for key in headers),
                "unresolved_variables": sorted(set(unresolved)),
                "error": body_error,
            })
    return requests, {
        "spec_version": str(document.get("openapi") or document.get("swagger") or ""),
        "external_refs_ignored": resolver.external_refs_ignored,
        "invalid_refs_ignored": resolver.invalid_refs_ignored,
    }


def _validate_openapi(
    document: Any, *, requested_name: str | None, base_url: str | None,
    max_requests: int = MAX_REQUESTS, max_document_bytes: int = MAX_COLLECTION_BYTES,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(document, dict):
        raise RequestImportError("OpenAPI import must be one JSON object")
    if _json_size(document) > max_document_bytes:
        raise RequestImportError(f"OpenAPI import exceeds the {max_document_bytes}-byte limit")
    requests, metadata = _openapi_requests(
        document, base_url=base_url, max_requests=max_requests
    )
    if not requests:
        raise RequestImportError("OpenAPI import contains no supported operations")
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    name = str(requested_name or info.get("title") or "Imported OpenAPI specification").strip()[:160]
    payload = {"format": "openapi", "document": document, "base_url": str(base_url or "").strip() or None}
    summary = _summary(
        name=name,
        format_name="openapi",
        requests=requests,
        digest=_digest(payload),
        extra={
            **metadata,
            "scripts_ignored": 0,
            "environment_variable_names": [],
            "collection_variable_names": [],
            "generated_examples": True,
        },
    )
    return payload, summary


def _summary(
    *, name: str, format_name: str, requests: list[dict[str, Any]], digest: str, extra: dict[str, Any],
) -> dict[str, Any]:
    methods = Counter(str(item.get("method") or "") for item in requests)
    port_hints = sorted({port for item in requests if (port := _port_hint(str(item.get("url") or ""))) is not None})
    public_requests = []
    for item in requests:
        method = str(item.get("method") or "")
        public_requests.append({
            "id": item.get("id"),
            "name": item.get("name"),
            "folder": item.get("folder"),
            "method": method,
            "url": public_request_url(str(item.get("url") or "")),
            "header_names": sorted(str(key)[:120] for key in (item.get("headers") or {}))[:MAX_HEADERS],
            "body_mode": str(item.get("body_mode") or "none")[:100],
            "auth_type": str(item.get("auth_type") or "none")[:200],
            "safe_method": method in SAFE_METHODS,
            "supported": method in SUPPORTED_METHODS and bool(item.get("url")) and not item.get("error") and not item.get("unresolved_variables"),
        })
    return {
        "schema_version": "device-request-collection/v1",
        "name": name,
        "format": format_name,
        "document_sha256": digest,
        "request_count": len(requests),
        "safe_request_count": sum(1 for item in public_requests if item["safe_method"]),
        "state_changing_request_count": sum(1 for item in public_requests if item["method"] in STATE_CHANGING_METHODS),
        "unsupported_request_count": sum(1 for item in public_requests if not item["supported"]),
        "methods": dict(sorted(methods.items())),
        "port_hints": port_hints,
        "requests": public_requests,
        "secrets_redacted": True,
        **extra,
    }
