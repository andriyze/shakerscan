"""Injection and access-control findings: the request, the parameter, the differential and the fix."""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Mapping

from .common import command, display_url, fact, facts, integer, join_limited, origin_of, q, record, strings, text

_SQL_FIX = [
    ("Python (DB-API)", 'cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))'),
    ("Node.js (pg)", "await client.query('SELECT * FROM products WHERE id = $1', [productId])"),
    ("Java (JDBC)", 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM products WHERE id = ?");\nps.setString(1, productId);'),
    ("PHP (PDO)", '$stmt = $pdo->prepare("SELECT * FROM products WHERE id = ?");\n$stmt->execute([$productId]);'),
]

_XSS_FIX = [
    ("React / JSX", "{userValue}  // escaped by default; never dangerouslySetInnerHTML with input"),
    ("DOM", "element.textContent = value  // not innerHTML / outerHTML / document.write"),
    ("Jinja2 / Django", "{{ value }}  // autoescape on; never |safe or mark_safe on input"),
    ("PHP", "echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8');"),
]


def _pairs(evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for pair in list(evidence.get("response_pairs") or ())[:6]:
        pair = record(pair)
        control, payload = pair.get("control_status"), pair.get("payload_status")
        if control is None and payload is None:
            continue
        rows.append({"control": text(control, 40), "payload": text(payload, 40)})
    return rows


def _location(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> tuple[str, str, str]:
    # Request-body differentials carry no URL, only the origin the request went to.
    url = text(evidence.get("request_url") or evidence.get("url") or finding.get("url") or evidence.get("origin"), 800)
    if url.startswith("/") and finding.get("target_url"):
        url = text(finding.get("target_url"), 400).rstrip("/") + url
    method = text(evidence.get("method"), 12).upper() or "GET"
    parameter = text(evidence.get("field_path") or evidence.get("parameter_name") or evidence.get("param") or evidence.get("parameter"), 200)
    return url, method, parameter


def _with_value(url: str, parameter: str, value: str, name: str = "") -> str:
    """``url`` with query ``parameter`` set to ``value``, sent as ``name`` when given (other parameters kept)."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    sent = name or parameter
    query = [(k, v) for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True) if k not in {parameter, sent}]
    query.append((sent, value))
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))


# A path-segment candidate reaches sqlmap with its custom injection marker after the segment value
# (/products/1*), and sqlmap names that injection point "#1*"; neither belongs to the application.
_SQLMAP_MARKER_NAME = re.compile(r"#(\d+)\*")
# A proof row keeps the route (/products/{int}) and names the segment path_N. The values are the
# ones a Scan puts in a templated segment when it requests the route, so the command sends what the
# proof sent.
_PATH_FIELD = re.compile(r"path_(\d+)")
_SEGMENT_SAMPLES = {"{int}": "1", "{uuid}": "00000000-0000-4000-8000-000000000000"}


def _path_injection(url: str, parameter: str) -> tuple[str, str, str] | None:
    """(URL to show, parameter name, URL with a quote in the segment) for an injectable path segment.

    The segment is not a query parameter, so setting one in the query tests nothing.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    segments = parsed.path.split("/")
    marker, field = _SQLMAP_MARKER_NAME.fullmatch(parameter), _PATH_FIELD.fullmatch(parameter)
    if marker:
        marked = [index for index, segment in enumerate(segments) if segment.endswith("*")]
        if not 1 <= int(marker.group(1)) <= len(marked):
            return None
        index = marked[int(marker.group(1)) - 1]
        shown = sent = [segment.rstrip("*") for segment in segments]
    elif field and 0 < int(field.group(1)) < len(segments) and segments[int(field.group(1))] in _SEGMENT_SAMPLES:
        index, shown = int(field.group(1)), segments
        sent = [_SEGMENT_SAMPLES.get(segment, segment) for segment in segments]
    else:
        return None
    quoted = [*sent[:index], sent[index] + "%27", *sent[index + 1:]]
    rebuilt = [urllib.parse.urlunsplit(parsed._replace(path="/".join(path))) for path in (shown, quoted)]
    return rebuilt[0], f"path_{index}", rebuilt[1]


# sqlmap's --batch prompt, which older scans stored as the DBMS: "it looks like the back-end DBMS is
# 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y".
_SQLMAP_DBMS_PROMPT = re.compile(r"back-end DBMS is '([^']{1,60})'")

_DBMS_MARKERS = (
    ("SQLite", ("sqlite",)), ("PostgreSQL", ("postgres", "pg_", "psql", "pgsql")),
    ("MySQL / MariaDB", ("mysql", "mariadb")), ("Microsoft SQL Server", ("microsoft sql", "mssql", "sqlserver", "odbc sql server")),
    ("Oracle", ("ora-", "oracle")),
)


def dbms_from(signatures: list[str], excerpt: str) -> str:
    haystack = " ".join(signatures + [excerpt]).lower()
    return next((name for name, markers in _DBMS_MARKERS if any(marker in haystack for marker in markers)), "")


def build_sqli(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    raw_url, method, parameter = _location(finding, evidence)
    path_point = _path_injection(raw_url, parameter) if method == "GET" else None
    if path_point:
        raw_url, parameter, quoted_url = path_point
    url = display_url(raw_url)
    verified = finding.get("proof_state") == "verified" or finding.get("verified") is True
    signatures = strings(evidence.get("database_error_signatures"), 6, 200)
    stored_dbms = text(evidence.get("dbms"), 300)
    prompt = _SQLMAP_DBMS_PROMPT.search(stored_dbms)
    dbms = (prompt.group(1) if prompt else stored_dbms[:60]) or dbms_from(signatures, text(evidence.get("redacted_excerpt"), 1200))
    timing = record(evidence.get("timing_ms"))
    technique = text(evidence.get("technique"), 80).replace("_", " ")
    reps = integer(evidence.get("repetitions"))
    bypass = "bypass" in text(finding.get("title")).lower()
    pairs = _pairs(evidence)
    where = facts(fact("Endpoint", f"{method} {url}", mono=True), fact("Parameter", parameter, mono=True),
                  fact("Request part", evidence.get("request_class"), mono=True))
    summary = (
        f"The {parameter or 'request'} parameter of {method} {url} reaches a database query unescaped"
        + (f" ({dbms})" if dbms else "") + "."
        if verified else
        f"A database error appeared when {parameter or 'a parameter'} of {method} {url} was mutated; injection is not proven yet."
    )
    if bypass:
        summary = f"Login at {method} {url} accepts a SQL injection in {parameter or 'a field'} instead of a password: anyone can sign in."
    observed = facts(
        fact("Technique", technique), fact("Payload sent", evidence.get("payload_shape"), mono=True),
        fact("Response time (median)", f"control {timing.get('control_median')} ms, payload {timing.get('payload_median')} ms" if timing else ""),
        fact("Confirmed", f"{reps} independent repetitions" if reps else ""),
        fact("Database", dbms), fact("Database error", join_limited(signatures, 3), mono=True),
        fact("Tool message", evidence.get("sqlmap_message"), mono=True),
        fact("Control / candidate status", " / ".join(str(v) for v in (evidence.get("control_status"), evidence.get("candidate_status")) if v is not None), mono=True),
    )
    excerpt = text(evidence.get("redacted_excerpt"), 1200)
    reproduce = None
    if method == "GET" and parameter and raw_url.startswith(("http://", "https://")) and "." not in parameter:
        reproduce = command(
            f"curl -sS {q(quoted_url if path_point else _with_value(raw_url, parameter, chr(39)))} | grep -iE 'sql|syntax|database|ORA-|SQLITE'",
            expect="a database error for the single quote, none for a normal value",
            note="One harmless quote; do not run destructive payloads against production.",
        )
    elif parameter:
        # The request and parameter are target-chosen, so they are printed as quoted words; the
        # comment line stays fixed text (an interactive zsh does not read "#" as a comment).
        reproduce = command(
            "# Send this request with the parameter set to a single quote, then to a normal value, and compare:\n"
            f"printf '%s\\n' {q(f'{method} {url}')} {q(f'parameter: {parameter}')}",
            note="The finding stores the request shape, not a replayable body; the Retest button replays it.",
        )
    return {
        "class": "injection.sqli" if verified else "injection.sqli_candidate",
        "class_label": "SQL injection" + ("" if verified else " (candidate)"),
        "summary": summary,
        "where": where,
        "observed": observed,
        "pairs": pairs,
        "excerpt": {"label": "Response excerpt (redacted by the scanner)", "text": excerpt} if excerpt else None,
        "expected": ["The same response for the payload and the control value, and no database error text."],
        "context": [
            "With SQL injection an attacker can usually read any table the application's database user can, and often modify data.",
        ] + (["Error messages from the database are shown to users, which makes exploitation faster."] if signatures else []),
        "reproduce": reproduce,
        "verify": reproduce and {**reproduce, "expect": "no database error and an ordinary not-found or validation response"},
        "fix": [
            f"Pass {parameter or 'the value'} to the database as a bound parameter (prepared statement), never by building the SQL string.",
            "Run the application with a database account that can access only what it needs.",
            "Return a generic error page; log database errors server-side.",
        ],
        "examples": [{"label": label, "code": code} for label, code in _SQL_FIX],
    }


def build_nosqli(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    url, method, parameter = _location(finding, evidence)
    operator = text(evidence.get("operator"), 30)
    bypass = "bypass" in text(finding.get("title")).lower()
    # The proof sends the operator where the request carries the field: as query brackets
    # (field[$ne]=x) for a GET or HEAD with no stored request, in the stored request's body otherwise.
    in_query = method in {"GET", "HEAD"} and not evidence.get("request_ref_id")
    if in_query:
        field = parameter or "field"
        bracketed = f"{field}[{operator or '$ne'}]"
        reproduce = command(f"curl -sS {q(_with_value(url, field, 'x', name=bracketed))}",
                            note=f"Compare with the same request with {field}=x, an ordinary string value.")
    else:
        reproduce = command(f"curl -sS -X {q(method)} {q(url)} -H 'content-type: application/json' -d {q('{' + chr(34) + (parameter or 'field') + chr(34) + ':{' + chr(34) + (operator or '$ne') + chr(34) + ':null}}')}",
                            note="Compare with the same request using an ordinary string value.")
    return {
        "class": "injection.nosqli",
        "class_label": "NoSQL operator injection",
        "summary": (f"{method} {url} accepts a query operator{f' ({operator})' if operator else ''} in {parameter or 'a field'}"
                    + (": the login succeeds without the password." if bypass else ", which changes the database query.")),
        "where": facts(fact("Endpoint", f"{method} {url}", mono=True), fact("Parameter", parameter, mono=True)),
        "observed": facts(fact("Operator", operator, mono=True), fact("Technique", text(evidence.get("technique")).replace("_", " ")),
                          fact("Confirmed", f"{integer(evidence.get('repetitions'))} independent repetitions" if integer(evidence.get("repetitions")) else "")),
        "pairs": _pairs(evidence),
        "expected": ["Operators in input rejected or treated as literal strings; the response identical to the control."],
        "context": ["Operator injection lets an attacker change query logic: match any record, skip the password check, or enumerate data."],
        "reproduce": reproduce,
        "fix": ["Validate that each field has the expected type (a string, not an object) before it reaches the query.",
                "Use the driver's sanitizer (mongo-sanitize / express-mongo-sanitize) or reject keys starting with $."],
        "examples": [{"label": "Express", "code": f"if (typeof req.{'query' if in_query else 'body'}.username !== 'string') return res.status(400).end()"}],
    }


def build_xss(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    url, _method, parameter = _location(finding, evidence)
    verified = finding.get("proof_state") == "verified" or finding.get("verified") is True
    location = text(evidence.get("injection_location"), 60).replace("_", " ")
    technique = text(evidence.get("technique"), 60).replace("headless_xss_", "").replace("_", " ")
    transcript = strings(evidence.get("event_transcript"), 6, 200)
    related = strings(evidence.get("related_request_urls"), 5, 400)
    stored = bool(related)
    summary = (
        f"Input in {parameter or 'the request'}{f' ({location})' if location else ''} is placed into the page of {origin_of(url) or url} "
        + ("as markup, and a test script executed in a real browser." if verified else "without encoding; execution is not proven yet.")
    )
    out = {
        "class": "injection.xss" if verified else "injection.xss_candidate",
        "class_label": ("Stored" if stored else "Reflected" if location != "dom" else "DOM") + " cross-site scripting" + ("" if verified else " (candidate)"),
        "summary": summary,
        "where": facts(fact("Page", url, mono=True), fact("Parameter", parameter, mono=True), fact("Injection point", location),
                       fact("Client route", record(evidence.get("browser_alert")).get("client_route"), mono=True),
                       fact("Where it executed", join_limited(related, 2), mono=True)),
        "observed": facts(fact("Execution signal", technique or text(evidence.get("message"), 200)),
                          fact("Browser events", join_limited(transcript, 4), mono=True),
                          fact("Verifier", evidence.get("browser_build") or evidence.get("canonical_capability"), mono=True)),
        "expected": ["The input rendered as text (HTML-encoded), and no script execution."],
        "context": [
            "A script running on this origin acts as the signed-in user: it can read pages, submit forms and send data elsewhere."
            + (" Session cookies without HttpOnly are directly readable." if verified else ""),
        ],
        # The URL is target-chosen (a crawled path can hold $(...)), so it is never a bare shell
        # line: pasted, the command only prints it.
        "reproduce": command(
            f"# Open this URL in a browser you are willing to test with:\nprintf '%s\\n' {q(url)}"
            if url.startswith(("http://", "https://")) else "# Retest replays the stored request.",
            note="The page the scanner sent the input to"
                 + ("; the pages where it ran are under Where it executed" if stored else "")
                 + ". Stored evidence keeps this URL without the values the scanner injected, so opening it "
                   "does not replay the payload; Retest replays the stored request.",
        ),
        "fix": [
            f"Encode {parameter or 'the value'} for the context it is written into (HTML text, attribute, JavaScript or URL) when rendering.",
            "Avoid sinks that parse HTML (innerHTML, document.write, dangerouslySetInnerHTML, |safe).",
            "Add a Content-Security-Policy without 'unsafe-inline' as a second layer.",
        ],
        "examples": [{"label": label, "code": code} for label, code in _XSS_FIX],
    }
    return out


def build_authz(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    tool = text(finding.get("tool"), 60)
    url = text(evidence.get("url") or evidence.get("request_url") or finding.get("url"), 600)
    if tool == "smart_authz":
        obj = record(evidence.get("object"))
        return {
            "class": "access.bola",
            "class_label": "Broken object-level authorization",
            "summary": f"A second account could read an object that belongs to the first account at {url}.",
            "where": facts(fact("Object URL", url, mono=True), fact("Found via", evidence.get("producer_url"), mono=True),
                           fact("Object id", " in ".join(text(obj.get(key), 120) for key in ("id_key", "id_location") if obj.get(key)), mono=True),
                           fact("Sensitive fields", join_limited(strings(obj.get("sensitive_field_names"), 20, 80), 6), mono=True)),
            "observed": facts(fact("Owner response", evidence.get("owner_status"), mono=True),
                              fact("Other account's response", evidence.get("attacker_status"), mono=True),
                              fact("Responses equivalent", "yes" if evidence.get("responses_equivalent") else "")),
            "expected": ["403 or 404 for the account that does not own the object."],
            "context": ["Every object of this type is probably readable by any signed-in user who changes the identifier."],
            "reproduce": command(f"curl -sS -o /dev/null -w '%{{http_code}}\\n' -H 'Authorization: <second account>' {q(url)}",
                                 expect="200 with the first account's data"),
            "fix": ["Check on every request that the object belongs to (or is shared with) the requesting user, in the data-access layer.",
                    "Prefer queries scoped by owner (WHERE id = ? AND owner_id = ?) over a lookup by id alone."],
        }
    return {
        "class": "access.anonymous_parity",
        "class_label": "Same data with and without credentials",
        "summary": f"{url} returned the same data to an anonymous request as to a signed-in user.",
        "where": facts(fact("URL", url, mono=True)),
        "observed": facts(fact("Anonymous response", evidence.get("anonymous_status"), mono=True),
                          fact("Authenticated response", evidence.get("authenticated_status"), mono=True),
                          fact("Confirmed", f"{integer(evidence.get('repetitions'))} repetitions" if integer(evidence.get("repetitions")) else "")),
        "expected": ["401/403 for anonymous requests if this function is meant to be private."],
        "context": ["Only a flaw if this data is meant for signed-in users; public catalogues and help pages behave this way on purpose."],
        "reproduce": command(f"curl -sS -o /dev/null -w '%{{http_code}} %{{size_download}}\\n' {q(url)}", expect="the same status and size as when signed in"),
        "fix": ["If the endpoint is private, require authentication on it (and on its siblings); otherwise mark the finding accepted risk."],
    }


__all__ = ["build_authz", "build_nosqli", "build_sqli", "build_xss"]
