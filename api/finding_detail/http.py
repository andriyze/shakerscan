"""Response-header and cookie findings: the recorded response, the expected header and a stack fix."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .common import command, detected_stack, fact, facts, origin_of, q, record, text

# header -> (display name, recommended value, what it protects)
HEADERS: Mapping[str, tuple[str, str, str]] = {
    "content-security-policy": (
        "Content-Security-Policy",
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        "Limits which scripts, frames and resources the page may load, so an injected script cannot run or load attacker code.",
    ),
    "strict-transport-security": (
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
        "Tells browsers to use HTTPS only for this host, so a user's first plain-HTTP request cannot be intercepted and downgraded.",
    ),
    "referrer-policy": (
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
        "Controls how much of the page URL is sent to other sites in the Referer header.",
    ),
    "permissions-policy": (
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
        "Disables browser features (camera, microphone, location) the site does not use.",
    ),
    "x-frame-options": (
        "X-Frame-Options",
        "DENY",
        "Stops other sites from framing these pages (clickjacking). CSP frame-ancestors is the modern equivalent.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        "nosniff",
        "Stops browsers from guessing a different content type, e.g. running an uploaded text file as script.",
    ),
    "cross-origin-opener-policy": ("Cross-Origin-Opener-Policy", "same-origin", "Isolates the page's browsing context from cross-origin windows."),
    "cross-origin-embedder-policy": ("Cross-Origin-Embedder-Policy", "require-corp", "Requires embedded resources to opt in to being loaded."),
    "cross-origin-resource-policy": ("Cross-Origin-Resource-Policy", "same-origin", "Stops other origins from embedding this response."),
}


# A frame-ancestors source worth copying from the observed policy into an example: 'none',
# 'self', or one named host with its scheme. Scheme sources (https:, data:) and wildcard hosts
# (*.com) let many sites frame the page, and anything else could break out of the snippet, so
# those fall back to the recommended 'self'.
_SAFE_FRAME_SOURCE = re.compile(
    r"'(?:none|self)'|https?://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,20}(?::\d{1,5})?/?",
    re.IGNORECASE,
)


def _observed_frame_ancestors(policy: str) -> str:
    """The observed CSP frame-ancestors sources when they already restrict framing, else ""."""
    for part in policy.split(";"):
        tokens = part.split()
        if tokens and tokens[0].lower() == "frame-ancestors":
            sources = tokens[1:]
            if sources and all(_SAFE_FRAME_SOURCE.fullmatch(token) for token in sources):
                return " ".join(sources)
            return ""
    return ""


def _stack_example(stack: str | None, header: str, value: str) -> list[dict[str, str]]:
    examples = {
        "nginx": ("nginx", f'add_header {header} "{value}" always;'),
        "apache": ("Apache httpd", f'Header always set {header} "{value}"'),
        "iis": ("IIS web.config", f'<httpProtocol><customHeaders><add name="{header}" value="{value}" /></customHeaders></httpProtocol>'),
        "caddy": ("Caddy", f'header {header} "{value}"'),
        "express": ("Express", f"app.use((req, res, next) => {{ res.setHeader('{header}', \"{value}\"); next() }})  // or helmet()"),
        "php": ("PHP", f"header('{header}: {value}');"),
        "tomcat": ("Tomcat / Spring", f'Spring Security: http.headers(...) or a Filter that sets response.setHeader("{header}", "{value}")'),
        "werkzeug": ("Python (Flask/Django)", f'response.headers["{header}"] = "{value}"  # Django: SECURE_* settings / middleware'),
    }
    order = [stack] if stack in examples else []
    order += [name for name in ("nginx", "apache", "express", "iis") if name not in order]
    return [{"label": examples[name][0], "code": examples[name][1]} for name in order[:4]]


def build_missing_header(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    header = text(evidence.get("header") or evidence.get("header_absent") or evidence.get("header_name"), 80).lower()
    if not header:
        header = text(evidence.get("check"), 120).removeprefix("missing_header_").lower()
    display, value, purpose = HEADERS.get(header, (header.title(), "", "A browser security header."))
    observed = record(evidence.get("observed_response"))
    url = text(evidence.get("url") or evidence.get("matched_at") or finding.get("url"), 400)
    origin = origin_of(url) or url
    # A recorded error page (older findings carried the root's 404) is not the response that lacked
    # the header: show none, and point the commands at a page the check matched.
    observed_status = observed.get("response_status")
    if isinstance(observed_status, int) and not 200 <= observed_status < 400:
        observed = {}
    if not observed:
        url = text((evidence.get("matched_urls") or [None])[0], 400) or url
    headers = {str(k).lower(): v for k, v in record(observed.get("observed_headers")).items()}
    status = observed.get("response_status") or evidence.get("status")
    request_line = text(observed.get("request_line"), 300)
    stack = detected_stack(headers)
    context: list[str] = []
    csp = text(headers.get("content-security-policy"), 2000)
    if header == "x-frame-options" and "frame-ancestors" in csp:
        context.append("The response already sets CSP frame-ancestors, which modern browsers use instead of X-Frame-Options: the remaining risk is limited to very old browsers.")
    if header == "strict-transport-security" and url.startswith("http://"):
        context.append("This origin is plain HTTP, where browsers ignore HSTS: the issue that matters is serving the site without HTTPS. Redirect it to HTTPS and send HSTS there.")
    matched = int(evidence.get("matched_url_count") or 0)
    if matched > 1:
        context.append(f"{matched} scanned pages on this origin lacked the header; it is reported once per origin.")
    content_type = text(headers.get("content-type"), 120)
    if header == "content-security-policy" and content_type and "html" not in content_type:
        context.append(f"The recorded response is {content_type}, not HTML; CSP matters most on HTML pages.")
    present = [name for name in sorted(headers) if name in HEADERS or name in {"server", "x-powered-by"}]
    observed_facts = facts(
        fact("Request", request_line, mono=True),
        fact("Response status", status, mono=True),
        fact("Server", headers.get("server"), mono=True),
        fact("X-Powered-By", headers.get("x-powered-by"), mono=True),
        fact("Security headers present", ", ".join(name for name in present if name in HEADERS) or "none", mono=True),
    )
    curl = f"curl -sS -o /dev/null -D - {q(url or origin)} | grep -i {q('^' + header + ':')}"
    return {
        "class": "header.missing",
        "class_label": f"Missing {display} header",
        "summary": f"{origin} answered{f' {status}' if status else ''} without a {display} header. {purpose}",
        "where": facts(fact("Origin", origin, mono=True), fact("Example page", (evidence.get("matched_urls") or [None])[0] if matched > 1 else "", mono=True)),
        "observed": observed_facts,
        "expected": [f"{display}: {value}" if value else f"A {display} header on every HTML response."],
        "context": context,
        "reproduce": command(curl, expect="no output: the header is absent"),
        "verify": command(curl, expect=f"{display}: {value}" if value else f"a {display} line"),
        "fix": [f"Send {display} on every response from {origin}{' (detected server: ' + stack + ')' if stack else ''}."]
               + (["Start with Content-Security-Policy-Report-Only to find what the policy would block, then enforce it."] if header == "content-security-policy" else [])
               + (["Add includeSubDomains only when every subdomain serves HTTPS; preload only after that."] if header == "strict-transport-security" else []),
        "examples": _stack_example(stack, display, value) if value else [],
        "stack": stack,
    }


def build_weak_header(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    """A security header that is present but whose value leaves its protection open."""
    header = text(evidence.get("header"), 80).lower() or text(evidence.get("check"), 120).removeprefix("weak_header_")
    display, value, purpose = HEADERS.get(header, (header.title(), "", "A browser security header."))
    observed = record(evidence.get("observed_response"))
    headers = {str(k).lower(): v for k, v in record(observed.get("observed_headers")).items()}
    url = text(evidence.get("url") or finding.get("url"), 400)
    origin = origin_of(url) or url
    current = text(evidence.get("observed_value"), 2000) or text(headers.get(header), 2000)
    issues = [record(item) for item in evidence.get("issues") or () if isinstance(item, Mapping)]
    expected = text(evidence.get("expected_value"), 600) or value
    # A policy that already restricts framing keeps its own frame-ancestors: recommending 'self'
    # in place of an observed 'none' would loosen the protection while fixing something else.
    framing = _observed_frame_ancestors(current) if header == "content-security-policy" else ""
    if framing:
        value = value.replace("frame-ancestors 'self'", f"frame-ancestors {framing}")
        expected = expected.replace("frame-ancestors 'self'", f"frame-ancestors {framing}")
    # Some expectations describe a value ("DENY or SAMEORIGIN", "nonces or hashes"); only one that is
    # the recommended value itself is a header line the check can print.
    literal = bool(expected) and expected == value
    stack = detected_stack(headers)
    curl = f"curl -sS -o /dev/null -D - {q(url or origin)} | grep -i {q('^' + header + ':')}"
    return {
        "class": "header.weak_value",
        "class_label": f"Weak {display} value",
        "summary": f"{origin} sends {display}, but its value is weak: " + " ".join(text(item.get("text"), 300) for item in issues[:3]),
        "where": facts(fact("Origin", origin, mono=True), fact("Header", display, mono=True)),
        "observed": facts(
            fact(f"{display} (as sent)", current, mono=True, limit=2000),
            fact("Request", observed.get("request_line"), mono=True),
            fact("Response status", observed.get("response_status") or evidence.get("status"), mono=True),
            fact("Server", headers.get("server"), mono=True),
        ),
        "expected": [f"{display}: {expected}" if literal else f"{display} — {expected}"] if expected else [],
        "context": [text(item.get("text"), 400) for item in issues] + [purpose],
        "reproduce": command(curl, expect=f"{display}: {current[:120]}"),
        "verify": command(curl, expect=f"{display}: {expected[:160]}" if literal else f"a {display} line without the weaknesses listed above"),
        "fix": [f"Change the {display} value sent by {origin}{' (detected server: ' + stack + ')' if stack else ''}: {expected}."]
               + (["Replace inline scripts with external files or add a per-response nonce, then drop 'unsafe-inline'; test with Content-Security-Policy-Report-Only first."] if header == "content-security-policy" else [])
               + (["Raise max-age to at least 15552000 (180 days), ideally 31536000; add includeSubDomains once every subdomain serves HTTPS."] if header == "strict-transport-security" else []),
        "examples": _stack_example(stack, display, value) if value else [],
        "stack": stack,
    }


_COOKIE_EXAMPLES = (
    ("Express (express-session)", "session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' } })"),
    ("PHP (php.ini)", "session.cookie_secure = 1\nsession.cookie_httponly = 1\nsession.cookie_samesite = Lax"),
    ("Django", "SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = 'Lax'"),
    ("Java (web.xml)", "<session-config><cookie-config><http-only>true</http-only><secure>true</secure></cookie-config></session-config>"),
    ("nginx proxy", "proxy_cookie_flags NAME secure httponly samesite=lax;"),
)


def build_cookie(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    name = text(evidence.get("cookie_name"), 120)
    flags = record(evidence.get("cookie_flags"))
    check = text(evidence.get("check"), 80)
    missing = "HttpOnly" if check.endswith("httponly") else "Secure"
    url = text(evidence.get("url") or finding.get("url"), 400)
    origin = origin_of(url) or url

    def flag(value: Any) -> str:
        return "set" if value is True else "not set" if value is False else "not recorded"

    samesite = text(flags.get("samesite"), 20)
    context = []
    if missing == "HttpOnly":
        context.append(f"Any script that runs on {origin} — including an injected one — can read {name} through document.cookie and send it elsewhere.")
    else:
        context.append(f"Without Secure the browser also sends {name} over plain HTTP to this host, where anyone on the network path can read it.")
    if not samesite:
        context.append("SameSite is not set either; browsers then default to Lax, which still sends the cookie on top-level cross-site navigations.")
    curl = f"curl -sS -o /dev/null -D - {q(url or origin)} | grep -i {q('^set-cookie: ' + name + '=')}"
    examples = [{"label": label, "code": code.replace("NAME", name)} for label, code in _COOKIE_EXAMPLES]
    return {
        "class": f"cookie.missing_{missing.lower()}",
        "class_label": f"Session cookie without {missing}",
        "summary": f"{origin} sets the session cookie {name} without the {missing} attribute.",
        "where": facts(fact("Origin", origin, mono=True), fact("Cookie", name, mono=True)),
        "observed": facts(
            fact("Secure", flag(flags.get("secure"))), fact("HttpOnly", flag(flags.get("httponly"))),
            fact("SameSite", samesite or "not set"), fact("Response status", evidence.get("status"), mono=True),
            fact("Cookie value", "never stored by the scanner"),
        ),
        "expected": [f"Set-Cookie: {name}=…; Path=/; Secure; HttpOnly; SameSite=Lax"],
        "context": context,
        "reproduce": command(curl, expect=f"a Set-Cookie line for {name} without {missing}"),
        "verify": command(curl, expect=f"the Set-Cookie line for {name} includes {missing}"),
        "fix": [f"Set {missing} on {name} where the application creates its session cookie, together with "
                f"{'HttpOnly' if missing == 'Secure' else 'Secure'} and SameSite=Lax."],
        "examples": examples,
    }


__all__ = ["HEADERS", "build_cookie", "build_missing_header", "build_weak_header"]
