"""DOM-XSS leads in a script: an attacker-controlled source shortly before an HTML or code sink.

Ported from the removed ``scanner_tools/dom_xss_analyzer`` (which nothing called): its source and
sink signatures, paired here by distance in characters rather than lines, because production
bundles are minified onto one line. A lead is a reason to run the browser proof (``xss.verify``,
``deep_domxss`` for a URL parameter, a client-route fragment for ``location.hash``), never a finding:
static pairing cannot tell whether the value is encoded on the way.
"""
from __future__ import annotations

import re
from typing import Any

WINDOW = 300
ARGUMENT = 120
MAX_LEADS = 12

_SOURCES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("location.hash", re.compile(r"location\.hash\b")),
    ("location.search", re.compile(r"location\.search\b")),
    ("location.href", re.compile(r"location\.href\b(?!\s*=[^=])")),
    ("document.URL", re.compile(r"document\.(?:URL|documentURI)\b")),
    ("document.referrer", re.compile(r"document\.referrer\b")),
    ("window.name", re.compile(r"window\.name\b(?!\s*=[^=])")),
    ("url_parameter", re.compile(r"""\.get\(\s*['"]([A-Za-z0-9_\-]{1,64})['"]\s*\)""")),
    ("postMessage", re.compile(r"""addEventListener\(\s*['"]message['"]|\bonmessage\s*=""")),
)
_SINKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("innerHTML", re.compile(r"\.(?:inner|outer)HTML\s*\+?=(?!=)")),
    ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(")),
    ("document.write", re.compile(r"document\.write(?:ln)?\s*\(")),
    ("eval", re.compile(r"(?<![\w.$])eval\s*\(")),
    ("Function", re.compile(r"\bnew\s+Function\s*\(|(?<![\w.$])Function\s*\(")),
    ("timer_string", re.compile(r"""set(?:Timeout|Interval)\s*\(\s*['"`]""")),
    ("jquery_html", re.compile(r"""\.(?:html|append|prepend|after|before)\s*\(\s*[A-Za-z_$]""")),
    ("location_assign", re.compile(r"(?<![\w.$])(?:window\.|document\.)?location(?:\.href)?\s*=(?!=)")),
)
_PARAM = re.compile(r"""\.get\(\s*['"]([A-Za-z0-9_\-]{1,64})['"]\s*\)""")


def dom_xss_leads(text: str) -> list[dict[str, Any]]:
    """``{source, sink, parameter}`` for each sink with a source in the ``WINDOW`` characters before it
    or the first ``ARGUMENT`` characters after it (its argument).

    ``parameter`` is the URL parameter the source reads (``URLSearchParams.get('q')``), when it names
    one. The same (source, sink, parameter) is listed once; at most ``MAX_LEADS``.
    """
    text = str(text or "")
    sources = [(match.start(), name, match) for name, pattern in _SOURCES for match in pattern.finditer(text)]
    if not sources:
        return []
    sources.sort(key=lambda item: item[0])
    leads: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for sink, pattern in _SINKS:
        for match in pattern.finditer(text):
            # Before the sink (a variable read earlier) or inside its argument (``.html(location.hash)``).
            near = [item for item in sources if match.start() - WINDOW <= item[0] < match.end() + ARGUMENT]
            if not near:
                continue
            _position, source, found = min(near, key=lambda item: abs(item[0] - match.end()))
            parameter = ""
            if source == "url_parameter":
                parameter = found.group(1)
            else:
                named = _PARAM.search(text, max(0, match.start() - WINDOW), match.start())
                parameter = named.group(1) if named and source in {"location.search", "location.href",
                                                                    "document.URL"} else ""
            key = (source, sink, parameter)
            if key in seen:
                continue
            seen.add(key)
            leads.append({"source": "location.search" if source == "url_parameter" else source,
                          "sink": sink, **({"parameter": parameter} if parameter else {})})
            if len(leads) >= MAX_LEADS:
                return leads
    return leads
