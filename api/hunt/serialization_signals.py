"""Serialized objects a page hands its client: leads for insecure deserialization.

Ported from the removed ``scanner_tools/deserialization_tests`` (which nothing called): the
serialized-object signatures of Java, .NET, Python and Ruby (and PHP inside an input value or a
URL parameter). An application that sends one to the browser usually reads it back, so the input
that carries it is worth testing; without an out-of-band callback or a known gadget chain nothing
here proves anything, so the sweep records an unverified candidate, never a finding.
"""
from __future__ import annotations

import re

_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("java", re.compile(r"(?<![A-Za-z0-9+/])rO0AB[A-Za-z0-9+/]{20,}={0,2}")),
    ("java", re.compile(r"(?i)(?<![0-9a-f])aced0005[0-9a-f]{24,}")),
    ("dotnet_binaryformatter", re.compile(r"(?<![A-Za-z0-9+/])AAEAAAD/////[A-Za-z0-9+/]{12,}={0,2}")),
    ("python_pickle", re.compile(r"(?<![A-Za-z0-9+/])gASV[A-Za-z0-9+/]{16,}={0,2}")),
    ("ruby_marshal", re.compile(r"(?<![A-Za-z0-9+/])BAh[A-Za-z0-9+/]{20,}={0,2}")),
)
# PHP's text form is common in documentation, so only as an input's value or a URL parameter.
_PHP_IN_VALUE = re.compile(
    r"""(?:value\s*=\s*["']|[?&][\w-]{1,64}=)(?:O|a)(?::|%3A)\d{1,4}(?::|%3A)(?:"|%22|\{|%7B)""", re.I)
MAX_SCAN_CHARS = 200_000


def serialized_formats(text: str) -> list[str]:
    """The serialization formats whose objects appear in a response body, each once."""
    head = str(text or "")[:MAX_SCAN_CHARS]
    found: list[str] = []
    for name, pattern in _SIGNATURES:
        if name not in found and pattern.search(head):
            found.append(name)
    if _PHP_IN_VALUE.search(head):
        found.append("php")
    return found
