"""Free-text redaction is linear on hostile text and masks exactly what it masked before.

External release audit, 2026-10-09: the multipart-field rule read a line to its end once per
``name="password"`` field on it, so a 1 MB line of fields took minutes; the masked archive runs
``redact_text`` over every body. Its neighbours had the same shape: an unclosed ``<password>``
element searched to the end of the text once per opening tag, a ``mysql`` mention once per
mention, and the ``key=value`` / ``key: value`` rules retried a name such as ``token-token-...``
at every hyphen and every split, which was cubic (6 KB took 29 s).

The reference below is the rule table as it was. The rewritten rules must give the same text for
every input; the scaling checks run in a subprocess with a timeout so a regression fails instead
of hanging the suite. The inputs are test fixtures.
"""

from __future__ import annotations

import json
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scanner import redaction
from scanner.redaction import (
    _NOT_WITHHELD_MARKER,
    _NOT_WITHHELD_QUOTED,
    _SENSITIVE_COLON_KEY,
    _SENSITIVE_TEXT_KEY,
    redact_text,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

# The rules R2 rewrote, exactly as they were.
_REFERENCE_REWRITTEN = {
    3: (re.compile(rf"(?i)\b({_SENSITIVE_TEXT_KEY})\s*=\s*{_NOT_WITHHELD_MARKER}([^&\s,;]+)"), r"\1=***"),
    4: (
        re.compile(rf"(?i)\b({_SENSITIVE_COLON_KEY})(\s*:\s*){_NOT_WITHHELD_MARKER}([^\s,;\"']{{4,}})"),
        r"\1\2***",
    ),
    5: (
        re.compile(rf'(?i)(["\']{_SENSITIVE_TEXT_KEY}["\']\s*:\s*)(["\']){_NOT_WITHHELD_QUOTED}[^"\']+(["\'])'),
        r"\1\2***\3",
    ),
    6: (
        re.compile(rf'(?i)(["\']{_SENSITIVE_TEXT_KEY}["\']\s*:\s*)(?:-?\d+(?:\.\d+)?|true|false|null)'),
        r'\1"***"',
    ),
    7: (
        re.compile(rf'(?is)(name=["\']{_SENSITIVE_TEXT_KEY}["\'][^\r\n]*\r?\n\r?\n).*?(?=\r?\n--|$)'),
        r"\1***",
    ),
    8: (
        re.compile(
            rf'(?is)(<({_SENSITIVE_TEXT_KEY})(?:\s[^>]*)?>)(?!\[withheld:[1-9][0-9]{{0,3}}\]</).*?(</\2\s*>)'
        ),
        r"\1***\3",
    ),
    10: (re.compile(r"(?i)(\b(?:mysql|mariadb)\b[^\r\n]*?\s-p)(?!\s)(\S+)"), r"\1***"),
}


def reference_redact_text(text: str) -> str:
    """``redact_text`` (no known values) as the rule table stood before R2."""
    for index, rule in enumerate(redaction._TEXT_PATTERNS):
        pattern, replacement = _REFERENCE_REWRITTEN.get(index, rule)
        text = pattern.sub(replacement, text)
    return text


def test_the_reference_covers_every_rewritten_rule_and_keeps_the_rest():
    assert len(redaction._TEXT_PATTERNS) == 13
    assert redaction._TEXT_PATTERNS[8] is redaction._mask_xml_elements
    assert redaction._TEXT_PATTERNS[10] is redaction._mask_mysql_passwords
    for index, rule in enumerate(redaction._TEXT_PATTERNS):
        assert callable(rule) or isinstance(rule, tuple)
        if index not in _REFERENCE_REWRITTEN:
            assert isinstance(rule, tuple), index  # unchanged rules are still plain regexes


_ATOMS = {
    "mixed": (
        "name=", 'name="', "name='", "password", "PassWord", "api_key", "api-key", "token", "tokens",
        "tokenizer", "x-", "-", "_", "secret", "bearer", "authorization", '"', "'", "\n", "\r\n", "\n\n",
        "\r\n\r\n", "--", " ", "\t", ":", "=", ";", ",", "&", "<password>", "</password>", "</PASSWORD >",
        "<password a=1>", "<", ">", "</", "İ", "ı", "ſ", "K", "k", "i", "s", "mysql",
        " -p", " -P", "-psecret", "abc123", "[withheld:3]", "12", "true", "null", "é", "value",
    ),
    "names": (
        "token", "tokens", "tokenizer", "-", "_", "x", "é", "İ", "K", "٣", "pass", "word",
        "password", "api", "key", "=", ":", " ", "\t", "abcd", "[withheld:3]", "'", '"', ",", "&", ";",
        "bearer", "AUTHORIZATION", "\n", "1", ".", "/",
    ),
    "multipart": (
        'name="password"', "name='api_key'", 'name="x"', 'name="token-', '"', "\n", "\r\n", "\n\n",
        "\r\n\r\n", "\r", "--", "--b", "x", " ", "value",
    ),
    "quoted": (
        '"', "'", '"password"', '"api_key":', "token", "tokens", "-", "_", "x", ":", " ", "12", "-3.5",
        "true", "null", "abc", "[withheld:3]", "[withheld:3]\"", "[withheld:3]'", "İ", "K",
    ),
    "mysql": (
        "mysql", "mariadb", "MySQL", " ", "\n", "\r", "\r\n", "-p", "-P", " -p", "-pX", "x", "é",
        "\t", "_mysql", "mysql_", "-", "p",
    ),
    "elements": (
        "<password>", "<Password x='1'>", "</password>", "</PASSWORD\t>", "</password-x>", "<api_key>",
        "</api_key>", "<İtoken>", "</itoken>", "<Key_token>", "</key_token>", "<", ">", "</",
        "[withheld:1]", "[withheld:1]</password>",
        "x", " ", "\n",
    ),
}


@pytest.mark.parametrize("family", sorted(_ATOMS))
def test_rewritten_rules_redact_exactly_as_before(family):
    rng = random.Random(f"r2-{family}")
    atoms = _ATOMS[family]
    for _ in range(3_000):
        text = "".join(rng.choice(atoms) for _ in range(rng.randint(1, 40)))
        assert redact_text(text) == reference_redact_text(text), repr(text)


@pytest.mark.parametrize("text, expected", [
    ('Content-Disposition: form-data; name="password"\r\n\r\nhunter2\r\n--b--',
     'Content-Disposition: form-data; name="password"\r\n\r\n***\r\n--b--'),
    ('<input name="x"><input name="password">\n\nhunter2', '<input name="x"><input name="password">\n\n***'),
    ("<password>hunter2</password><password>s3cr3t</PASSWORD >",
     "<password>***</password><password>***</PASSWORD >"),
    ("mysql mysql -u root -phunter2 next", "mysql mysql -u root -p*** next"),
    ("--client-secret=abc&x=1", "--client-secret=***&x=1"),
    ("étoken-password: abcdef", "étoken-password: ***"),
])
def test_known_shapes(text, expected):
    assert redact_text(text) == expected
    assert reference_redact_text(text) == expected


# One subprocess times every hostile shape at size N and 4N (best of three). A quadratic rule
# takes 16x as long at 4N and the old key rules 64x; a linear one about 4x. The bound is
# generous so a busy CI host does not fail it, and the subprocess timeout turns a regression
# into a failure instead of a hung suite.
_SCALING_SCRIPT = r"""
import json, sys, time
from scanner.redaction import redact_text
shapes = {
    "multipart fields on one line": lambda n: '<input name="password">' * n,
    "unclosed elements": lambda n: "<password>" * n + "</other>",
    "elements of many names": lambda n: "".join(f"<password{i}>" for i in range(n)) + "</x>",
    "mysql mentions": lambda n: "mysql " * n,
    "hyphenated name": lambda n: "token-" * n,
    "underscored name": lambda n: "token_" * n,
    "quoted hyphenated name": lambda n: '"' + "token-" * n,
    "key value pairs": lambda n: "password: abcd " * n,
}
result = {}
for label, make in shapes.items():
    timings = []
    for size in (sys.argv[1], sys.argv[2]):
        text = make(int(size))
        best = min(
            (lambda start: (redact_text(text), time.perf_counter() - start)[1])(time.perf_counter())
            for _ in range(3)
        )
        timings.append(best)
    result[label] = timings
mb = '<input name="password">' * (1_048_576 // 23)
start = time.perf_counter(); redact_text(mb); result["one megabyte of fields"] = [time.perf_counter() - start]
print(json.dumps(result))
"""


def test_hostile_text_redacts_in_linear_time():
    completed = subprocess.run(
        [sys.executable, "-c", _SCALING_SCRIPT, "12000", "48000"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=True,
    )
    timings = json.loads(completed.stdout)
    for label, values in timings.items():
        if len(values) == 2:
            small, large = values
            # The floor keeps scheduler noise on a fast run from failing a linear rule; the old
            # rules took seconds to minutes at the larger size, far past any floor.
            assert large <= 9 * max(small, 0.05), (label, small, large)
    # Before R2 this one line took minutes (163 s in the audit).
    assert timings["one megabyte of fields"][0] < 10, timings
