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
from api.runtime.archive_body_masking import mask_url_userinfo_redacted
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
    # The URL userinfo rule is the Hunt body masking's reader since the 2.9.0 masking review: the
    # regex it replaced matched across compact JSON strings (``"http://a","p":"x:y@z"`` lost a
    # quote), stopped a password at its first ``@`` and split references (``[withheld:***@``).
    9: (mask_url_userinfo_redacted, None),
    11: (re.compile(r"(?i)(\b(?:mysql|mariadb)\b[^\r\n]*?\s-p)(?!\s)(\S+)"), r"\1***"),
}


def reference_redact_text(text: str) -> str:
    """``redact_text`` (no known values) as the rule table stood before R2."""
    for index, rule in enumerate(redaction._TEXT_PATTERNS):
        pattern, replacement = _REFERENCE_REWRITTEN.get(index, rule)
        text = pattern(text) if replacement is None else pattern.sub(replacement, text)
    return text


def test_the_reference_covers_every_rewritten_rule_and_keeps_the_rest():
    # 14: the provider-key rule (review sweep M2) was appended; it is a plain regex, unchanged.
    assert len(redaction._TEXT_PATTERNS) == 14
    assert redaction._TEXT_PATTERNS[13][0] is redaction._PROVIDER_KEY_RE
    assert redaction._TEXT_PATTERNS[8] is redaction._mask_xml_elements
    assert redaction._TEXT_PATTERNS[9] is redaction._mask_url_userinfo
    assert redaction._TEXT_PATTERNS[11] is redaction._mask_mysql_passwords
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
    "userinfo": (
        "https", "redis", "a", "A1", "x+y.z-", "-", ".", "1", "_", "é", "İ", "K", "ſ", "://", ":", "/",
        "@", "u", "pass", "[withheld:3]", "[withheld:3]@", " ", "\t", "\n", "?", "#", "token",
    ),
}


@pytest.mark.parametrize("family", sorted(_ATOMS))
def test_rewritten_rules_redact_exactly_as_before(family):
    rng = random.Random(f"r2-{family}")
    atoms = _ATOMS[family]
    for _ in range(3_000):
        text = "".join(rng.choice(atoms) for _ in range(rng.randint(1, 40)))
        assert redact_text(text) == reference_redact_text(text), repr(text)


# The userinfo regex rule 9 replaced, for the differential below.
_OLD_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]*):(?!\[withheld:[1-9][0-9]{0,3}\]@)[^@\s/]+@")


# The connection-string rule main also had (removed: the userinfo reader covers it).
_OLD_CONNECTION_RE = re.compile(
    r"(?i)\b((?:postgres(?:ql)?|mysql|mongodb|redis|amqp|https?|ftp)://[^\s:@/]+:)"
    r"(?!\[withheld:[1-9][0-9]{0,3}\]@)([^\s@/]+)(@)")


def _old_redact_text(text: str) -> str:
    """``redact_text`` as main ran it before the 2.9.0 masking review."""
    for index, rule in enumerate(redaction._TEXT_PATTERNS):
        if index == 9:
            text = _OLD_USERINFO_RE.sub(r"\1:***@", text)
        else:
            pattern, replacement = _REFERENCE_REWRITTEN.get(index, rule)
            text = pattern(text) if replacement is None else pattern.sub(replacement, text)
    return _OLD_CONNECTION_RE.sub(r"\1***\3", text)


def _crosses_strings(text: str, match: re.Match[str]) -> bool:
    """The old match read past a string's end into the next string: a quote in its user name, or
    a URL opened by a quote whose authority holds that quote then JSON/JS punctuation (claim 5)."""
    authority = match.group(0).split("://", 1)[1]
    user, password = authority.split(":", 1)
    if re.search(r"[\"'`]", user):
        return True
    start = match.start() + match.group(0).index("://")
    while start > 0 and re.match(r"[A-Za-z0-9+.-]", text[start - 1]) and match.start() < start:
        start -= 1
    quote = text[start - 1] if start > 0 and text[start - 1] in "\"'`" else None
    return quote is not None and re.search(re.escape(quote) + r"\s*[,:\]})]", authority) is not None


def _withheld_before_but_shown_now(text: str) -> list[str]:
    """Every password the old rules withheld that the new output shows more often than the old
    one did. One direction only: redaction may withhold more than before, never less."""
    old, new = _old_redact_text(text), redact_text(text)
    shown = []
    for pattern, group in ((_OLD_USERINFO_RE, 0), (_OLD_CONNECTION_RE, 2)):
        for match in pattern.finditer(text):
            value = match.group(group)
            if group == 0:
                value = value[value.index("://") + 3:][:-1].split(":", 1)[1]
            # The intended differences: the old regex split a reference at its own ``:``, and read
            # a user name across a string's closing quote into the next string (claim 5).
            if "[withheld:" in match.group(0) or _crosses_strings(text, match):
                continue
            if len(value) >= 4 and new.count(value) > old.count(value):
                shown.append(value)
    return shown


def test_the_userinfo_rule_never_shows_a_password_the_old_rules_withheld():
    rng = random.Random("r2-userinfo-differential")
    atoms = _ATOMS["userinfo"] + ('"', "'", "#", "?", "Pa#ss", "o'neil", "S3cr?t")
    for _ in range(5_000):
        text = "".join(rng.choice(atoms) for _ in range(rng.randint(1, 40)))
        assert "[withheld:***" not in redact_text(text), repr(text)  # never splits a reference
        assert _withheld_before_but_shown_now(text) == [], repr(text)


_SCHEMES = ("https", "http", "redis", "postgres", "mongodb+srv", "amqp", "ftp", "git+ssh", "s3", "x-y")
_CONTEXTS = ("{}", '"{}"', "'{}'", '{{"u":"{}"}}', '<a href="{}">', "url={}", "({})", "`{}`", "[{}]",
             "<{}>", "{},x", "DATABASE_URL={}\n", "&lt;{}&gt;", "<a href='{}'>")


@pytest.mark.parametrize("alphabet", [
    "abcdefXYZ0123456789!$&'()*+,;=-._~",                   # RFC 3986 userinfo characters
    "abcdefXYZ0123456789!$&'()*+,;=-._~%:?#[]\"<>{}|^`\\",  # and what hand-written DSNs hold
])
def test_generated_url_passwords_are_withheld_at_least_as_before(alphabet):
    """Seeded (2.9.0 review): every generated password the old rules withheld stays withheld."""
    rng = random.Random(f"userinfo-{len(alphabet)}")
    for _ in range(20_000):
        password = "Pq" + "".join(rng.choice(alphabet) for _ in range(rng.randint(2, 12))) + "Zk"
        url = f"{rng.choice(_SCHEMES)}://{rng.choice(['', 'u', 'admin', 'a.b'])}:{password}@" + rng.choice(
            ["h", "db.example", "10.0.0.1:5432", "h/path", "h?x=1"])
        text = rng.choice(_CONTEXTS).format(url)
        old, new = _old_redact_text(text), redact_text(text)
        quote = text[text.index(url) - 1] if text.index(url) and text[text.index(url) - 1] in "\"'`" else None
        if quote and re.search(re.escape(quote) + r"\s*[,:\]})]", password):
            # The URL's own quote then JSON/JS punctuation: the quoted URL ended there, the rest is
            # the next value (claim 5) -- the intended difference besides references.
            continue
        pieces = {password[k:k + 4] for k in range(len(password) - 3)}
        assert not any(piece in new and piece not in old for piece in pieces), (text, new)


@pytest.mark.parametrize("text", [
    "upstream connect failed: postgres://app:Pa#ss?w0rd@db.internal:5432/app",
    "MongoServerSelectionError mongodb://root:Hunt3r#2024@mongo:27017",
    "redis://:S3cr?tV4lue@cache:6379/0 refused",
    "<a href='ftp://u:o'neil99@h/'>",
])
def test_passwords_with_unencoded_delimiters_stay_withheld(text):
    assert redact_text(text) == _old_redact_text(text)
    for secret in ("Pa#ss", "Hunt3r", "S3cr?t", "neil99"):
        assert secret not in redact_text(text)


@pytest.mark.parametrize("text, expected", [
    ('Content-Disposition: form-data; name="password"\r\n\r\nhunter2\r\n--b--',
     'Content-Disposition: form-data; name="password"\r\n\r\n***\r\n--b--'),
    ('<input name="x"><input name="password">\n\nhunter2', '<input name="x"><input name="password">\n\n***'),
    ("<password>hunter2</password><password>s3cr3t</PASSWORD >",
     "<password>***</password><password>***</PASSWORD >"),
    ("mysql mysql -u root -phunter2 next", "mysql mysql -u root -p*** next"),
    ("--client-secret=abc&x=1", "--client-secret=***&x=1"),
    ("étoken-password: abcdef", "étoken-password: ***"),
    ("see https://ID:SECRET@api.example/x and redis://:pw@cache", "see https://ID:***@api.example/x and redis://:***@cache"),
    ("https://u:[withheld:3]@h", "https://u:[withheld:3]@h"),
    # Compact JSON: a quoted URL ends at its own quote, a password at the authority's last ``@``.
    ('{"u":"http://a","p":"x:y@z"}', '{"u":"http://a","p":"x:y@z"}'),
    ('{"a":"https://x","t":"k:v","e":"me@ex.com"}', '{"a":"https://x","t":"k:v","e":"me@ex.com"}'),
    ('{"a":"redis://:pa@ss@host"}', '{"a":"redis://:***@host"}'),
    ('{"a":"https://user:p%2Fw@host"}', '{"a":"https://user:***@host"}'),
    ("postgres://app:s3cret@db/x", "postgres://app:***@db/x"),
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
    "dotted scheme-like words": lambda n: "a." * n + "://",
    "url separators": lambda n: "a://b:" * n,
    "userinfo without an at sign": lambda n: "token-" * n + "://" + ":" * n,
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
