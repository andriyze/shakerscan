"""Commands a finding's evidence offers for copying, built and checked in one place.

The scanner stores two kinds of command text in a finding's evidence: the manual verification
commands of an exposed file (``verify_commands``) and the one-line ``reproduction`` of a
configuration finding. Releases before every target-chosen value went through ``shell_word``
stored them with the URL or host as typed, so a stored row can hold text a shell would expand.

A finding read therefore rebuilds ``verify_commands`` from the evidence's own URL and path
(``exposed_file_verify_commands``), and offers a stored ``reproduction`` for copying only when
it has exactly the shape the scanner writes, with each variable part an inert shell word
(``is_current_reproduction``). Anything else is shown as recorded text only.
"""

from __future__ import annotations

import re

from .shell_words import shell_word

_PRIVATE_KEY_MARKERS = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "server.key", "private.key", ".pem")
_DATABASE_CONFIG_MARKERS = ("database.yml", "database.yaml", "db.yml", "db.yaml")


def exposed_file_verify_commands(url: str, path: str, base_url: str) -> list[str]:
    """The manual verification commands of an exposed file at ``url`` (``path`` as found)."""
    path_l = str(path or "").lower()
    word = shell_word(url)
    commands = [f"curl -sI {word}", f"curl -sL {word} | sed -n '1,40p'"]
    if ".git" in path_l:
        base = str(base_url or "").rstrip("/")
        commands.extend([f"curl -sL {shell_word(base + '/.git/HEAD')}", f"curl -sL {shell_word(base + '/.git/config')}"])
    if any(marker in path_l for marker in _PRIVATE_KEY_MARKERS):
        commands.append(f"curl -sL {word} | grep -E 'BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY' -m1")
    if any(marker in path_l for marker in _DATABASE_CONFIG_MARKERS):
        credential_key = shell_word("(^|[[:space:]:\"'])(password|username|adapter|database)[:=]")
        commands.append(f"curl -sL {word} | grep -Ei {credential_key} -m1")
    return commands


# One shell_word: bare runs of the characters it leaves unquoted (the word not starting with "="),
# single-quoted runs without a quote, backslash or control character, and the "'" and "\\" it
# writes for a quote and a backslash. A shell reads such a word back as text, whatever it holds.
_PIECE = r"'[^'\\\x00-\x1f\x7f-\x9f]*'" + "|" + re.escape("\"'\"") + "|" + re.escape('"\\\\"')
_WORD = rf"(?:[A-Za-z0-9_@%+:,./-]|{_PIECE})(?:[A-Za-z0-9_@%+=:,./-]|{_PIECE})*"
_OPENSSL = rf"openssl s_client -connect {_WORD} -servername {_WORD}"
_REPRODUCTIONS = tuple(re.compile(pattern) for pattern in (
    rf"curl -sIL {_WORD}",
    rf"curl -sI {_WORD}",
    rf"curl -sL {_WORD}",
    rf"curl -sI -H {_WORD} -H 'Access-Control-Request-Method: GET' -X OPTIONS {_WORD}",
    rf"dig \+short {_WORD} [A-Z]{{1,10}}",
    rf"delv @1\.1\.1\.1 {_WORD} A",
    rf"testssl\.sh -e --fast {_WORD}",
    rf"{_OPENSSL}",
    rf"{_OPENSSL} -status \| sed -n '1,120p'",
    rf"echo \| {_OPENSSL} 2>/dev/null \| openssl x509 -noout -enddate",
))


def is_current_reproduction(command: object) -> bool:
    """Whether a stored ``reproduction`` has a shape the scanner writes, every variable part one
    inert shell word, so it can be offered for copying as stored."""
    return isinstance(command, str) and any(pattern.fullmatch(command) for pattern in _REPRODUCTIONS)
