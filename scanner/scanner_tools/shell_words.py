"""Shell words for the commands ShakerScan offers to copy.

Reproduce, verify, check and replay commands carry values the scanned target chose: a URL path, a
header, a certificate name, a parameter, a payload. A person pastes these commands into a
terminal, so every such value goes through ``shell_word`` and reaches the command as one inert
argument.

Target text never goes into a ``#`` comment line either. An interactive zsh does not treat ``#``
as a comment unless INTERACTIVE_COMMENTS is set (it is off by default), so it would expand a
``$(...)`` written there. Comment lines in copied commands hold fixed text only.
"""

from __future__ import annotations

import re
import urllib.parse

# C0 controls, DEL and C1 controls. A terminal acts on these as keys while text is pasted without
# bracketed paste (^C or ^U drops what was typed so far, so the rest of the line would be read
# outside its quotes), so a copied command never carries one.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# The characters ``shlex.quote`` leaves unquoted; every other word is single-quoted.
_BARE = re.compile(r"[A-Za-z0-9_@%+=:,./-]+")


def _percent(match: re.Match[str]) -> str:
    return urllib.parse.quote(match.group(), safe="")


def _quoted_run(run: str) -> str:
    # A leading "=" stays quoted: zsh expands an unquoted "=name" to the path of a command.
    if _BARE.fullmatch(run) and not run.startswith("="):
        return run
    return "'" + run.replace("'", "'\"'\"'") + "'"


def shell_word(value: object) -> str:
    """``value`` as one shell word that sh, bash, dash, ksh, zsh and fish read back literally.

    The word is single-quoted the way ``shlex.quote`` does it, so ``$(...)``, backticks, ``;``,
    ``&``, ``|``, globs and quotes stay text. Two characters are written differently:

    - a backslash is written as ``"\\\\"`` between the single-quoted runs, because fish reads
      ``\\'`` inside single quotes as an escaped quote, which would end the word early;
    - a control character is written as its percent-encoding (``%0D``), the form a URL carries
      it in, because a terminal acts on it while the command is pasted.
    """
    text = _CONTROL.sub(_percent, str(value))
    if not text:
        return "''"
    return '"\\\\"'.join(_quoted_run(run) if run else "" for run in text.split("\\"))
