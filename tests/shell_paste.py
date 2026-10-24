"""Run a copied command the way a person's terminal would, with nothing real on PATH.

PATH holds only recording stand-ins for the tools these commands call (curl, dig, openssl, ...)
and ``pwn``, which leaves a marker file. A target-chosen value can run ``pwn`` (or ``touch``)
only if a shell read it as syntax instead of as one word, so the marker shows that, and the
stand-ins' records show the exact arguments each tool would have received. Nothing reaches the
network.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

MARKER = ".shell-ran"

# Target-chosen text that runs the marker when a shell reads it unquoted. The ``pwn`` forms work
# in every shell (zsh does not split $IFS); the ``${=...}`` form splits a word by hand in zsh;
# the quote forms try to break out of a single-quoted word, the last one in fish's way.
PAYLOADS = (
    "$(touch$IFS.shell-ran)",
    "`touch$IFS.shell-ran`",
    ";touch$IFS.shell-ran;",
    "'$(touch$IFS.shell-ran)",
    "$(pwn)",
    "`pwn`",
    ";pwn;",
    "|pwn|",
    "'$(pwn)'",
    "$(${=${:-touch${IFS[1]}.shell-ran}})",
    "\\'$(pwn)\\'",
)

_RECORDED_TOOLS = ("curl", "dig", "delv", "openssl", "nmap", "nuclei", "testssl.sh", "grep", "sed")
# Each stand-in writes its own record, so tools running side by side in a pipeline never interleave.
_RECORDER = """#!/bin/sh
{ printf '%s\\n' "${0##*/}"; for arg in "$@"; do printf '\\t%s\\n' "$arg"; done; } > "$CALL_LOG/$$"
"""


@dataclass(frozen=True)
class Shell:
    name: str
    argv: tuple[str, ...]
    interactive: bool = False  # the command is typed at a prompt, line by line, from stdin


def shells() -> tuple[Shell, ...]:
    """The shells on this host, run as a script and as an interactive prompt.

    ``bash`` and ``/bin/sh`` are required; dash, ksh and zsh run when installed. The interactive
    zsh keeps INTERACTIVE_COMMENTS off (its default), so a ``#`` line is not a comment there; the
    interactive bash has history expansion on.
    """
    bash = shutil.which("bash")
    assert bash, "bash is required to check copied commands"
    found = [Shell("bash", (bash,)), Shell("sh", ("/bin/sh",)),
             Shell("interactive bash", (bash, "--norc", "--noprofile", "-i"), interactive=True)]
    for name in ("dash", "ksh"):
        if path := shutil.which(name):
            found.append(Shell(name, (path,)))
    if zsh := shutil.which("zsh"):
        found += [Shell("zsh", (zsh, "-f")), Shell("zsh rcquotes", (zsh, "-f", "-o", "rcquotes")),
                  Shell("interactive zsh", (zsh, "-f", "-i"), interactive=True)]
    return tuple(found)


@dataclass(frozen=True)
class Run:
    shell: str
    stdout: str
    calls: tuple[tuple[str, tuple[str, ...]], ...]  # (tool, argv) of each stand-in that ran


def _tools(root: Path) -> Path:
    tools = root / "bin"
    if not tools.exists():
        tools.mkdir(parents=True)
        (tools / "touch").symlink_to(shutil.which("touch"))
        (tools / "pwn").write_text(f"#!/bin/sh\n: > {MARKER}\n")
        for tool in _RECORDED_TOOLS:
            (tools / tool).write_text(_RECORDER)
        for script in tools.iterdir():
            if script.name != "touch":
                script.chmod(0o755)
    return tools


def _wait_for_group(group: int) -> None:
    """Wait for every process the shell started: a shell may return before the earlier members of
    a pipeline (ksh does), and their records or marker would be read too soon."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return
        except PermissionError:  # macOS answers EPERM once only unreaped zombies are left
            return
        time.sleep(0.01)
    raise AssertionError(f"processes of a pasted command still running after 30 s (group {group})")


def _run(shell: Shell, command: str, tools: Path, root: Path) -> Run:
    home = root / shell.name.replace(" ", "-")
    work, calls = home / "work", home / "calls"
    shutil.rmtree(home, ignore_errors=True)
    work.mkdir(parents=True)
    calls.mkdir()
    env = {"PATH": str(tools), "HOME": str(home), "HISTFILE": "/dev/null", "CALL_LOG": str(calls)}
    if shell.name in {"bash", "sh"}:
        parsed = subprocess.run([*shell.argv, "-n", "-c", command], env=env, capture_output=True, text=True,
                                timeout=30, check=False)
        assert parsed.returncode == 0, (shell.name, command, parsed.stderr)
    argv = list(shell.argv) if shell.interactive else [*shell.argv, "-c", command]
    with subprocess.Popen(argv, cwd=work, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, start_new_session=True) as done:
        stdout, stderr = done.communicate(command + "\n" if shell.interactive else "", timeout=30)
    _wait_for_group(done.pid)
    assert not (work / MARKER).exists(), (shell.name, command, stderr)
    records = []
    for record in sorted(calls.iterdir()):
        tool, *args = record.read_text().split("\n")[:-1]
        records.append((tool, tuple(arg[1:] for arg in args)))
    return Run(shell.name, stdout, tuple(records))


def paste(command: str, root: Path) -> list[Run]:
    """Run ``command`` in every shell; fail if one could not parse it or ran target syntax."""
    tools = _tools(root)
    found = shells()
    with ThreadPoolExecutor(max_workers=len(found)) as pool:
        return list(pool.map(lambda shell: _run(shell, command, tools, root), found))
