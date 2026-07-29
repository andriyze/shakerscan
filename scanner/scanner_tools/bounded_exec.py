"""Exec one argv-only scanner command after applying worker-side safety limits."""

from __future__ import annotations

import os
import pwd
import resource
import sys


def _limit(kind: int, value: int) -> None:
    resource.setrlimit(kind, (value, value))


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    if not arguments or not os.path.isabs(arguments[0]):
        raise SystemExit("bounded_exec requires an absolute executable path")

    _limit(resource.RLIMIT_CPU, 300)
    _limit(resource.RLIMIT_AS, 2 * 1024**3)
    _limit(resource.RLIMIT_FSIZE, 100 * 1024**2)
    _limit(resource.RLIMIT_NOFILE, 256)
    if hasattr(resource, "RLIMIT_NPROC"):
        _limit(resource.RLIMIT_NPROC, 128)
    _limit(resource.RLIMIT_CORE, 0)

    if os.geteuid() == 0:
        account = pwd.getpwnam("scanner")
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    os.execve(arguments[0], arguments, os.environ)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
