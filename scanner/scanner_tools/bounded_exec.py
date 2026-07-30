"""Exec one argv-only scanner command after applying worker-side safety limits."""

from __future__ import annotations

import os
import pwd
import resource
import sys
import ctypes
import ctypes.util
import errno


SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000
SCMP_CMP_EQ = 4
PR_SET_NO_NEW_PRIVS = 38
DENIED_SOCKET_DOMAINS = (
    2,   # AF_INET
    3,   # AF_AX25
    4,   # AF_IPX
    5,   # AF_APPLETALK
    6,   # AF_NETROM
    7,   # AF_BRIDGE
    8,   # AF_ATMPVC
    9,   # AF_X25
    10,  # AF_INET6
    11,  # AF_ROSE
    16,  # AF_NETLINK
    17,  # AF_PACKET
    31,  # AF_BLUETOOTH
    35,  # AF_NFC
    40,  # AF_VSOCK
    44,  # AF_XDP
)


class _ScmpArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_uint32),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def _limit(kind: int, value: int) -> None:
    resource.setrlimit(kind, (value, value))


def _deny_network_syscalls() -> None:
    """Deny external-capable socket creation while preserving local Unix IPC."""
    library_name = ctypes.util.find_library("seccomp")
    if not library_name:
        raise SystemExit("bounded_exec requires libseccomp for no-network execution")
    seccomp = ctypes.CDLL(library_name, use_errno=True)
    libc = ctypes.CDLL(None, use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(_ScmpArgCmp),
    ]
    seccomp.seccomp_rule_add_array.restype = ctypes.c_int
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SystemExit(f"bounded_exec could not set no_new_privileges: errno={ctypes.get_errno()}")
    context = seccomp.seccomp_init(SCMP_ACT_ALLOW)
    if not context:
        raise SystemExit("bounded_exec could not allocate seccomp context")
    try:
        socket_syscall = seccomp.seccomp_syscall_resolve_name(b"socket")
        if socket_syscall < 0:
            raise SystemExit("bounded_exec could not resolve socket syscall")
        for domain in DENIED_SOCKET_DOMAINS:
            comparison = _ScmpArgCmp(0, SCMP_CMP_EQ, domain, 0)
            result = seccomp.seccomp_rule_add_array(
                context,
                SCMP_ACT_ERRNO | errno.EPERM,
                socket_syscall,
                1,
                ctypes.byref(comparison),
            )
            if result != 0:
                raise SystemExit(f"bounded_exec could not deny socket domain {domain}: result={result}")
        io_uring_syscall = seccomp.seccomp_syscall_resolve_name(b"io_uring_setup")
        if io_uring_syscall >= 0:
            result = seccomp.seccomp_rule_add(
                context,
                SCMP_ACT_ERRNO | errno.EPERM,
                io_uring_syscall,
                0,
            )
            if result != 0:
                raise SystemExit(f"bounded_exec could not deny io_uring_setup: result={result}")
        result = seccomp.seccomp_load(context)
        if result != 0:
            raise SystemExit(f"bounded_exec could not load seccomp filter: result={result}")
    finally:
        seccomp.seccomp_release(context)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    no_address_space_limit = False
    if arguments[:1] == ["--no-address-space-limit"]:
        no_address_space_limit = True
        arguments = arguments[1:]
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    if not arguments or not os.path.isabs(arguments[0]):
        raise SystemExit("bounded_exec requires an absolute executable path")

    _limit(resource.RLIMIT_CPU, 300)
    # Go and OCaml runtimes reserve an enormous sparse address space and crash
    # under RLIMIT_AS even when RSS is small. For those explicitly selected
    # adapters, the worker's 4 GiB cgroup is the resident-memory boundary.
    if not no_address_space_limit:
        _limit(resource.RLIMIT_AS, 2 * 1024**3)
    _limit(resource.RLIMIT_FSIZE, 100 * 1024**2)
    _limit(resource.RLIMIT_NOFILE, 256)
    if hasattr(resource, "RLIMIT_NPROC"):
        _limit(resource.RLIMIT_NPROC, 128)
    _limit(resource.RLIMIT_CORE, 0)
    _deny_network_syscalls()

    if os.geteuid() == 0:
        account = pwd.getpwnam("scanner")
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    os.execve(arguments[0], arguments, os.environ)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
