"""Operator-created, revocable run leases for the optional planner-only listener.

This is ingress authentication, not a second Hunt approval/budget registry. The
canonical run retains every execution permission. No lease-issuing HTTP route
exists on the planner listener, and the client receives only a random bearer.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from uuid import UUID, uuid4

MAX_LEASE_SECONDS = 24 * 60 * 60
MAX_CONFIG_BYTES = 4096


@dataclass(frozen=True)
class PlannerLease:
    hunt_id: str
    planner_id: str
    token_sha256: str
    issued_at: int
    expires_at: int

    @classmethod
    def parse(cls, value: object, *, now: float) -> 'PlannerLease':
        if not isinstance(value, dict) or set(value) != {
            'schema_version', 'enabled', 'hunt_id', 'planner_id', 'token_sha256',
            'issued_at', 'expires_at',
        }:
            raise ValueError('Invalid planner lease')
        if value['schema_version'] != 'hunt-planner-lease/v1' or value['enabled'] is not True:
            raise ValueError('Planner lease is disabled or unsupported')
        issued, expires = value['issued_at'], value['expires_at']
        if (type(issued) is not int or type(expires) is not int
                or not 0 < expires - issued <= MAX_LEASE_SECONDS
                or issued > now or expires <= now):
            raise ValueError('Planner lease is not current')
        digest = value['token_sha256']
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Invalid planner credential digest')
        return cls(str(UUID(value['hunt_id'])), str(UUID(value['planner_id'])), digest, issued, expires)

    def accepts(self, token: str) -> bool:
        if not re.fullmatch(r'[A-Za-z0-9_-]{43,256}', token):
            return False
        return hmac.compare_digest(hashlib.sha256(token.encode('ascii')).hexdigest(), self.token_sha256)


def load_lease(path: Path, *, now: float | None = None) -> PlannerLease:
    """Read on every request: removal, expiry and atomic replacement revoke access.

    The grant file belongs to the listener's OS identity, is not group/world
    accessible and must not be mounted into the planner. File permissions are a
    useful check, not an isolation claim against a same-UID local coding agent.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES
                or info.st_mode & 0o077
                or (hasattr(os, 'geteuid') and info.st_uid != os.geteuid())):
            raise ValueError('Planner lease file must be owner-only regular data')
        raw = handle.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError('Planner lease is too large')
    return PlannerLease.parse(json.loads(raw), now=time.time() if now is None else now)


def write_lease(hunt_id: str, grant_path: Path, token_path: Path, *, seconds: int = 8 * 60 * 60) -> None:
    """Create, never overwrite, both files. Keep bearer values out of argv/logs."""
    hunt_id = str(UUID(hunt_id))
    if type(seconds) is not int or not 0 < seconds <= MAX_LEASE_SECONDS:
        raise ValueError('Lease lifetime must be between 1 and 86400 seconds')
    if grant_path.resolve() == token_path.resolve():
        raise ValueError('Use distinct server grant and planner token files')
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    grant = {
        'schema_version': 'hunt-planner-lease/v1', 'enabled': True,
        'hunt_id': hunt_id, 'planner_id': str(uuid4()),
        'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
        'issued_at': now, 'expires_at': now + seconds,
    }
    # Publish the credential before the grant, so failure never enables an
    # orphan lease. On failure remove only a token this invocation created.
    with open(token_path, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as handle:
        handle.write(token + '\n')
    try:
        with open(grant_path, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as handle:
            json.dump(grant, handle, sort_keys=True)
            handle.write('\n')
    except Exception:
        token_path.unlink()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hunt-id', required=True)
    parser.add_argument('--grant-file', type=Path, required=True)
    parser.add_argument('--token-file', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=8 * 60 * 60)
    args = parser.parse_args()
    write_lease(args.hunt_id, args.grant_file, args.token_file, seconds=args.seconds)
    print('Created an expiring single-Hunt lease; no testing authority was added.')


if __name__ == '__main__':
    main()
