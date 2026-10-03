"""Bounded, worker-local SSH transports. No local shell or SSH subprocess is used."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import io
import errno
import select
import socket
import threading
import time
from typing import Any
from uuid import uuid4

try:
    from runtime.ssh_command_contract import (SSH_CONNECT_SECONDS, SSH_MAX_SESSIONS,
        SSH_SESSION_IDLE_SECONDS, SSH_SESSION_LIFETIME_SECONDS)
except ModuleNotFoundError:
    from ..runtime.ssh_command_contract import (SSH_CONNECT_SECONDS, SSH_MAX_SESSIONS,
        SSH_SESSION_IDLE_SECONDS, SSH_SESSION_LIFETIME_SECONDS)


@dataclass
class SshTransport:
    binding: tuple
    session_id: str = field(default_factory=lambda: str(uuid4()))
    transport: Any = None
    sock: Any = None
    fingerprint: str | None = None
    created: float = field(default_factory=time.monotonic)
    touched: float = field(default_factory=time.monotonic)
    busy: bool = False
    closed: bool = False
    lock: Any = field(default_factory=threading.RLock)

    def close(self):
        with self.lock:
            self.closed = True
            if self.transport is not None:
                self.transport.close()
            if self.sock is not None:
                self.sock.close()

    def connect(self, address, port, cancelled):
        import paramiko
        sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM)
        with self.lock:
            self.sock = sock
            if self.closed or cancelled():
                sock.close()
                raise InterruptedError('cancelled')
        sock.setblocking(False)
        error = sock.connect_ex((address, port))
        if error not in {0, errno.EINPROGRESS, errno.EWOULDBLOCK}:
            raise OSError(error, 'SSH connection failed')
        deadline = time.monotonic() + SSH_CONNECT_SECONDS
        while error:
            if self.closed or cancelled():
                raise InterruptedError('cancelled')
            if time.monotonic() >= deadline:
                raise TimeoutError('SSH connection timeout')
            _, writable, _ = select.select([], [sock], [], 0.1)
            if writable:
                error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if error:
                    raise OSError(error, 'SSH connection failed')
        sock.settimeout(SSH_CONNECT_SECONDS)
        with self.lock:
            if self.closed or cancelled():
                raise InterruptedError('cancelled')
            self.transport = paramiko.Transport(sock)
            self.transport.banner_timeout = SSH_CONNECT_SECONDS
            self.transport.auth_timeout = SSH_CONNECT_SECONDS
            self.transport.channel_timeout = SSH_CONNECT_SECONDS
        self.transport.start_client(timeout=SSH_CONNECT_SECONDS)
        if cancelled() or self.closed:
            raise InterruptedError('cancelled')
        key = self.transport.get_remote_server_key()
        self.fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        return self.fingerprint

    def authenticate(self, material, kind, cancelled):
        import paramiko
        if cancelled() or self.closed:
            raise InterruptedError('cancelled')
        if kind == 'ssh_password':
            self.transport.auth_password(material['username'], material['secret'], fallback=False)
        else:
            key = None
            for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                try:
                    key = key_class.from_private_key(io.StringIO(material['secret']),
                        password=material.get('secondary_secret'))
                    break
                except (ValueError, paramiko.SSHException):
                    continue
            if key is None:
                raise ValueError('unsupported_ssh_private_key')
            self.transport.auth_publickey(material['username'], key)
        if cancelled() or self.closed or not self.transport.is_authenticated():
            raise InterruptedError('authentication_interrupted')
        self.transport.set_keepalive(15)

    def usable(self):
        return bool(not self.closed and self.transport and self.transport.is_active()
                    and self.transport.is_authenticated())


class SshTransportPool:
    """An opaque ID never changes the target, identity, Hunt or service binding."""
    def __init__(self):
        self.sessions: dict[str, SshTransport] = {}
        self.lock = threading.RLock()

    def acquire(self, binding, session_id=None):
        with self.lock:
            if session_id:
                session = self.sessions.get(session_id)
                expected = binding
                if session is not None and binding[3] is None:
                    expected = (*binding[:3], session.binding[3], *binding[4:])
                if session is None or session.binding != expected or not session.usable():
                    raise ValueError('ssh_session_binding_or_connection_changed')
                if session.busy:
                    raise ValueError('ssh_session_busy')
                if time.monotonic() - session.created >= SSH_SESSION_LIFETIME_SECONDS:
                    self.remove(session_id)
                    raise ValueError('ssh_session_expired')
                session.busy = True
                return session, True
            if len(self.sessions) >= SSH_MAX_SESSIONS:
                raise ValueError('ssh_worker_session_capacity_reached')
            session = SshTransport(binding=binding, busy=True)
            self.sessions[session.session_id] = session
            return session, False

    def release(self, session):
        with self.lock:
            session.busy = False
            session.touched = time.monotonic()

    def remove(self, session_id, *, hunt_id=None, target_digest=None):
        with self.lock:
            session = self.sessions.get(session_id)
            if session is None:
                return False
            if (hunt_id is not None and session.binding[0] != str(hunt_id)
                    or target_digest is not None and session.binding[1] != target_digest):
                raise ValueError('ssh_session_binding_mismatch')
            session.close()
            del self.sessions[session_id]
            return True

    def reap(self, active_hunts=None):
        removed = []
        now = time.monotonic()
        with self.lock:
            for identifier, session in list(self.sessions.items()):
                stale_run = active_hunts is not None and session.binding[0] not in active_hunts
                expired = (not session.busy and (now-session.touched >= SSH_SESSION_IDLE_SECONDS
                           or now-session.created >= SSH_SESSION_LIFETIME_SECONDS or not session.usable()))
                if stale_run or expired:
                    self.remove(identifier)
                    removed.append(identifier)
        return removed

    def close_all(self):
        with self.lock:
            for identifier in list(self.sessions):
                self.remove(identifier)


SSH_TRANSPORTS = SshTransportPool()
