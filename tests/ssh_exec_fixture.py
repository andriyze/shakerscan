"""Loopback-only SSH test server executing explicitly listed local fixture commands.

This fixture runs real processes and streams their pipes. It is never installed
with ShakerScan and does not accept commands outside the test's explicit set.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import threading
import time

import paramiko

USERNAME = 'fixture-operator'
PASSWORD = 'fixture-only-password'


class CommandServer:
    def __init__(self, directory: Path):
        self.directory = directory
        self.key = paramiko.RSAKey.generate(2048)
        self.fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(self.key.asbytes()).digest()).decode().rstrip('=')
        self.allowed: set[str] = set()
        self.commands: list[str] = []
        self.public_keys: set[bytes] = set()
        self.logins = 0
        self.connections = 0
        self.running: set[int] = set()
        self.transports = []
        self.threads = []
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(10)
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def allow(self, *commands):
        self.allowed.update(commands)

    def accept(self):
        while not self.stopped.is_set():
            try:
                sock, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self.connection, args=(sock,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def connection(self, sock):
        server = self

        class Identity(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return 'password,publickey'

            def check_auth_password(self, username, password):
                if username == USERNAME and password == PASSWORD:
                    with server.lock:
                        server.logins += 1
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED

            def check_auth_publickey(self, username, key):
                if username == USERNAME and key.asbytes() in server.public_keys:
                    with server.lock:
                        server.logins += 1
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                text = command.decode('utf-8')
                if text not in server.allowed:
                    return False
                with server.lock:
                    server.commands.append(text)
                thread = threading.Thread(target=server.execute, args=(channel, text), daemon=True)
                server.threads.append(thread)
                thread.start()
                return True

        transport = paramiko.Transport(sock)
        transport.add_server_key(self.key)
        self.transports.append(transport)
        with self.lock:
            self.connections += 1
        try:
            transport.start_server(server=Identity())
            channels = []
            while transport.is_active() and not self.stopped.is_set():
                channel = transport.accept(timeout=0.1)
                if channel is not None:
                    channels.append(channel)
                channels = [item for item in channels if not item.closed]
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()
            sock.close()

    def execute(self, channel, command):
        process = subprocess.Popen(['/bin/sh', '-c', command], cwd=self.directory,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        with self.lock:
            self.running.add(process.pid)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
        selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
        try:
            while selector.get_map() and not self.stopped.is_set() and not channel.closed:
                for key, _ in selector.select(timeout=0.05):
                    value = os.read(key.fd, 4096)
                    if not value:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == 'stdout':
                        channel.sendall(value)
                    else:
                        channel.sendall_stderr(value)
            if not channel.closed and not self.stopped.is_set():
                channel.send_exit_status(process.wait(timeout=3))
        except (OSError, EOFError, subprocess.TimeoutExpired):
            pass
        finally:
            # The fixture cooperates with channel cancellation. Arbitrary remote servers
            # may leave detached children alive; production results report that uncertainty.
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=3)
            with self.lock:
                self.running.discard(process.pid)
            selector.close()
            process.stdout.close()
            process.stderr.close()
            channel.close()

    def close(self):
        self.stopped.set()
        self.sock.close()
        for transport in self.transports:
            transport.close()
        self.thread.join(timeout=3)
        for thread in self.threads:
            thread.join(timeout=3)


def tls_material(directory):
    """Ephemeral local certificate trusted explicitly by the acceptance client."""
    from datetime import datetime, timedelta, timezone
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
            x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .sign(key,hashes.SHA256()))
    cert, private = directory/'tls.pem', directory/'tls-key.pem'
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    private.chmod(0o600)
    return cert, private
