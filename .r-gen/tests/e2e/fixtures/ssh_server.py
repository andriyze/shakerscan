"""Disposable SSH identity fixture; no command or shell channel is accepted."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
import time

import paramiko

KEY = paramiko.RSAKey.generate(2048)
FINGERPRINT = 'SHA256:' + base64.b64encode(hashlib.sha256(KEY.asbytes()).digest()).decode().rstrip('=')
LOCK = threading.Lock()
STATS = {'authentication_attempts': 0, 'successful_logins': 0, 'channel_requests': 0}


class Identity(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        success = username == 'fixture-operator' and password == 'fixture-only-password'
        with LOCK:
            STATS['authentication_attempts'] += 1
            STATS['successful_logins'] += int(success)
        return paramiko.AUTH_SUCCESSFUL if success else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        with LOCK:
            STATS['channel_requests'] += 1
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def connection(sock):
    transport = paramiko.Transport(sock)
    try:
        transport.add_server_key(KEY)
        transport.start_server(server=Identity())
        while transport.is_active():
            time.sleep(0.05)
    except (EOFError, OSError, paramiko.SSHException):
        pass
    finally:
        transport.close()


def listen(port):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', port))
    listener.listen(16)
    while True:
        sock, _ = listener.accept()
        threading.Thread(target=connection, args=(sock,), daemon=True).start()


class Stats(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        with LOCK:
            data = json.dumps({**STATS, 'host_key_fingerprint': FINGERPRINT}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == '__main__':
    for port in (22, 2222):
        threading.Thread(target=listen, args=(port,), daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0', 8081), Stats).serve_forever()
