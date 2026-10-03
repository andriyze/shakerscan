"""One bounded remote exec channel with concurrent stdout/stderr draining."""
from __future__ import annotations

import shlex
import time

try:
    from redaction import redact_text
except ModuleNotFoundError:
    from scanner.redaction import redact_text


class OutputCapture:
    def __init__(self, maximum, secrets=()):
        self.maximum = maximum
        self.secrets = tuple(sorted({value for value in secrets if value}, key=len, reverse=True))
        # KMP prefix tables make suffix withholding linear, including large private keys.
        self.prefixes = []
        for secret in self.secrets:
            table = [0] * len(secret)
            matched = 0
            for index in range(1, len(secret)):
                while matched and secret[index] != secret[matched]:
                    matched = table[matched-1]
                if secret[index] == secret[matched]:
                    matched += 1
                table[index] = matched
            self.prefixes.append((secret, table))
        self.data = {'stdout': bytearray(), 'stderr': bytearray()}
        self.truncated = False

    def append(self, name, value):
        remaining = self.maximum - sum(len(item) for item in self.data.values())
        self.data[name].extend(value[:remaining])
        self.truncated |= len(value) > remaining

    def public(self, *, final=False):
        result = {}
        for name, raw in self.data.items():
            text = bytes(raw).decode('utf-8', 'replace')
            for secret in self.secrets:
                text = text.replace(secret, '[REDACTED]')
            # Never publish an incomplete known credential, even on truncated/final output.
            hold = 0
            for secret, table in self.prefixes:
                matched = 0
                for char in text[-len(secret):]:
                    while matched and (matched == len(secret) or char != secret[matched]):
                        matched = table[matched-1]
                    if char == secret[matched]:
                        matched += 1
                hold = max(hold, matched)
            if hold:
                text = text[:-hold] + ('[REDACTED_PARTIAL]' if final else '')
            result[name] = redact_text(text)
        return {**result, 'output_bytes': sum(map(len, self.data.values())),
                'output_truncated': self.truncated, 'output_is_untrusted': True}


def run_command(session, values, *, command, cwd, stopped, capture, on_progress, outcome=None):
    """Never retry after a command request; uncertain execution is a distinct outcome.

    Closing an SSH channel stops local IO. A server may keep a detached process
    alive, so interruption is never reported as confirmed remote termination.
    """
    started = time.monotonic()
    deadline = started + values['timeout_seconds']
    channel = None
    result = outcome if outcome is not None else {}
    result.update({'command_dispatched': False, 'exit_status': None, 'timed_out': False,
              'cancelled': False, 'execution_uncertain': False,
              'remote_termination_confirmed': None})
    try:
        if stopped():
            result['cancelled'] = True
            return result
        channel = session.transport.open_session(timeout=min(5, values['timeout_seconds']))
        channel.settimeout(0.1)
        if stopped():
            result['cancelled'] = True
            return result
        wire_command = command if cwd is None else 'cd -- ' + shlex.quote(cwd) + ' && ' + command
        # Mark before the request: loss of its acknowledgement must not trigger a retry.
        result['command_dispatched'] = True
        channel.exec_command(wire_command)
        channel.shutdown_write()
        while True:
            for name, ready, receive in (
                ('stdout', channel.recv_ready, channel.recv),
                ('stderr', channel.recv_stderr_ready, channel.recv_stderr),
            ):
                for _ in range(16):
                    if not ready():
                        break
                    data = receive(4096)
                    if not data:
                        break
                    capture.append(name, data)
            on_progress(capture.public())
            if stopped():
                result['cancelled'] = True
                break
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                code = channel.recv_exit_status()
                result['exit_status'] = code if code >= 0 else None
                result['execution_uncertain'] = code < 0
                break
            if capture.truncated or time.monotonic() >= deadline:
                result['timed_out'] = time.monotonic() >= deadline
                result['execution_uncertain'] = True
                break
            if channel.closed or not session.transport.is_active():
                result['execution_uncertain'] = True
                break
            time.sleep(0.01)
    except Exception as exc:
        result['error'] = 'ssh_channel:' + type(exc).__name__
        result['execution_uncertain'] = result['command_dispatched']
        result['cancelled'] = bool(stopped())
    finally:
        if channel is not None:
            channel.close()
        if result['cancelled'] or result['timed_out'] or capture.truncated:
            result['execution_uncertain'] = result['command_dispatched'] and result['exit_status'] is None
            result['remote_termination_confirmed'] = False if result['command_dispatched'] else None
        result['command_seconds'] = round(time.monotonic() - started, 4)
    return result
