"""Drain authenticated SSH completion packets even when channel close races IO."""
from types import SimpleNamespace

import pytest

from api.capabilities.ssh_channel import OutputCapture, run_command


class CompletingChannel:
    closed = False

    def __init__(self, code, payload_size=4):
        self.code = code
        self.payload = b'x' * payload_size
        self.stdout = b''
        self.stderr = b''
        self.dispatched = []
        self.arrived = False

    def settimeout(self, value): pass
    def shutdown_write(self): pass
    def exec_command(self, command): self.dispatched.append(command)
    def recv_ready(self): return bool(self.stdout)
    def recv_stderr_ready(self): return bool(self.stderr)

    def recv(self, size):
        value, self.stdout = self.stdout[:size], self.stdout[size:]
        return value

    def recv_stderr(self, size):
        value, self.stderr = self.stderr[:size], self.stderr[size:]
        return value

    def exit_status_ready(self):
        # The reader observed no exit status, then the transport thread delivered
        # output, exit-status and close before the following closed-channel check.
        if not self.arrived:
            self.arrived = True
            self.stdout, self.stderr = self.payload, b'err\n'
            self.closed = True
            return False
        return True

    def recv_exit_status(self): return self.code
    def close(self): self.closed = True


def execute(channel, maximum=262144, stopped=lambda: False):
    transport = SimpleNamespace(open_session=lambda **kwargs: channel, is_active=lambda: True)
    capture = OutputCapture(maximum)
    result = run_command(SimpleNamespace(transport=transport), {'timeout_seconds': 2},
        command='fixture-command', cwd=None, stopped=stopped, capture=capture,
        on_progress=lambda value: None)
    return result, capture.public(final=True)


@pytest.mark.parametrize('code', [0, 7, -1])
@pytest.mark.parametrize('payload_size', [4, 150000])
def test_closed_channel_drains_buffered_output_and_keeps_actual_exit_status(code, payload_size):
    channel = CompletingChannel(code, payload_size)
    result, output = execute(channel)
    assert output['stdout'] == 'x' * payload_size
    assert output['stderr'] == 'err\n'
    assert result['exit_status'] == (code if code >= 0 else None)
    assert result['execution_uncertain'] is (code < 0)
    assert not result['timed_out'] and not result['cancelled']
    assert channel.dispatched == ['fixture-command']


def test_terminal_output_still_obeys_capture_limit():
    channel = CompletingChannel(7, 150000)
    result, output = execute(channel, maximum=1024)
    assert output['output_bytes'] == 1024
    assert output['output_truncated']
    assert result['execution_uncertain']
    assert result['exit_status'] is None
    assert channel.dispatched == ['fixture-command']


def test_cancel_after_dispatch_still_stops_before_classifying_completion():
    channel = CompletingChannel(0)
    result, output = execute(channel, stopped=lambda: bool(channel.dispatched))
    assert result['cancelled'] and result['execution_uncertain']
    assert result['exit_status'] is None
    assert channel.dispatched == ['fixture-command']


def test_real_server_completion_between_output_poll_and_status_check(tmp_path):
    import time
    import paramiko
    from tests.ssh_exec_fixture import CommandServer, PASSWORD, USERNAME

    fixture = CommandServer(tmp_path)
    command = "sleep 0.05; printf 'out\\n'; printf 'err\\n' >&2; exit 7"
    fixture.allow(command)
    client = paramiko.SSHClient()
    client.get_host_keys().add(f'[127.0.0.1]:{fixture.port}', fixture.key.get_name(), fixture.key)
    channel = None
    try:
        client.connect('127.0.0.1', port=fixture.port, username=USERNAME, password=PASSWORD,
            look_for_keys=False, allow_agent=False, timeout=3, auth_timeout=3, banner_timeout=3)
        transport = client.get_transport()
        open_session = transport.open_session
        def tracked_session(**kwargs):
            nonlocal channel
            channel = open_session(**kwargs)
            return channel
        session = SimpleNamespace(transport=SimpleNamespace(
            open_session=tracked_session, is_active=transport.is_active))
        def progress(value):
            # A slow stream consumer lets real transport packets arrive after
            # the first drain, before the production loop checks completion.
            deadline = time.monotonic() + 2
            while not channel.closed and time.monotonic() < deadline:
                time.sleep(0.001)
            assert channel.closed, 'fixture did not close the exec channel'
        capture = OutputCapture(1024)
        result = run_command(session, {'timeout_seconds': 3}, command=command,
            cwd=None, stopped=lambda: False, capture=capture, on_progress=progress)
        assert result['exit_status'] == 7 and not result['execution_uncertain'], result
        output = capture.public(final=True)
        assert output['stdout'] == 'out\n' and output['stderr'] == 'err\n'
        assert fixture.commands == [command] and fixture.logins == 1
    finally:
        client.close()
        fixture.close()
