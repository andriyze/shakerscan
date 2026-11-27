"""Incremental SSE output for the shared API CLI; no retries or redirects."""
from __future__ import annotations

import json
import sys
import time
import urllib.error

MAX_EVENT_LINE_BYTES = 2 * 1024 * 1024


def stream_response(request, *, opener, timeout, output=None):
    output = output or sys.stdout
    request.add_header('Accept', 'text/event-stream')
    deadline = time.monotonic() + timeout
    event = ''
    terminal = False
    failed = False
    with opener.open(request, timeout=timeout) as response:
        if response.headers.get_content_type() != 'text/event-stream':
            raise ValueError('The instance did not return an event stream')
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError('SSH stream deadline reached; the connection is closed, never retried')
            raw = response.readline(MAX_EVENT_LINE_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_EVENT_LINE_BYTES:
                raise ValueError('The instance returned an oversized SSE line')
            line = raw.decode('utf-8', 'replace')
            if line.startswith('event:'):
                event = line[6:].strip()
            elif line.startswith('data:'):
                value = json.loads(line[5:])
                if event == 'error':
                    failed = terminal = True
                elif event == 'result':
                    terminal = True
                    failed = value.get('action_result', {}).get('status') not in {'success', 'queued'}
            if not line.startswith(':'):
                output.write(line)
                output.flush()
    if not terminal:
        raise ValueError('Stream ended before a terminal result; do not automatically resend the command')
    return 1 if failed else 0
