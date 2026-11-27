"""Incremental canonical SSH events for MCP; never replay an uncertain command."""
import json
import time
import urllib.error
import urllib.request


class SSHStreamError(ValueError):
    """The SSH stream ended without a result.

    ``before_stream`` is true only when the server answered the request with an HTTP error
    instead of opening the stream: nothing was accepted. Once the stream is open the server has
    accepted the action, so an ``error`` event (``status_code``/``detail``) or a stream that ends
    early leaves the command's outcome open; ``action_id`` names the action to inspect."""

    def __init__(self, message, *, before_stream=False, action_id=None, status_code=None,
                 detail=None, body=None):
        super().__init__(message)
        self.before_stream = before_stream
        self.action_id = action_id
        self.status_code = status_code
        self.detail = detail
        self.body = body


def ssh_events(client, path, payload, progress=None):
    request = urllib.request.Request(client.base_url+path,
        data=json.dumps(payload,separators=(',',':')).encode(),method='POST',
        headers={'Accept':'text/event-stream','Content-Type':'application/json',
                 **({'Authorization':'Bearer '+client.api_token} if client.api_token else {})})
    accepted = None
    event = ''
    deadline = time.monotonic()+340
    try:
        response = client.opener.open(request,timeout=340)
    except urllib.error.HTTPError as exc:
        body = exc.read(65536).decode('utf-8', errors='replace')
        raise SSHStreamError('SSH request was answered HTTP %d before the stream opened' % exc.code,
                             before_stream=True, status_code=exc.code, body=body) from exc
    with response:
        if response.headers.get_content_type() != 'text/event-stream':
            raise ValueError('Expected canonical SSH event stream')
        while time.monotonic()<deadline:
            raw = response.readline(2097153)
            if not raw:
                break
            if len(raw)>2097152:
                raise ValueError('SSH event exceeded output limit')
            line = raw.decode('utf-8')
            if line.startswith('event:'):
                event = line[6:].strip()
            elif line.startswith('data:'):
                value = json.loads(line[5:])
                if event=='accepted':
                    accepted = value
                if event in {'accepted','output'} and progress:
                    progress(event,value)
                if event=='result':
                    return value
                if event=='error':
                    action_id = (accepted or {}).get('action_id')
                    raise SSHStreamError(
                        'SSH stream reported an error after the server accepted action '+str(action_id),
                        action_id=action_id, status_code=value.get('status_code'), detail=value.get('detail'))
    action_id = (accepted or {}).get('action_id')
    raise SSHStreamError('SSH stream ended without a terminal result; inspect action '+str(action_id)+' before another command',
                         action_id=action_id)
