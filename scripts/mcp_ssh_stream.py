"""Incremental canonical SSH events for MCP; never replay an uncertain command."""
import json
import time
import urllib.request


def ssh_events(client, path, payload, progress=None):
    request = urllib.request.Request(client.base_url+path,
        data=json.dumps(payload,separators=(',',':')).encode(),method='POST',
        headers={'Accept':'text/event-stream','Content-Type':'application/json',
                 **({'Authorization':'Bearer '+client.api_token} if client.api_token else {})})
    accepted = None
    event = ''
    deadline = time.monotonic()+340
    with client.opener.open(request,timeout=340) as response:
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
                    raise ValueError('Canonical SSH action refused: '+str(value.get('detail')))
    raise ValueError('SSH stream ended without a terminal result; inspect action '+str((accepted or {}).get('action_id'))+' before another command')
