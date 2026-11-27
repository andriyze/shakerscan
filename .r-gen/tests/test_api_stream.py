"""Stream output is incremental, bounded, and never resubmits an uncertain command."""
import io
from email.message import Message
from types import SimpleNamespace
import urllib.request

import pytest

from scripts.api_stream import stream_response


class Response(io.BytesIO):
    def __init__(self, body, mime='text/event-stream'):
        super().__init__(body)
        self.headers = Message()
        self.headers['Content-Type'] = mime


def invoke(body):
    output = io.StringIO()
    response = Response(body)
    request = urllib.request.Request('https://fixture.invalid/hunts/run/ssh/exec')
    calls = []
    def open_request(*args,**kwargs):
        calls.append(args)
        return response
    result = stream_response(request,opener=SimpleNamespace(open=open_request),timeout=5,output=output)
    assert len(calls)==1
    return result,output.getvalue()


def test_events_are_printed_without_buffering_the_completed_http_response():
    body=b'event: output\ndata: {"stdout":"first"}\n\nevent: result\ndata: {"action_result":{"status":"success"}}\n\n'
    status,text=invoke(body)
    assert status==0 and 'first' in text and text.endswith('\n\n')


def test_failure_event_is_not_a_successful_cli_result():
    assert invoke(b'event: error\ndata: {"status_code":403}\n\n')[0]==1


def test_interrupted_stream_never_retries():
    with pytest.raises(ValueError,match='before a terminal result'):
        invoke(b'event: output\ndata: {"stdout":"partial"}\n\n')
