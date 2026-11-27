"""Buffered write bodies must not starve SSH/SSE disconnect listeners."""
import asyncio
import json

import pytest

from api.public_api_contract import PublicV2BodyLimitMiddleware, PUBLIC_V2_WRITE_BODY_LIMITS


@pytest.mark.parametrize('chunks', [[b'{}'], [b'{', b'}'], [b'']])
def test_buffer_replays_once_then_waits_for_the_real_disconnect(chunks):
    async def run():
        source = asyncio.Queue()
        expected = [dict(type='http.request', body=chunk, more_body=index < len(chunks)-1)
                    for index, chunk in enumerate(chunks)]
        for message in expected:
            source.put_nowait(message)

        async def app(scope, receive, send):
            for message in expected:
                assert await receive() == message
            listener = asyncio.create_task(receive())
            try:
                await asyncio.sleep(0)
                assert not listener.done(), 'Body middleware fabricated another request instead of awaiting disconnect'
                source.put_nowait({'type': 'http.disconnect'})
                assert await asyncio.wait_for(listener, 1) == {'type': 'http.disconnect'}
            finally:
                listener.cancel()
                await asyncio.gather(listener, return_exceptions=True)

        async def send(message):
            raise AssertionError('This test does not send a response')

        await PublicV2BodyLimitMiddleware(app)(
            {'type': 'http', 'method': 'POST', 'path': '/hunts/fixture/ssh/exec', 'headers': []},
            source.get, send)
    asyncio.run(run())


def test_streaming_route_still_rejects_oversized_chunked_body_before_dispatch():
    async def run():
        source = asyncio.Queue()
        source.put_nowait({'type': 'http.request', 'body': b'x' * (PUBLIC_V2_WRITE_BODY_LIMITS['hunt']+1),
                          'more_body': False})
        sent = []
        async def app(scope, receive, send):
            raise AssertionError('Oversized input reached the application')
        async def send(message):
            sent.append(message)
        await PublicV2BodyLimitMiddleware(app)(
            {'type': 'http', 'method': 'POST', 'path': '/hunts/fixture/ssh/exec', 'headers': []},
            source.get, send)
        assert sent[0]['status'] == 413
        assert json.loads(sent[1]['body'])['detail']['error'] == 'request_body_too_large'
    asyncio.run(run())
