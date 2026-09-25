"""POST /public/check: the bounded posture check, run by the same engine as pub.shakerscan.com.

The engine (``posture/``, bundled into the API image) receives the raw request body on stdin
and answers ``{"status", "body"}`` on stdout, so request validation, observations and error
documents are byte-for-byte the public service's schema. On an instance no quota, cache or
target restriction applies: the operator decides what to check.
"""
from __future__ import annotations

import asyncio
import json
import os

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=['Public check'])

ENGINE_PATH = os.getenv('SHAKERSCAN_POSTURE_ENGINE', '/opt/shakerscan/posture/instance.cjs')
NODE_BINARY = os.getenv('SHAKERSCAN_POSTURE_NODE', '/usr/local/bin/node')
MAX_REQUEST_BYTES = 2048
MAX_RESULT_BYTES = 262_144
# The engine bounds itself at 8 seconds; this covers process start and a slow exit.
ENGINE_TIMEOUT_SECONDS = 15
_concurrency = asyncio.Semaphore(max(1, int(os.getenv('SHAKERSCAN_POSTURE_CONCURRENCY', '4') or 4)))


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({'error': {'code': code, 'message': message}}, status_code=status,
                        headers={'Cache-Control': 'no-store'})


def _engine_environment() -> dict[str, str]:
    """Only what the engine needs; API credentials and database settings never reach it."""
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp', 'NODE_ENV': 'production'}
    resolver = os.getenv('SHAKERSCAN_POSTURE_RESOLVER', '').strip()
    if resolver in {'system', 'doh'}:
        env['POSTURE_RESOLVER'] = resolver
    token = os.getenv('SHAKERSCAN_POSTURE_IPINFO_TOKEN', '').strip()
    if token:
        env['POSTURE_IPINFO_TOKEN'] = token
    return env


async def run_engine(body: bytes) -> tuple[int, object]:
    """Run one check; returns the engine's HTTP status and JSON document."""
    async with _concurrency:
        try:
            process = await asyncio.create_subprocess_exec(
                NODE_BINARY, ENGINE_PATH,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                env=_engine_environment(), cwd='/tmp')
        except OSError:
            return 503, {'error': {'code': 'service_unavailable', 'message': 'The check engine is not installed in this image.'}}
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(body), ENGINE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return 504, {'error': {'code': 'timeout', 'message': 'Public check deadline exceeded.'}}
    try:
        result = json.loads(stdout[:MAX_RESULT_BYTES]) if len(stdout) <= MAX_RESULT_BYTES else None
    except ValueError:
        result = None
    if not isinstance(result, dict) or not isinstance(result.get('status'), int) or not 200 <= result['status'] <= 599 \
            or not isinstance(result.get('body'), dict):
        return 503, {'error': {'code': 'service_unavailable', 'message': 'The check engine returned an invalid result.'}}
    return result['status'], result['body']


@router.post('/public/check')
async def public_check(request: Request):
    """DNS, email, HTTP and TLS posture observations (schema 2) for a hostname or IP address."""
    if 'json' not in request.headers.get('content-type', '').lower():
        return _error(415, 'unsupported_media_type', 'Use application/json encoded as UTF-8.')
    body = b''
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_REQUEST_BYTES:
            return _error(413, 'body_too_large', 'Request body exceeds the allowed size.')
    status, document = await run_engine(body)
    return JSONResponse(document, status_code=status, headers={'Cache-Control': 'no-store'})
