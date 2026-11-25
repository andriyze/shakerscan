"""A path SQLi uses the same repeated proof, bound to one manifest segment."""
import json
from urllib.parse import unquote, urlsplit

import pytest

from api.capabilities.sqli_proof import SQLiProofError
from api.runtime.request_replay_executor import ReplayTransportResult
from tests.test_sqli_proof_capability import _request, _run, _run_with_budget


def candidate(**changes):
    return {'candidate_id': 'd' * 64, 'method': 'GET', 'parameter_location': 'path',
            'parameter_name': 'path_4', 'path_segment_index': 4,
            'canonical_path': '/users/v1/name/{int}', 'request_class': 'safe_read', **changes}


class PathTransport:
    def __init__(self, echo=False):
        self.requests = []
        self.echo = echo

    async def send(self, request, **kwargs):
        self.requests.append(request)
        value = unquote(urlsplit(request.url).path.split('/')[4])
        if self.echo:
            body = json.dumps({'value': value}).encode()
        else:
            body = b'SQLite error: unrecognized token' if value.endswith("'") else b'{"user":1}'
        return ReplayTransportResult(status_code=200, connected_address='192.0.2.10',
            final_url=request.url, response_headers={'Content-Type': 'application/json'},
            response_body=body, elapsed_ms=5)


def test_path_error_differential_proves_only_after_repeated_control_payload_pairs():
    transport = PathTransport()
    result = _run(_request(url='https://app.example.test/users/v1/name/1*'), candidate(), transport)
    assert result.observations[0]['proof_state'] == 'verified'
    assert result.observations[0]['proof_contract'] == 'sqli_error_differential/v2'
    assert result.actual_budget['http_requests'] == 4
    paths = [urlsplit(r.url).path for r in transport.requests]
    assert paths == ['/users/v1/name/1', '/users/v1/name/1%27'] * 2
    assert all(r.method == 'GET' for r in transport.requests)


def test_path_echo_is_not_boolean_proof_and_budget_stays_bounded():
    transport = PathTransport(echo=True)
    result = _run_with_budget(_request(url='https://app.example.test/users/v1/name/1*'),
                             candidate(), transport, http_requests=8)
    assert result.observations[0]['proof_state'] == 'not_proven'
    assert result.actual_budget['http_requests'] == len(transport.requests) == 8


def test_uuid_segment_uses_its_own_value_without_changing_the_route():
    value = '10000000-0000-4000-8000-000000000001'
    transport = PathTransport()
    result = _run(_request(url=f'https://app.example.test/users/v1/name/{value}*'),
                  candidate(canonical_path='/users/v1/name/{uuid}'), transport)
    assert result.observations[0]['proof_state'] == 'verified'
    assert urlsplit(transport.requests[0].url).path.endswith(value)
    assert urlsplit(transport.requests[1].url).path.endswith(value + '%27')


def test_payload_delimiters_cannot_change_origin_or_escape_the_selected_segment():
    transport = PathTransport(echo=True)
    result = _run(_request(url='https://app.example.test/users/v1/name/1*'),
                  candidate(time_payload="1'/../../other?x=1#@evil.test"), transport)
    assert result.observations[0]['proof_state'] == 'not_proven'
    assert len(transport.requests) == 14
    for request in transport.requests:
        parsed = urlsplit(request.url)
        assert parsed.scheme == 'https' and parsed.netloc == 'app.example.test'
        assert not parsed.query and not parsed.fragment
        assert len(parsed.path.split('/')) == 5


@pytest.mark.parametrize('changes', [
    {'path_segment_index': True}, {'path_segment_index': -1}, {'path_segment_index': 3},
    {'path_segment_index': 9}, {'parameter_name': 'q'},
    {'canonical_path': '/users/v1/name/1'},
    {'canonical_path': '/other/v1/name/{int}'},
    {'canonical_path': '/users/v1/name/{uuid}'},
    {'method': 'POST'},
])
def test_malformed_or_conflicting_path_authority_is_refused_before_traffic(changes):
    transport = PathTransport()
    with pytest.raises(SQLiProofError):
        _run(_request(url='https://app.example.test/users/v1/name/1*'), candidate(**changes), transport)
    assert transport.requests == []
