import pytest
from tests.disposable_postgres import require_disposable_database

NAME = 'shakerscan_collection_retry_test'


@pytest.mark.parametrize('dsn', [
    'postgresql://127.0.0.1/production',
    f'postgresql://production.example/{NAME}',
    f'postgresql://127.0.0.1/{NAME}?host=production.example',
    f'postgresql://127.0.0.1/{NAME}#anything',
    f'http://127.0.0.1/{NAME}',
    '',
])
def test_only_explicit_disposable_local_database_is_allowed(dsn):
    with pytest.raises(ValueError): require_disposable_database(dsn, NAME)


def test_local_named_test_database_is_accepted():
    dsn = f'postgresql://postgres:fixture@127.0.0.1:5432/{NAME}'
    assert require_disposable_database(dsn, NAME) == dsn


def test_collection_fixture_has_unique_host_identity_and_real_parser_input():
    from uuid import uuid4
    from urllib.parse import urlsplit
    from tests.collection_upload_fixtures import collection_upload_fixture
    from scanner.scanner_tools.request_collections import validate_and_index
    origins = set()
    for _ in range(2):
        origin, payload = collection_upload_fixture(uuid4())
        origins.add(urlsplit(origin).hostname)
        _, summary, index = validate_and_index(payload['document'], payload['environment'])
        assert summary['request_count'] == len(index) == 1
        assert index[0]['redacted_url'] == origin + '/items'
    assert len(origins) == 2  # targets.url and canonical_key are both unique in PostgreSQL.
