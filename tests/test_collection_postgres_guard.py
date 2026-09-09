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
