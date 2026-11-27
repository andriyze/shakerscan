"""Strict opt-in guard for integration tests that reset a local test schema."""
from urllib.parse import urlsplit


def require_disposable_database(dsn: str, database: str) -> str:
    value = urlsplit(dsn)
    if (value.scheme not in {'postgres', 'postgresql'}
            or value.hostname not in {'localhost', '127.0.0.1', '::1'}
            or value.path != '/' + database or value.query or value.fragment):
        raise ValueError('Refusing a nonlocal, ambiguous, or non-test PostgreSQL database')
    return dsn
