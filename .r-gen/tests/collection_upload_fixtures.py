"""Synthetic collection input with unique target identity; never sends traffic."""
from uuid import UUID


def collection_upload_fixture(target: UUID):
    origin = f'https://{target.hex}.collection.example.invalid'
    return origin, {
        'target_id': str(target), 'name': 'Synthetic ' + target.hex,
        'document': {
            'info': {'name': 'Synthetic upload', 'schema': 'v2.1'},
            'item': [{'name': 'metadata only', 'request': {'method': 'GET', 'url': origin + '/items'}}],
        },
        'environment': {'name': 'synthetic environment', 'values': [
            {'key': 'token', 'value': 'fixture-not-a-real-secret', 'enabled': True},
        ]},
    }