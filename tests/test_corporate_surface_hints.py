import json
import pytest

from scanner.scanner_tools.surface_hints import corporate_surface_hints
from api.capabilities.artifact import analyze_javascript_bytes


def test_embedded_tenant_and_storage_urls_are_unverified_leads_without_secrets():
    text = '''const authority="https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0?client_secret=private-value";
    const object="https://demo-bucket.s3.eu-west-1.amazonaws.com/private-file?X-Amz-Signature=private-signature";
    const blob="https://demoaccount.blob.core.windows.net/container/private-name?sig=private-sas";
    const gcs="https://storage.googleapis.com/example-bucket/private-name?token=private-token";
    const realm="https://identity.fixture.invalid/realms/demo/protocol/openid-connect/auth";'''
    hints = corporate_surface_hints(text)
    assert {hint['provider'] for hint in hints} == {
        'microsoft_entra', 'amazon_s3', 'azure_blob', 'google_cloud_storage', 'keycloak_candidate'}
    assert all(hint['ownership'] == 'unconfirmed' and hint['access_state'] == 'not_tested' for hint in hints)
    assert 'private-' not in json.dumps(hints)
    assert all('?' not in hint['origin'] and '/' not in hint['identifier'] for hint in hints)


def test_deceptive_provider_suffixes_userinfo_and_shared_audiences_are_not_tenants():
    text = '''"https://login.microsoftonline.com.evil.invalid/demo.onmicrosoft.com"
    "https://login.microsoftonline.com/common/v2.0"
    "https://login.microsoftonline.com/not-a-tenant"
    "https://password@demo.s3.amazonaws.com/object"
    "https://demo.s3.amazonaws.com.evil.invalid/object"
    "https://demo.blob.core.windows.net.evil.invalid/object"'''
    assert corporate_surface_hints(text) == []


def test_hints_deduplicate_and_have_hard_size_limits():
    content = ' '.join(f'"https://bucket-{i}.s3.amazonaws.com/object"' for i in range(1000))
    hints = corporate_surface_hints(content)
    assert len(hints) == 50
    assert len(corporate_surface_hints(content[:50] * 100)) <= 1
    assert corporate_surface_hints('x' * 262144 + content) == []
    secret = 'sk_live_' + 'aB12cD34eF56gH78' * 2
    assert corporate_surface_hints(f'"https://identity.fixture.invalid/realms/{secret}"') == []


def test_hunt_reuses_scan_http_shapes_for_routes_outside_api_prefix_without_body_values():
    body = b'''const api=axios.create({baseURL:"/workshop"});
    api.get('/users/v1/_debug', {params:{tenant:'private-query'}});
    fetch('/login', {method:'POST', body:JSON.stringify({username:'private-user',password:'private-password'})});'''
    result = analyze_javascript_bytes(body)
    shapes = {item['url']: item for item in result['request_shapes']}
    assert shapes['/workshop/users/v1/_debug']['method'] == 'GET'
    assert shapes['/workshop/users/v1/_debug']['query_parameter_names'] == ['tenant']
    assert shapes['/login']['body_parameter_names'] == ['username', 'password']
    assert shapes['/login']['method'] == 'POST'
    assert all(item['reachability'] == 'unverified' for item in shapes.values())
    assert 'private-' not in json.dumps(result)


@pytest.mark.parametrize('path', [
    '/storage/v1/b/example-bucket',
    '/storage/v1/b/example-bucket/o/private-object',
    '/download/storage/v1/b/example-bucket/o/private-object',
    '/upload/storage/v1/b/example-bucket/o',
    '/example-bucket/private-object',
])
def test_google_storage_api_and_xml_paths_name_the_actual_bucket_only(path):
    hints = corporate_surface_hints(f'https://storage.googleapis.com{path}?token=private-value')
    assert len(hints) == 1
    assert hints[0]['identifier'] == 'example-bucket'
    assert 'private-' not in json.dumps(hints)
    result = analyze_javascript_bytes(f'const storage="https://storage.googleapis.com{path}"'.encode())
    assert result['corporate_surface_leads'] == hints


@pytest.mark.parametrize('path', [
    '/storage/v1/b?project=example-project',
    '/storage/v1/b/',
    '/upload/storage/v1/b',
    '/download/storage/v1/b',
    '/storage/v1/b/with%2Fslash/o/private-object',
])
def test_google_storage_collections_do_not_invent_a_bucket(path):
    assert corporate_surface_hints(f'https://storage.googleapis.com{path}') == []


def test_google_storage_xml_bucket_can_itself_be_named_storage():
    hints = corporate_surface_hints('https://storage.googleapis.com/storage/private-object')
    assert hints[0]['identifier'] == 'storage'
