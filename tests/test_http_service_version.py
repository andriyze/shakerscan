"""Observed HTTP Server product/version pairs must reach existing advisory matching."""
import pytest

from api.exposure.service_inventory import normalized_observation
from api.exposure.service_intel import enrich_service
from scanner.scanner_tools.device_advisories import match_advisories


def fingerprint(banner, **extra):
    return {'kind': 'http_fingerprint', 'url': 'https://app.example.test:8443/login',
            'status': 200, 'webserver': banner, **extra}


@pytest.mark.parametrize('banner,product,version', [
    ('nginx/1.18.0', 'nginx', '1.18.0'),
    ('Apache/2.4.49 (Unix)', 'Apache', '2.4.49'),
    ('Microsoft-IIS/10.0', 'Microsoft-IIS', '10.0'),
    ('OpenResty/1.21.4.1', 'OpenResty', '1.21.4.1'),
])
def test_positive_http_banner_retains_product_version_and_exact_listener(banner, product, version):
    service = normalized_observation(fingerprint(banner))
    assert service['product'] == product and service['version'] == version
    assert service['application_origin'] == 'https://app.example.test:8443'
    assert service['port'] == 8443 and service['identity_basis'] == 'http_response'


def test_named_http_version_reaches_cpe_match_without_becoming_verified():
    service = normalized_observation(fingerprint('Apache/2.4.49 (Unix)'))
    record = {'cve': 'CVE-2026-99999', 'cpe': 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
              'product': 'http_server', 'version_end_including': '2.4.49'}
    enrich_service(service, {'status': 'available', 'advisories': [record]}, match_advisories)
    candidate, = service['cve_candidates']
    assert candidate['version_evaluation'] == 'affected'
    assert candidate['applicability'] == 'candidate'
    assert candidate['local_validation'] == 'no_linked_validation'


@pytest.mark.parametrize('banner', ['nginx', 'nginx/latest', 'nginx/', 'nginx/1.24\nother',
                                  'nginx/1.24:*:*', 'Unknown Gateway', 'nginx/' + '1' * 300])
def test_missing_or_malformed_version_never_becomes_an_exact_product_version(banner):
    service = normalized_observation(fingerprint(banner))
    assert service['version'] is None


def test_unreached_or_redirected_service_is_not_inferred_from_a_server_banner():
    assert normalized_observation(fingerprint('Apache/2.4.49', status=None)) is None
    service = normalized_observation(fingerprint('nginx/1.24', status=302,
        final_url='https://other.example.test:9000/'))
    assert service['application_origin'] == 'https://app.example.test:8443'
