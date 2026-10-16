"""Observed corporate product names use exact CPE identities, including OS parts."""
import pytest

from api.exposure.service_intel import derived_cpes, enrich_service
from scanner.scanner_tools.device_advisories import match_advisories


@pytest.mark.parametrize('product,identity', [
    ('Fortinet FortiOS', 'o:fortinet:fortios'),
    ('FortiOS', 'o:fortinet:fortios'),
    ('Palo Alto Networks PAN-OS', 'o:paloaltonetworks:pan-os'),
    ('PAN-OS', 'o:paloaltonetworks:pan-os'),
    ('Ivanti Connect Secure', 'a:ivanti:connect_secure'),
    ('Citrix NetScaler Application Delivery Controller', 'a:citrix:netscaler_application_delivery_controller'),
    ('Atlassian Confluence Server', 'a:atlassian:confluence_server'),
    ('Atlassian Confluence Data Center', 'a:atlassian:confluence_data_center'),
    ('Atlassian Jira Server', 'a:atlassian:jira_server'),
    ('Atlassian Jira Data Center', 'a:atlassian:jira_data_center'),
])
def test_exact_corporate_fingerprint_reaches_existing_advisory_and_kev_pipeline(product, identity):
    cpe = f'cpe:2.3:{identity}:1.2.3:*:*:*:*:*:*:*'
    assert derived_cpes(product, '1.2.3') == [cpe]
    record = {'cve': 'CVE-2026-99999', 'cpe': f'cpe:2.3:{identity}:*:*:*:*:*:*:*:*',
              'product': identity.split(':')[-1], 'version_end_including': '1.2.4',
              'known_exploited': {'date_added': '2026-10-01', 'ransomware': False}}
    service = {'product': product, 'version': '1.2.3', 'cpes': [], 'findings': []}
    enrich_service(service, {'status': 'available', 'advisories': [record]}, match_advisories)
    candidate, = service['cve_candidates']
    assert candidate['version_evaluation'] == 'affected'
    assert candidate['known_exploited']['date_added'] == '2026-10-01'
    assert candidate['applicability'] == 'candidate'
    assert candidate['local_validation'] == 'no_linked_validation'
    assert service['findings'] == []
    service['version'] = '1.2.5'
    enrich_service(service, {'status': 'available', 'advisories': [record]}, match_advisories)
    assert service['cve_candidates'] == []


@pytest.mark.parametrize('product,version', [
    ('Fortinet', '1.2.3'), ('FortiGate', '1.2.3'), ('Citrix', '1.2.3'),
    ('Confluence', '1.2.3'), ('FortiOS', None), ('PAN-OS', 'latest'),
    ('Ivanti Connect Secure', '1.2.3:*:*'),
])
def test_ambiguous_vendor_or_unknown_version_never_invents_cpe(product, version):
    assert derived_cpes(product, version) == []


def test_explicit_cpe_is_not_replaced_by_a_product_alias():
    seen = []
    def matcher(records, **kwargs):
        seen.append(kwargs['cpe'])
        return []
    explicit = 'cpe:2.3:h:fortinet:fortigate:1:*:*:*:*:*:*:*'
    enrich_service({'product': 'FortiOS', 'version': '1.2.3', 'cpes': [explicit]},
                   {'status': 'available', 'advisories': []}, matcher)
    assert seen == [explicit]
