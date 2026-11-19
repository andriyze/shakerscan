"""Leads a verified finding opens: the class table and the proposals it yields (pure)."""
from uuid import uuid4

from api.hunt.followup_leads import CLASSES, lead_proposals, proven_class
from api.hunt.hunt_hypotheses import DIMENSIONS, FAMILY_PATTERN, SEVERITIES


def _finding(**fields):
    return {'id': uuid4(), 'cwe': None, 'url': 'https://app.test/api/fetch?url=http://x&token=SECRET',
            'evidence': {}, **fields}


def test_the_table_stays_small_and_every_lead_is_a_valid_board_entry():
    leads = [lead for proven in CLASSES for lead in proven.leads]
    assert len(leads) <= 30
    assert len({lead.rule for lead in leads}) == len(leads)
    for lead in leads:
        assert FAMILY_PATTERN.fullmatch(lead.family) and lead.severity in SEVERITIES
        assert len(lead.title) <= 200 and len(lead.description) <= 2000
    # A type or CWE names one class only.
    types = [name for proven in CLASSES for name in proven.types]
    cwes = [name for proven in CLASSES for name in proven.cwes]
    assert len(set(types)) == len(types) and len(set(cwes)) == len(cwes)


def test_a_finding_is_classified_by_its_declared_type_then_its_cwe():
    assert proven_class(_finding(cwe='CWE-918')).name == 'ssrf'
    assert proven_class(_finding(cwe='cwe-89')).name == 'sqli'
    # The declared type wins over a broader CWE.
    assert proven_class(_finding(cwe='CWE-200', evidence={'finding_type': 'bola'})).name == 'bola'
    assert proven_class(_finding(cwe='CWE-200', evidence='{"finding_type": "xss"}')).name == 'xss'
    assert proven_class(_finding(cwe='CWE-1004')) is None
    assert proven_class(_finding(evidence='not json')) is None


def test_a_proposal_names_the_proven_route_without_its_query():
    finding = _finding(cwe='CWE-918', evidence={'method': 'post'})
    [lead] = lead_proposals(finding)
    assert lead['family'] == 'ssrf' and lead['rule'] == 'ssrf_internal_services'
    assert lead['dimensions'] == {'proof_surface': 'ssrf_internal_services', 'route': '/api/fetch', 'method': 'POST'}
    assert lead['finding_id'] == str(finding['id'])
    assert 'SECRET' not in str(lead) and set(lead['dimensions']) <= set(DIMENSIONS)


def test_a_target_wide_lead_is_one_per_finding_and_a_route_lead_needs_a_route():
    finding = _finding(cwe='CWE-639', url=None)
    # Without a URL only the target-wide lead remains.
    [lead] = lead_proposals(finding)
    assert lead['rule'] == 'bola_sibling_objects'
    assert lead['dimensions'] == {'proof_surface': 'bola_sibling_objects', 'object_key': f"finding:{finding['id']}"}
    assert [item['rule'] for item in lead_proposals(_finding(cwe='CWE-639'))] == [
        'bola_write_methods', 'bola_sibling_objects']
    assert lead_proposals(_finding(cwe='CWE-16')) == []
    # An unusual method is left out rather than recorded.
    [ssrf] = lead_proposals(_finding(cwe='CWE-918', evidence={'method': 'PROPFIND; DROP'}))
    assert 'method' not in ssrf['dimensions']
