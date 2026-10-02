"""Metadata authority and explicit fixed-tool discovery through the Hunt contract."""
from dataclasses import replace

import pytest

from api.hunt.contracts import capability_manifest
from api.hunt.start_contract import normalize_hunt_start_payload
from api.runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError


@pytest.mark.parametrize('kind', ['web', 'api', 'network', 'device'])
def test_passive_hunt_can_manage_metadata_without_granting_testing(kind):
    contract = normalize_hunt_start_payload({
        'target_id':'target-1','target_kind':kind,'goal':'Rename the target and register my TV',
        'policy':{'active_testing':False},'budgets':{'max_active_actions':0},
    })
    names = {item['name'] for item in capability_manifest(contract, credentials_available=False)}
    assert {'targets.create', 'targets.update'} <= names
    assert not names & {'credentials.grant', 'collections.bind', 'ports.discover', 'xss.verify', 'templates.scan'}
    for name in ('targets.create', 'targets.update'):
        spec = CAPABILITY_REGISTRY.require(name)
        assert spec.required_approval == 'operator_intent'
        assert not spec.requires_active_approval
        with pytest.raises(CapabilityInputContractError):
            CAPABILITY_REGISTRY.validate_hunt_input(name, {'operator_confirmed':False})


@pytest.mark.parametrize('changes', [
    {'binary':'nmap'}, {'risk_tier':'active'}, {'hunt_executor':'worker_network'},
    {'placement_requirements':{'control_plane':True,'user_confirmation':True,'network_reachability':True}},
    {'budget_cost':{'http_requests':1}},
])
def test_operator_intent_cannot_become_network_authority(changes):
    with pytest.raises(ValueError, match='metadata actions'):
        replace(CAPABILITY_REGISTRY.require('targets.create'), **changes)


@pytest.mark.parametrize('name,binary', [
    ('service.fingerprint','nmap'), ('service.nse_check','nmap'),
    ('templates.scan','nuclei'), ('sqli.verify','sqlmap'), ('xss.verify','dalfox'),
    ('ports.discover','naabu'), ('subdomains.discover','subfinder'),
    ('web.probe','httpx'), ('web.crawl','katana'), ('web.content_discover','ffuf'),
])
def test_tool_contract_names_the_real_executor_without_planner_process_control(name, binary):
    spec = CAPABILITY_REGISTRY.require(name)
    declaration = spec.planner_contract()
    assert declaration['tool']['binary'] == binary
    assert declaration['tool']['name'] == binary
    assert declaration['call']['url_template'].endswith('/capabilities/'+name)
    assert not {'argv','binary','command','tool_name'} & set(declaration['input_schema']['properties'])


def test_nuclei_filters_reach_fixed_argv_and_cannot_override_template_authority():
    from api import agent_tools
    options = agent_tools.canonical_hunt_scanner_options('templates.scan', {
        'path':'/status', 'severity':'medium,info', 'tags':'exposure,config',
    })
    argv = agent_tools._tmpl_nuclei('https://tv.test:8443/status', options)
    assert argv[argv.index('-severity')+1] == 'medium,info'
    assert argv[argv.index('-tags')+1] == 'exposure,config'
    assert argv[argv.index('-id')+1] == agent_tools._CANONICAL_PASSIVE_NUCLEI_IDS
    assert '-no-interactsh' in argv and '-disable-redirects' in argv
    for unsafe in ({'tags':'exposure;echo unsafe'}, {'severity':'--unsafe'}, {'template_ids':'external-template'}):
        with pytest.raises(ValueError):
            agent_tools.canonical_hunt_scanner_options('templates.scan', unsafe)


def test_public_contract_lists_every_planner_tool_without_granting_it_to_a_passive_run():
    from api.hunt.start_contract import hunt_start_public_contract
    catalog = hunt_start_public_contract()['tool_calls']
    assert {item['name'] for item in catalog} == {
        spec.name for spec in CAPABILITY_REGISTRY.list() if spec.planner_visible
    }
    assert len(catalog) == len({item['name'] for item in catalog})
    assert next(item for item in catalog if item['name']=='templates.scan')['required_approval']=='active_testing'
