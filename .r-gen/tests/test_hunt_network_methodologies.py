"""Network and household-device knowledge uses the same real Hunt skill lifecycle."""
import asyncio
import copy
from pathlib import Path

import pytest

from api.hunt.run_service import HuntRunService
from api.hunt.skills import bind_skills_to_hunt, load_skill_library
from scripts.generate_install_manifest import installer_paths
from tests.test_hunt_skill_lifecycle import _Connection, _Pool

BASELINE = 'skill.network.discovery-and-service-assessment'
SPECIALISTS = ('skill.network.smart-tv-assessment', 'skill.network.camera-assessment',
               'skill.network.router-assessment')
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope='module')
def library():
    return load_skill_library()


@pytest.mark.parametrize('kind', ['web', 'api', 'network', 'device'])
def test_naabu_objective_routes_to_executable_baseline(library, kind):
    suggestion = library.suggest(goal='Scan ports with naabu', target_kind=kind,
                                 allowed_capabilities=['ports.discover','service.fingerprint'])[0]
    assert suggestion['skill_id'] == BASELINE
    assert suggestion['execution']['fully_executable'] is True
    assert suggestion['execution']['missing_capabilities'] == []
    assert suggestion['auto_bound'] is False


@pytest.mark.parametrize('kind', ['network', 'device'])
def test_generic_asset_objective_gets_basic_network_baseline(library, kind):
    assert library.suggest(goal='Investigate', target_kind=kind)[0]['skill_id'] == BASELINE


@pytest.mark.parametrize('kind', ['network', 'device'])
@pytest.mark.parametrize(('objective','skill'), [
    ('Assess my home smart TV', SPECIALISTS[0]),
    ('Test my IP camera management interface', SPECIALISTS[1]),
    ('Assess my home router', SPECIALISTS[2]),
])
def test_device_objectives_select_focused_methodologies(library, kind, objective, skill):
    suggestion = library.suggest(goal=objective,target_kind=kind)[0]
    assert suggestion['skill_id'] == skill
    assert suggestion['execution']['missing_capabilities'] == []
    spec = library.require(skill)
    assert spec.support == 'supported' and spec.deferred_techniques
    assert spec.requires_skills == (BASELINE,)


@pytest.mark.parametrize('kind', ['network', 'device'])
@pytest.mark.parametrize('skill', SPECIALISTS)
def test_specialist_binding_reports_real_prerequisites_without_new_authority(library, kind, skill):
    allowed, budget = ('http.request',), object()
    bound = bind_skills_to_hunt([skill],target_kind=kind,allowed_capabilities=allowed,
                               budget=budget,library=library)
    assert {s.skill_id for s in bound.specs} == {BASELINE,skill}
    specialist = next(s for s in bound.context_section['bound'] if s['skill_id'] == skill)
    assert set(specialist['withheld_capabilities']) == {'ports.discover','service.fingerprint'}
    assert specialist['missing_capabilities'] == []
    assert bound.allowed_capabilities is allowed and bound.budget is budget


@pytest.mark.parametrize('kind', ['network','device'])
@pytest.mark.parametrize('skill', SPECIALISTS)
def test_read_then_bind_preserves_saved_run_and_loads_baseline(library, kind, skill):
    conn = _Connection()
    conn.row['target_kind'] = kind
    policy = copy.deepcopy(conn.row['policy_json'])
    service = HuntRunService(lambda: _Pool(conn))
    hunt_id = str(conn.hunt_id)
    payload = asyncio.run(service.read_skill(hunt_id,skill))
    assert payload['methodology'] and payload['support'] == 'supported'
    asyncio.run(service.read_skill(hunt_id,BASELINE))
    result = asyncio.run(service.bind_skill(hunt_id,skill,reason='Operator requested asset assessment'))
    assert {row['skill_id'] for row in result['skills']} >= {BASELINE,skill}
    assert conn.row['policy_json'] == policy


def test_new_methodologies_are_installed_and_have_readable_deeper_references(library):
    installed = installer_paths((ROOT/'install/index.sh').read_text())
    for name in (BASELINE,*SPECIALISTS,'skill.network.managed-ssh-assessment'):
        spec = library.require(name)
        assert Path(spec.path).relative_to(ROOT).as_posix() in installed
        assert spec.public(include_body=True)['methodology']


@pytest.mark.parametrize('kind',['web','api','network','device'])
def test_stored_ssh_objective_selects_the_live_executor(library,kind):
    suggestion = library.suggest(goal='Connect using stored SSH credentials on port 2222',
        target_kind=kind,allowed_capabilities=['ssh.connect'])[0]
    assert suggestion['skill_id'] == 'skill.network.managed-ssh-assessment'
    assert suggestion['execution']['fully_executable']
