"""Target instructions use bounded metadata authority through the canonical Hunt registry."""
import pytest
from pydantic import ValidationError

from api.hunt.contracts import capability_manifest
from api.hunt.start_contract import normalize_hunt_start_payload
from api.runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError
from api.targets.skill import TargetSkillWrite, MAX_TARGET_SKILL_CHARACTERS


@pytest.mark.parametrize('kind',['web','api','network','device'])
def test_passive_hunt_has_all_target_skill_operations_without_network_authority(kind):
    contract = normalize_hunt_start_payload({'target_id':'target-1','target_kind':kind,
        'goal':'Maintain instructions','policy':{'active_testing':False},'budgets':{'max_active_actions':0}})
    names = {item['name'] for item in capability_manifest(contract,credentials_available=False)}
    for operation in ['read','create','update','delete']:
        name = 'targets.skill.'+operation
        assert name in names
        spec = CAPABILITY_REGISTRY.require(name)
        assert not spec.requires_active_approval
        assert spec.hunt_executor == 'inline'
        assert set(spec.budget_cost) == {'tool_wall_seconds'}
        assert spec.required_approval is None
        assert not spec.placement_requirements.get('user_confirmation')
    assert 'ports.discover' not in names


def test_skill_input_cannot_select_other_targets_or_skip_revision_confirmation():
    valid = {'operator_confirmed':True,'methodology':'Use the saved profile','expected_revision':0}
    assert CAPABILITY_REGISTRY.validate_hunt_input('targets.skill.create',valid) == valid
    for changes in [{'target_id':'another-target'}, {'argv':['unsafe']},
                    {'expected_revision':-1}, {'methodology':'x'*(MAX_TARGET_SKILL_CHARACTERS+1)}]:
        with pytest.raises(CapabilityInputContractError):
            CAPABILITY_REGISTRY.validate_hunt_input('targets.skill.create',{**valid,**changes})
    with pytest.raises(CapabilityInputContractError):
        CAPABILITY_REGISTRY.validate_hunt_input('targets.skill.update',{'methodology':'Missing revision and intent'})
    assert CAPABILITY_REGISTRY.validate_hunt_input('targets.skill.read',{}) == {}
    assert CAPABILITY_REGISTRY.validate_hunt_input('targets.skill.create',
        {'methodology':'Use saved inputs','expected_revision':0})['expected_revision'] == 0


@pytest.mark.parametrize('body',[{'methodology':' '}, {'title':' '}, {'methodology':'\x00'},
                              {'expected_revision':True}, {'expected_revision':1.5}])
def test_blank_or_malformed_instructions_are_rejected(body):
    with pytest.raises(ValidationError):
        TargetSkillWrite(**{'methodology':'Useful instructions','expected_revision':0,**body})


def test_hunt_audit_input_contains_content_digest_not_instruction_body(monkeypatch):
    from api.hunt import interaction_router
    monkeypatch.setattr(interaction_router._arsenal_routes, '_redact_agent_payload', lambda values: values)
    redacted = interaction_router._hunt_redacted_capability_input('targets.skill.update',
        {'methodology':'Operator instructions with private context','expected_revision':2,'operator_confirmed':True})
    assert 'methodology' not in redacted
    assert len(redacted['body_sha256']) == 64 and redacted['characters'] > 0


@pytest.mark.parametrize('model',['target_update','device_create','device_update'])
def test_generic_metadata_writes_cannot_bypass_skill_revision_checks(model):
    from api.targets.router import TargetUpdate
    from api.devices.router import DeviceTargetCreate, DeviceTargetUpdate
    cls = {'target_update':TargetUpdate,'device_create':DeviceTargetCreate,'device_update':DeviceTargetUpdate}[model]
    values = {'primary_locator':'tv.test'} if model == 'device_create' else {}
    with pytest.raises(ValidationError, match='revision check'):
        cls(**values,metadata_json={'target_skill':{'methodology':'Bypass','revision':0}})
    with pytest.raises(ValidationError, match='Hunt permissions'):
        cls(**values,metadata_json={'hunt_authority':{'metadata_changes':True}})
    assert cls(**values,metadata_json={'notes':'Ordinary notes'}).metadata_json == {'notes':'Ordinary notes'}


@pytest.mark.parametrize('saved',['legacy notes',{'revision':True},
    {'revision':1,'methodology':'x'*(MAX_TARGET_SKILL_CHARACTERS+1),'title':'Too long'},
    {'revision':2,'methodology':'Imported text','title':'Missing integrity metadata'}])
def test_malformed_legacy_metadata_cannot_load_unbounded_instructions(saved):
    from api.targets.skill import _public
    value = _public({'id':'target-1','metadata_json':{'target_skill':saved}})
    assert value['skill'] is None
