"""Target management declarations composed into the canonical capability registry."""

MAX_TARGET_SKILL_CHARACTERS = 12_000

def asset_capability_specs(spec, schema, kinds):
    confirmed = {'type':'boolean','description':'Deprecated compatibility field; grants no authority. Metadata edits default on but obey operator opt-outs; sharing needs saved grants.'}
    identifier = {'type':'string','format':'uuid'}
    revision = {'type':'integer','minimum':0}
    skill_text = {'title':{'type':'string','minLength':1,'maxLength':120},
                  'methodology':{'type':'string','minLength':1,'maxLength':MAX_TARGET_SKILL_CHARACTERS},
                  'expected_revision':revision}
    definitions = (
        ('targets.skill.create','Create instructions for this target, used automatically by future Hunts. Does not grant testing authority.',
         skill_text,('methodology','expected_revision')),
        ('targets.skill.update','Update this target’s saved instructions with a revision check. This Hunt’s startup snapshot is unchanged.',
         skill_text,('methodology','expected_revision')),
        ('targets.skill.delete','Delete this target’s saved instructions with a revision check. Existing Hunt snapshots are retained.',
         {'expected_revision':revision},('expected_revision',)),
        ('targets.create','Register a hostname or IP as a canonical target without testing it.',
         {'locator':{'type':'string','minLength':1,'maxLength':253},
          'name':{'type':'string','maxLength':255},
          'environment':{'type':'string','enum':['production','staging','lab','demo','calibration','internal']},
          'port_hints':{'type':'array','maxItems':128,'items':{'type':'integer','minimum':1,'maximum':65535}}},('locator',)),
        ('targets.update','Rename this target or a current service view without changing frozen scope.',
         {'target_id':identifier,'name':{'type':'string','minLength':1,'maxLength':255}},('name',)),
        ('credentials.grant','Explicitly grant an existing encrypted profile to this Hunt target. Receiving-target approval is revalidated; no secret is returned.',
         {'profile_id':identifier,'approval_receipt_id':identifier},('profile_id',)),
        ('collections.bind','Bind an existing collection to this Hunt target and exact selected HTTP origins, including an explicitly authorized cross-asset share.',
         {'collection_id':identifier,'allowed_origins':{'type':'array','minItems':1,'maxItems':32,'items':{'type':'string','maxLength':2048}},
          'environment_id':identifier},('collection_id','allowed_origins')),
    )
    read = spec('targets.skill.read','Read the current saved instructions for this target. They are context, not testing authority.',
        'internal','read_only',kinds,'targets.skill.read','1',None,
        {'tool_wall_seconds':5},{'control_plane':True},schema({},required=()),
        'target-management/v1',('target_management_observation','tool_receipt'),hunt_executor='inline')
    return (read,) + tuple(spec(name,description,'internal',
        'read_only' if name.startswith('targets.') else 'active',kinds,name,'1',
        None if name.startswith('targets.') else 'active_testing',
        {'tool_wall_seconds':5},{'control_plane':True,**({} if name.startswith('targets.') else {'user_confirmation':True})},
        schema({**properties,'operator_confirmed':confirmed},required=required),
        'target-management/v1',('target_management_observation','tool_receipt'),hunt_executor='inline')
        for name,description,properties,required in definitions)
