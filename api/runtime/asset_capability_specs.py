"""Target management declarations composed into the canonical capability registry."""

MAX_TARGET_SKILL_CHARACTERS = 12_000
MAX_PROPOSALS_PER_HUNT = 5

def asset_capability_specs(spec, schema, kinds):
    confirmed = {'type':'boolean','description':'Deprecated compatibility field; grants no authority. Metadata edits default on but obey operator opt-outs; instruction edits need the operator’s explicit instruction_changes opt-in; sharing needs saved grants.'}
    identifier = {'type':'string','format':'uuid'}
    revision = {'type':'integer','minimum':0}
    purpose = {'type':'string','enum':['instructions','knowledge'],'default':'instructions',
               'description':'instructions edits the operator’s target instructions and is refused unless the operator saved instruction_changes for this target (otherwise use targets.skill.propose); knowledge is automatically loaded advisory learning, permitted by metadata delegation. Neither grants execution authority.'}
    skill_text = {'title':{'type':'string','minLength':1,'maxLength':120},
                  'methodology':{'type':'string','minLength':1,'maxLength':MAX_TARGET_SKILL_CHARACTERS},
                  'expected_revision':revision, 'purpose':purpose}
    action_text = {
        'name':{'type':'string','minLength':1,'maxLength':120},
        'instructions':{'type':'string','maxLength':4000},
        'expected_revision':revision,
        'steps':{'type':'array','minItems':1,'maxItems':16,'items':{'type':'object',
            'additionalProperties':False, 'required':['capability','input'],
            'properties':{'capability':{'type':'string','maxLength':120},
                'input':{'type':'object'},'description':{'type':'string','maxLength':240}}}},
        'parameters':{'type':'object','maxProperties':16},
    }
    review_note = {
        'reason':{'type':'string','maxLength':2000,
                  'description':'Why the change helps; shown to the operator when the change is filed for review.'},
        'evidence_refs':{'type':'array','maxItems':20,'uniqueItems':True,'items':{'type':'string','format':'uuid'},
                         'description':'Ids of Hunt actions or receipts, findings, candidates or scans on this target’s asset.'},
    }
    reviewed = (' Applied only where the operator saved instruction_changes for this target; otherwise filed as '
                'a proposal for operator review (the result says applied=false).')
    definitions = (
        ('targets.actions.create','Save a named reusable action for this target using canonical capabilities and opaque references.'+reviewed,
         {**action_text,**review_note},('name','steps','expected_revision')),
        ('targets.actions.update','Edit a saved action on this exact target with a revision check. Future Hunts load the change.'+reviewed,
         {**action_text,**review_note,'action_id':identifier},('action_id','name','steps','expected_revision')),
        ('targets.actions.delete','Delete a saved action on this exact target with a revision check.'+reviewed,
         {'action_id':identifier,'expected_revision':revision,**review_note},('action_id','expected_revision')),
        ('targets.skill.create','Create this target’s advisory knowledge (purpose=knowledge), or its instructions where the operator opted in with instruction_changes. Used by future Hunts; grants no testing authority.',
         skill_text,('methodology','expected_revision')),
        ('targets.skill.update','Update this target’s advisory knowledge, or its instructions where the operator opted in with instruction_changes, with a revision check. This Hunt’s startup snapshot is unchanged.',
         skill_text,('methodology','expected_revision')),
        ('targets.skill.delete','Delete this target’s advisory knowledge, or its instructions where the operator opted in with instruction_changes, with a revision check. Existing Hunt snapshots are retained.',
         {'expected_revision':revision,'purpose':purpose},('expected_revision',)),
        ('targets.skill.propose',('Propose a change to this target’s operator instructions for an operator to review: the full proposed text, the revision you read, a reason and ids of supporting records. Applies nothing; at most '
         f'{MAX_PROPOSALS_PER_HUNT} per Hunt.'),
         {'title':{'type':'string','minLength':1,'maxLength':120,'description':'One line saying what the change does.'},
          'methodology':{'type':'string','minLength':1,'maxLength':MAX_TARGET_SKILL_CHARACTERS,
                         'description':'The complete proposed instructions text (a full replacement, not a diff).'},
          'reason':{'type':'string','minLength':1,'maxLength':2000},
          'base_revision':{**revision,'description':'The revision targets.skill.read returned; the proposal is reviewed against it.'},
          'evidence_refs':{'type':'array','maxItems':20,'uniqueItems':True,
                           'items':{'type':'string','format':'uuid'},
                           'description':'Ids of Hunt actions or receipts, findings, candidates or scans on this target’s asset.'}},
         ('title','methodology','reason','base_revision')),
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
    action_read = spec('targets.actions.read','Read named saved actions. Optional action_id and typed parameters resolve steps; execute each through the Hunt capability runtime.',
        'internal','read_only',kinds,'targets.actions.read','1',None,
        {'tool_wall_seconds':5},{'control_plane':True},
        schema({'action_id':identifier,'parameters':{'type':'object','maxProperties':16}}),
        'target-management/v1',('target_management_observation','tool_receipt'),hunt_executor='inline')
    return (read,action_read) + tuple(spec(name,description,'internal',
        'read_only' if name.startswith('targets.') else 'active',kinds,name,'1',
        None if name.startswith('targets.') else 'active_testing',
        {'tool_wall_seconds':5},{'control_plane':True,**({} if name.startswith('targets.') else {'user_confirmation':True})},
        schema({**properties,'operator_confirmed':confirmed},required=required),
        'target-management/v1',('target_management_observation','tool_receipt'),hunt_executor='inline')
        for name,description,properties,required in definitions)
