import assert from 'node:assert/strict'
import test from 'node:test'
import { targetInstructionState } from './targetInstructionState.mjs'

const operator = { methodology: 'Do not reboot', written_by: 'operator:target-skill-api' }
const draft = { methodology: 'Inspect the API on port 8443', written_by: 'hunt:example' }

test('operator instructions and later editable drafts remain separate', () => {
  const state = targetInstructionState({ skill: draft, operator_skill: operator, trust: 'hunt_advisory' })
  assert.equal(state.editable, operator)
  assert.equal(state.operator, operator)
  assert.equal(state.advisory, false)
  assert.equal(state.needsOperatorSave, false) // Learning never requires re-saving effective directives.
})
test('separately deleted learning leaves effective instructions editable', () => {
  const state = targetInstructionState({ skill: null, operator_skill: operator, trust: 'none' })
  assert.equal(state.exists, true)
  assert.equal(state.editable, operator)
  assert.equal(state.advisory, false)
  assert.equal(state.needsOperatorSave, false)
})
test('unknown drafts are never labelled as auto-loaded operator instructions', () => {
  for (const trust of [undefined, 'unknown_advisory', 'hunt_advisory']) {
    const state = targetInstructionState({ skill: draft, trust })
    assert.equal(state.operator, null)
    assert.equal(state.advisory, true)
    assert.equal(state.needsOperatorSave, true)
  }
})
test('operator save clears the advisory state without requiring another edit', () => {
  const state = targetInstructionState({ skill: operator, operator_skill: operator, trust: 'operator' })
  assert.equal(state.advisory, false)
  assert.equal(state.needsOperatorSave, false)
})
test('empty state is not an instruction', () => {
  assert.deepEqual(targetInstructionState(null), {
    editable: null, operator: null, advisory: false, exists: false, needsOperatorSave: false,
  })
})

test('delegated instruction edits are already effective without a second UI save', () => {
  const instruction = {...draft, instruction_authority: 'target_metadata_delegation'}
  const state = targetInstructionState({skill: instruction, operator_skill: instruction, trust:'operator_delegated'})
  assert.equal(state.editable, instruction)
  assert.equal(state.advisory, false)
  assert.equal(state.needsOperatorSave, false)
})
test('instruction deletion does not resurrect an earlier baseline from learned text', () => {
  const state = targetInstructionState({skill:null,operator_skill:null,knowledge:draft,trust:'none'})
  assert.equal(state.exists,false)
  assert.equal(state.operator,null)
  assert.equal(state.advisory,true)
})
