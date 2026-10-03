import assert from 'node:assert/strict'
import test from 'node:test'
import { targetInstructionState } from './targetInstructionState.mjs'

const operator = { methodology: 'Do not reboot', written_by: 'operator:target-skill-api' }
const draft = { methodology: 'Inspect the API on port 8443', written_by: 'hunt:example' }

test('operator instructions and later editable drafts remain separate', () => {
  const state = targetInstructionState({ skill: draft, operator_skill: operator, trust: 'hunt_advisory' })
  assert.equal(state.editable, draft)
  assert.equal(state.operator, operator)
  assert.equal(state.advisory, true)
  assert.equal(state.needsOperatorSave, true) // Saving an unchanged draft must remain possible.
})
test('a deleted Hunt draft leaves the operator baseline editable and removable', () => {
  const state = targetInstructionState({ skill: null, operator_skill: operator, trust: 'none' })
  assert.equal(state.exists, true)
  assert.equal(state.editable, operator)
  assert.equal(state.advisory, false)
  assert.equal(state.needsOperatorSave, true)
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
