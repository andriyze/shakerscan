import assert from 'node:assert/strict'
import test from 'node:test'

import { agentHandoff, budgetUsage, defaultRunTab, huntIsLive, pendingDecisions, requestsByAction } from './huntRunModel.mjs'

test('a live run opens on its requests, a finished one on its results, and a hash wins', () => {
  assert.equal(defaultRunTab({ status: 'active' }), 'requests')
  assert.equal(defaultRunTab({ status: 'awaiting_planner' }), 'requests')
  assert.equal(defaultRunTab({ status: 'completed', completed_at: '2026-10-01T00:00:00Z' }), 'results')
  assert.equal(defaultRunTab({ status: 'completed' }, '#timeline'), 'timeline')
  assert.equal(defaultRunTab({ status: 'completed' }, '#nonsense'), 'results')
  assert.equal(huntIsLive({ status: 'active', completed_at: '2026-10-01T00:00:00Z' }), false)
})

test('budget use pairs each limit with its own counter and lists zero limits as disabled', () => {
  const { rows, disabled } = budgetUsage({
    budget: { max_capability_calls: 300, max_http_requests: 20000, max_tcp_ports: 0, max_duration_seconds: 600 },
    budget_used: { agent_actions: 150, http_requests: 196, tcp_ports_attempted: 0 },
    created_at: '2026-10-01T10:00:00Z', completed_at: '2026-10-01T10:05:00Z',
  }, { max_capability_calls: 'Maximum capability calls' })
  const byName = Object.fromEntries(rows.map(row => [row.name, row]))
  assert.equal(byName.max_capability_calls.used, 150)
  assert.equal(byName.max_capability_calls.label, 'capability calls')
  assert.equal(byName.max_http_requests.used, 196)
  assert.equal(byName.max_duration_seconds.used, 300)
  assert.deepEqual(disabled, ['tcp ports'])
  // The most consumed dimension comes first.
  assert.equal(rows[0].name, 'max_capability_calls')
})

test('only operator decisions are pending: proposed SSH plans and an unfinished exhausted budget', () => {
  assert.deepEqual(pendingDecisions({ status: 'completed' }, [{ plan_id: 'p1', status: 'queued' }]), [])
  assert.deepEqual(pendingDecisions({ status: 'budget_exhausted', stop_reason: 'budget_exhausted:tcp_ports_attempted' }, [{ plan_id: 'p2', status: 'proposed' }]), [
    { kind: 'ssh_plan', id: 'p2' },
    { kind: 'budget', id: 'budget', reason: 'tcp ports attempted' },
  ])
  assert.deepEqual(pendingDecisions({ status: 'budget_exhausted', completed_at: '2026-10-01T00:00:00Z' }), [])
})

test('requests group under the action that sent them', () => {
  const { byAction, unlinked } = requestsByAction([
    { id: 'r1', hunt_action_id: 'a1' }, { id: 'r2', hunt_action_id: 'a1' }, { id: 'r3', hunt_action_id: null }, { id: 'r4', hunt_action_id: 'a2' },
  ])
  assert.deepEqual(byAction.get('a1').map(row => row.id), ['r1', 'r2'])
  assert.deepEqual(byAction.get('a2').map(row => row.id), ['r4'])
  assert.deepEqual(unlinked.map(row => row.id), ['r3'])
})

test('the agent handoff names the Hunt so a terminal agent can pick it up', () => {
  const handoff = agentHandoff({ hunt_id: 'abc-123' })
  assert.equal(handoff.command, 'shakerscan agent')
  assert.match(handoff.prompt, /Hunt abc-123/)
  assert.match(handoff.prompt, /shakerscan hunt get abc-123/)
})

test('the record gives each action its call arguments and its failure reason', async () => {
  const { actionOutcomes, callArguments } = await import('./huntRunModel.mjs')
  const outcomes = actionOutcomes({ decision_trace: [
    { action_id: 'a1', decision: { input: { as_principal: 'primary' } },
      outcome: { error: 'target login form was not identified', parser_errors: ['target login form was not identified'] } },
    { action_id: 'a2', decision: { input: { method: 'GET', path: '/api/orders', headers: { accept: 'json' } } }, outcome: { ok: true, error: null } },
    { decision: { input: {} } },
  ] })
  assert.deepEqual(outcomes.get('a1'), { input: { as_principal: 'primary' }, errors: ['target login form was not identified'] })
  assert.deepEqual(outcomes.get('a2').errors, [])
  assert.equal(outcomes.size, 2)
  assert.deepEqual(callArguments(outcomes.get('a2').input).map(item => `${item.key}=${item.value}`),
    ['method=GET', 'path=/api/orders', 'headers={"accept":"json"}'])
  assert.equal(callArguments({ body: 'x'.repeat(500) }, 20)[0].value.length, 20)
})

test('an exhausted stop reason names the limit to extend', async () => {
  const { exhaustedDimension } = await import('./huntRunModel.mjs')
  assert.equal(exhaustedDimension({ stop_reason: 'budget_exhausted:hosts_attempted' }), 'max_hosts')
  assert.equal(exhaustedDimension({ stop_reason: 'budget_exhausted:http_requests' }), 'max_http_requests')
  assert.equal(exhaustedDimension({ stop_reason: 'budget_exhausted:max_tcp_ports' }), 'max_tcp_ports')
  assert.equal(exhaustedDimension({ stop_reason: 'budget_exhausted:tool_wall_seconds', budget: {} }), null)
  assert.equal(exhaustedDimension({ stop_reason: 'completed' }), null)
})
