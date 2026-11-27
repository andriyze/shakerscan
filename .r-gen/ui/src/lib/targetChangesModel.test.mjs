import assert from 'node:assert/strict'
import test from 'node:test'
import { changesView } from './targetChangesModel.mjs'

test('a report with nothing to compare with says why and lists nothing', () => {
  const view = changesView({ since: { kind: 'last_hunt', at: null, resolved: false, note: 'No earlier Hunt on this target; nothing to compare with.' },
    sections: {}, knowledge: { active_by_applicability: {}, affected: [] } })
  assert.equal(view.resolved, false)
  assert.equal(view.note, 'No earlier Hunt on this target; nothing to compare with.')
  assert.deepEqual(view.groups, [])
  assert.equal(view.states, '')
})

test('each kind of change becomes a headed group of plain lines', () => {
  const view = changesView({
    since: { kind: 'release', at: '2026-01-02T03:04:05+00:00', resolved: true },
    sections: {
      endpoints: {
        added: { count: 2, at_least: false, items: [{ method: 'GET', path: '/api/orders', auth_state: 'authenticated' }, { method: 'POST', path: '/login', auth_state: null }] },
        removed: { count: 1000, at_least: true, items: [{ method: 'GET', path: '/old', auth_state: 'anonymous' }] },
        auth_surface: { significant: true },
      },
      deployment: { compared: true, changes: [{ field: 'technology_version', before: 'nginx 1.24', after: 'nginx 1.26', significance: 'significant' }] },
      responses: { changed: [{ method: 'GET', path: '/api/me', changes: [{ field: 'status_code', significance: 'significant' }, { field: 'body_size', significance: 'minor' }] }] },
      services: { added: [{ transport: 'tcp', port: 8443, service_name: 'https', product: 'nginx', version: '1.26' }], no_longer_observed: [{ transport: 'tcp', port: 22, service_name: 'ssh' }] },
      findings: { new: { count: 1, at_least: false } },
      subdomains: { new_targets: [{ host: 'new.example.test', source: 'certificate_transparency' }] },
    },
    knowledge: {
      active_by_applicability: { applicable: 3, needs_revalidation: 1, historical: 0 },
      affected: [
        { id: 'a', kind: 'negative_result', negative_state: 'finding_dismissed', applicability: 'needs_revalidation', reopened_for_review: true, caused_by: [{ type: 'finding', key: 'f1', field: 'severity' }] },
        { id: 'b', kind: 'hypothesis', applicability: 'needs_revalidation', caused_by: [] },
      ],
      affected_truncated: true,
    },
  })
  assert.equal(view.resolved, true)
  assert.equal(view.sinceLabel, 'the latest release')
  assert.equal(view.sinceAt, '2026-01-02T03:04:05+00:00')
  assert.deepEqual(view.groups.map((group) => group.label), [
    'Routes added (2)', 'Routes no longer found (1000+)', 'Sign-in surface', 'Deployment', 'Responses changed', 'Services',
    'Findings', 'New subdomains', 'Interpretations to review',
  ])
  const lines = Object.fromEntries(view.groups.map((group) => [group.label, group.items]))
  assert.deepEqual(lines['Routes added (2)'], ['GET /api/orders (authenticated)', 'POST /login'])
  assert.deepEqual(lines.Deployment, ['technology version: nginx 1.24 → nginx 1.26 (significant)'])
  assert.deepEqual(lines['Responses changed'], ['GET /api/me: status code (significant), body size (minor)'])
  assert.deepEqual(lines.Services, ['New: 8443/tcp https nginx 1.26', 'No longer observed: 22/tcp ssh'])
  assert.deepEqual(lines.Findings, ['1 new finding'])
  assert.deepEqual(lines['New subdomains'], ['new.example.test (certificate transparency)'])
  assert.deepEqual(lines['Interpretations to review'], [
    'Dismissed finding: reopened for review (finding f1 severity)', 'Hypothesis: needs re-testing',
    'More entries are affected than are listed here.',
  ])
  assert.equal(view.states, '3 still applies, 1 needs re-testing')
})

test('text observed from the target stays a plain string and is cut to a readable length', () => {
  const view = changesView({ since: { kind: 'last_hunt', at: '2026-01-01T00:00:00Z', resolved: true },
    sections: { endpoints: { added: { count: 1, items: [{ method: 'GET', path: `/<img src=x onerror=alert(1)>${'a'.repeat(500)}` }] } } } })
  const [line] = view.groups[0].items
  assert.ok(line.startsWith('GET /<img src=x onerror=alert(1)>'))
  assert.equal(line.length, 201)
  assert.equal(changesView(null).resolved, false)
})
