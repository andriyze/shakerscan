import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const targets = readFileSync(path.join(root, 'src/app/targets/page.tsx'), 'utf8')

test('target scan counters describe completed scans instead of all linked history', () => {
  assert.equal((targets.match(/completed scans/g) || []).length, 2)
})

test('per-target scan counters preserve exact target history context', () => {
  assert.match(targets, /function scanHistoryHref\(rootDomain: string, targetUrl: string\)/)
  assert.match(targets, /new URLSearchParams\(\{\s*domain: rootDomain,\s*search: targetUrl,/)
  assert.match(targets, /scanHistoryHref\(domain\.root_domain, domain\.root_target\.url\)/)
  assert.match(targets, /scanHistoryHref\(domain\.root_domain, subdomain\.url\)/)
  assert.doesNotMatch(targets, /href=\{`\/scans\?domain=\$\{domain\.root_domain\}`\}/)
})

test('subdomain finding counters have an accessible text label', () => {
  assert.match(targets, /\{subdomain\.active_findings_count\} findings/)
})

test('pathological domain labels stay inside their card', () => {
  assert.match(targets, /block min-w-\[10rem\] max-w-full truncate font-medium text-white/)
})

test('archived targets can be listed, restored and deleted from the Targets page', () => {
  // Archive sets is_active=false and the default inventory hides such rows, so without this the
  // group row showed no root-level control at all ("no exact root record") and an archived
  // target could be neither deleted nor restored.
  assert.match(targets, /includeInactive: archivedFilter/)
  assert.match(targets, /id="targets-archived-filter"/)
  assert.match(targets, /Show archived/)
  assert.equal((targets.match(/>archived<\/span>/g) || []).length, 2, 'root and subdomain rows carry the badge')
  assert.equal((targets.match(/void handleRestore\(/g) || []).length, 2, 'root and subdomain rows can be restored')
  assert.equal((targets.match(/archived=\{!/g) || []).length, 2, 'the delete dialog knows the row is already archived')
})
