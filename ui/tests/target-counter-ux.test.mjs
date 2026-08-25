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
  assert.match(targets, /block max-w-full truncate font-medium text-white/)
})
