import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const component = readFileSync(
  path.join(root, 'src/components/report/InfrastructureIntelligenceSection.tsx'),
  'utf8',
)
const report = readFileSync(path.join(root, 'src/components/ReportView.tsx'), 'utf8')

test('scan report renders target infrastructure as explicitly unscored context', () => {
  assert.match(report, /InfrastructureIntelligenceSection infrastructure=\{infrastructure\}/)
  assert.match(component, /Informational only · does not affect score or grade/)
  assert.match(component, /not vulnerability findings/)
  assert.doesNotMatch(component, /gradeTextColor|score_scan|cvss/i)
})

test('associated names are not presented as authorized or scanned targets', () => {
  assert.match(component, /Associated names/)
  assert.match(component, /do not prove common ownership/)
  assert.match(component, /are not automatically in scope/)
  assert.match(component, /were not scanned/)
  assert.match(component, /Unverified association/)
})

test('infrastructure section exposes registration, DNS, network, and certificate context', () => {
  for (const label of [
    'Domain registration',
    'Resolved network',
    'DNS topology',
    'Certificate identity',
    'Record TTL and answer details',
  ]) {
    assert.match(component, new RegExp(label))
  }
})

