import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const scan = readFileSync(path.join(root, 'src/app/scan/new/page.tsx'), 'utf8')
const hunt = readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8')

test('a new Scan starts with the target credentials that fit each lane, never another target list', () => {
  // Defaults come only from the list loaded for the selected target, once per target.
  assert.match(scan, /credentialProfilesTarget !== targetId\) return/)
  assert.match(scan, /if \(credentialDefaultsTarget\.current === targetId\) return/)
  // Through the same compatibility rules the pickers enforce; the comparator is a different identity.
  assert.match(scan, /preferredCredentialId\(credentialProfiles, \(profile\) => credentialCompatibility\(profile, 'primary'\)\.compatible\)/)
  assert.match(scan, /credentialCompatibility\(profile, 'secondary'\)\.compatible, \[primary\]/)
  // The selection is shown beside the target, not only inside the collapsed Advanced section.
  const summary = scan.indexOf('data-testid="credential-defaults"')
  assert.ok(summary > 0 && summary < scan.indexOf('id="advanced-scan-options"'))
  assert.match(scan, /Scans as \{selectedPrimaryProfile/)
  assert.match(scan, />Scan anonymously<\/Button>/)
})

test('a new Hunt starts with the target credentials per slot, and never an SSH identity', () => {
  assert.match(hunt, /setCredentialIds\(defaultHuntCredentialIds\(usable\)\)/)
  const pickers = readFileSync(path.join(root, 'src/lib/pickerOptions.ts'), 'utf8')
  assert.match(hunt, /options=\{credentialOptions\(/)
  assert.match(pickers, /from \$\{profile\.home_target_name \|\| 'another target'\}/)
})
