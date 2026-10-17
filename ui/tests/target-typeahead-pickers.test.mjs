import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

// 2.11 scale: pickers loaded every target (500 per request, every page) or silently only the first
// 100. They now search on the server: one bounded page per debounced query.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (file) => readFileSync(path.join(root, file), 'utf8')

const pickers = {
  hunt: read('src/app/hunt/page.tsx'),
  credentials: read('src/app/credentials/page.tsx'),
  share: read('src/components/credentials/ShareCredentialDialog.tsx'),
  collections: read('src/app/request-collections/page.tsx'),
  permissions: read('src/components/targets/TargetHuntPermissions.tsx'),
  picker: read('src/components/targets/TargetSearchCombobox.tsx'),
}
const capped = {
  schedules: read('src/app/schedules/page.tsx'),
  timeline: read('src/app/timeline/page.tsx'),
  leads: read('src/app/deep-hunt/leads/page.tsx'),
  experiment: read('src/app/deep-hunt/experiment/page.tsx'),
  newScan: read('src/app/scan/new/page.tsx'),
}

test('no picker loads the whole inventory', () => {
  for (const [name, source] of Object.entries({ ...pickers, ...capped })) {
    assert.doesNotMatch(source, /getAllTargetAssets/, name)
  }
  assert.doesNotMatch(read('src/lib/targetAssetApi.ts'), /export async function getAllTargetAssets/)
})

test('every target picker sends its typed text to the server and says when matches are bounded', () => {
  for (const [name, source] of Object.entries(pickers)) {
    assert.match(source, /useTargetSearch\(/, name)
    assert.match(source, /onQueryChange=\{(targetSearch|search)\.setQuery\}/, name)
    assert.match(source, /footerNote=\{/, name)
  }
})

test('pickers that cut at 100 targets search instead', () => {
  for (const name of ['schedules', 'timeline', 'leads', 'experiment']) {
    assert.match(capped[name], /<TargetSearchCombobox/, name)
    assert.doesNotMatch(capped[name], /getTargets\(/, name)
  }
  // New Scan recognises a registered target by searching for the typed URL.
  assert.match(capped.newScan, /useEffect\(\(\) => \{ setTargetQuery\(batchMode \? '' : target\) \}/)
  assert.doesNotMatch(capped.newScan, /getTargets\(/)
})

test('the Hunt launcher keeps offering only active web origins and hosts, and searches only while open', () => {
  assert.match(pickers.hunt, /return target\.is_active && \/\^\(https\?\|host\):\\\/\\\/\/i\.test\(target\.url\)/)
  assert.match(pickers.hunt, /enabled: launcherSearchOpen/)
  assert.match(pickers.hunt, /includeServices: true/)
  // "No targets" is only claimed when nothing was typed and the search answered.
  assert.match(pickers.hunt, /targetSearchProvesEmpty\(\{ \.\.\.targetSearch, assets: choices \}\) \? \(\s*<EmptyState/)
})

// Review fixes: Enter only for results that answer the box's text, and searches that stop
// cleanly. These check the wiring; the decisions themselves are tested in comboboxModel and
// targetSearchModel.
test('every server-searched picker tells the Combobox which query its options answer', () => {
  for (const [name, source] of Object.entries(pickers)) {
    assert.match(source, /optionsQuery=\{(targetSearch|search)\.answeredQuery\}/, name)
  }
  const combobox = read('src/components/ui/Combobox.tsx')
  assert.match(combobox, /canChooseActive\(\{ remote, loading, query, optionsQuery \}\)/)
  assert.match(combobox, /if \(chooseReady && activeIndex >= 0\) choose\(visible\[activeIndex\]\)/)
  assert.match(combobox, /setActive\(initialActive\(visible, value\)\)[\s\S]*\[open, visibleKey\]/, 'the highlight follows the visible list')
  assert.match(combobox, /aria-activedescendant=\{activeIndex >= 0 \?/)
})

test('the search hook pages through a filter, and never stays loading once disabled or aborted', () => {
  const hook = read('src/lib/useTargetSearch.ts')
  assert.match(hook, /collectAcceptedTargets\(/)
  assert.match(hook, /if \(!enabled\) \{\s*setLoading\(false\)/)
  assert.match(hook, /controller\.abort\(\)[\s\S]{0,200}setLoading\(false\)/)
})

test('no picker claims "no targets" from a partial or filtered answer', () => {
  assert.match(pickers.hunt, /targetSearchProvesEmpty\(\{ \.\.\.targetSearch, assets: choices \}\)/)
  assert.match(pickers.share, /targetSearchProvesEmpty\(\{ \.\.\.targetSearch, assets: choices \}\)/)
  assert.match(pickers.share, /useTargetSearch\(\{[^}]*accept \}\)/, 'the share filter pages on the server search')
  assert.match(pickers.collections, /targetSearchProvesEmpty\(/)
  assert.doesNotMatch(pickers.share, /targetSearch\.ready && !targetSearch\.loading && !choices\.length/)
})
