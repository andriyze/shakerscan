import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

// Every browser Hunt start the open-source edition offers is replaced, in a managed workspace, by
// "Start Hunts from your terminal: shakerscan agent" (components/hunt/TerminalHuntStart.tsx).
// The Hunts page itself is covered by the browser contract hunt-terminal-start.spec.ts.
const root = path.join(import.meta.dirname, '..')
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8')

test('the terminal hint reads the managed workspace the existing way', () => {
  const component = read('src/components/hunt/TerminalHuntStart.tsx')
  assert.match(component, /workspaceIsManaged\(\)/)
  assert.match(component, /'Start Hunts from your terminal:'/)
  assert.match(component, /'shakerscan agent'/)
})

for (const [file, start] of [
  ['src/components/targets/inventory/TargetRow.tsx', />Start Hunt<\/MenuItem>/],
  ['src/components/targets/SharedServicePorts.tsx', />Start Hunt<\/Link>/],
  ['src/components/targets/TargetActionsEditor.tsx', /Start Hunt<\/Link>/],
  ['src/app/asm/page.tsx', /Open Hunt/],
  ['src/app/hunt/page.tsx', /New Hunt<\/Button>/],
]) {
  test(`${file} offers its browser Hunt start only outside a managed workspace`, () => {
    const source = read(file)
    assert.match(source, /useWorkspaceIsManaged\(\)/)
    const managedBranch = source.search(/\bmanaged\s*\?/)
    assert.ok(managedBranch >= 0, 'the start is behind a managed check')
    const match = source.slice(managedBranch).match(start)
    assert.ok(match, 'the open-source start follows the managed branch')
    // The managed branch shows the terminal hint, not the browser start.
    const branch = source.slice(managedBranch, managedBranch + match.index)
    assert.match(branch, /TerminalHuntStart|TERMINAL_HUNT_START_LABEL/)
  })
}

test('the Hunts page opens no browser launcher in a managed workspace', () => {
  const source = read('src/app/hunt/page.tsx')
  assert.match(source, /const launcherSearchOpen = launcherOpen && !managed/)
  assert.match(source, /const launcherVisible = launcherOpen && !managed/)
  assert.match(source, /\{launcherOpen && !managed && <Card/)
})

test('a managed sidebar renders no section switch and shows every allowed page', () => {
  const source = read('src/components/Sidebar.tsx')
  assert.match(source, /const showAdvanced = managed \|\| showAll/)
  assert.match(source, /\{managed \? <span \/> : \(\s*<button\s+type="button"\s+role="switch"/)
})
