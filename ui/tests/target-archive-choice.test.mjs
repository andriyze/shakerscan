import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const dialog = fs.readFileSync(path.join(root, 'src/components/lifecycle/DeleteRecordsButton.tsx'), 'utf8')

test('a host with a linked web app can be archived instead of deleted', () => {
  // Soak N7: the preview of a host with a web app lists two roots, so "Archive target instead"
  // was never offered. The selected target is archived; the server covers its linked services.
  assert.doesNotMatch(dialog, /preview\.root_ids\.length === 1 && onArchived/)
  assert.match(dialog, /archiveTargetId && preview\.root_ids\.includes\(archiveTargetId\) \? archiveTargetId/)
  assert.match(dialog, /archiveTargetId=\{selection\.kind === 'target' \? selection\.target_id : undefined\}/)
  assert.match(dialog, /await archiveRecordTarget\(archiveId\)/)
  assert.match(dialog, /\{archiveId && onArchived && !archived && \(/)
})
