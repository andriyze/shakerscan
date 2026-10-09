import assert from 'node:assert/strict'
import test from 'node:test'

import { EXPORT_MAX_CALLS, EXPORT_PAGE_SIZE, collectArchiveExport, exportCapNotice, exportShortfallMessage } from './httpArchiveExport.mjs'

function archive(total, { pageCap = Infinity, drop = 0 } = {}) {
  const rows = Array.from({ length: total }, (_, i) => ({ id: `t${i}` }))
  const calls = []
  const fetchPage = async (offset, limit) => {
    calls.push({ offset, limit })
    const available = rows.slice(0, total - drop)
    const page = available.slice(offset, offset + Math.min(limit, pageCap))
    return {
      schema_version: 'http-archive-export/v1', redaction: 'redacted', fidelity: 'partial',
      exported: page.length, total, archive_total: total, truncated_export: page.length < total, transactions: page,
    }
  }
  return { fetchPage, calls }
}

test('the Requests JSON export holds every matching call, not the first browse page', async () => {
  // The lab scan: 92 calls; the export used to save 25 and mark the file truncated.
  const { fetchPage, calls } = archive(92)
  const exported = await collectArchiveExport(fetchPage)
  assert.equal(exported.transactions.length, 92)
  assert.equal(exported.exported, 92)
  assert.equal(exported.total, 92)
  assert.equal(exported.truncated_export, false)
  assert.equal(exported.redaction, 'redacted')
  assert.ok(EXPORT_PAGE_SIZE > 25)
  assert.deepEqual(calls, [{ offset: 0, limit: EXPORT_PAGE_SIZE }])
  assert.equal(exportShortfallMessage(exported), null)
})

test('the export pages through archives larger than one request', async () => {
  const { fetchPage, calls } = archive(92, { pageCap: 25 })
  const exported = await collectArchiveExport(fetchPage, { pageSize: 25 })
  assert.deepEqual(exported.transactions.map((row) => row.id), Array.from({ length: 92 }, (_, i) => `t${i}`))
  assert.deepEqual(calls.map((call) => call.offset), [0, 25, 50, 75])
  assert.equal(exported.truncated_export, false)
})

test('an archive that shrinks while exporting is reported, not passed off as complete', async () => {
  const { fetchPage } = archive(92, { pageCap: 25, drop: 10 })
  const exported = await collectArchiveExport(fetchPage, { pageSize: 25 })
  assert.equal(exported.exported, 82)
  assert.equal(exported.truncated_export, true)
  assert.match(exportShortfallMessage(exported), /82 of 92 matching calls/)
})

test('a refused page fails the whole export', async () => {
  let first = true
  const fetchPage = async () => {
    if (first) { first = false; return { total: 50, transactions: Array.from({ length: 25 }, (_, i) => ({ id: i })) } }
    throw new Error('Export failed (403)')
  }
  await assert.rejects(collectArchiveExport(fetchPage, { pageSize: 25 }), /403/)
})

test('fidelity, notes and capture stats describe every page, not just the first', async () => {
  const pages = [
    { total: 4, fidelity: 'complete', fidelity_detail: 'All calls archived', capture_stats: { unarchived_external_tool_capabilities: ['sqli.verify_batch'], archived: 2 }, transactions: [{ id: 'a' }, { id: 'b' }] },
    { total: 4, fidelity: 'partial', fidelity_detail: '1 recorded call(s) have payloads that are unavailable', capture_stats: { unarchived_external_tool_capabilities: ['xss.verify_batch'], archived: 4 }, transactions: [{ id: 'c' }, { id: 'd' }] },
  ]
  const exported = await collectArchiveExport(async (offset) => pages[offset / 2], { pageSize: 2 })
  assert.equal(exported.fidelity, 'partial')
  assert.equal(exported.fidelity_detail, 'All calls archived; 1 recorded call(s) have payloads that are unavailable')
  assert.deepEqual(exported.capture_stats, { unarchived_external_tool_capabilities: ['sqli.verify_batch', 'xss.verify_batch'], archived: 4 })
  assert.equal(exported.exported, 4)
})

test('a call archived mid-export does not appear twice', async () => {
  // A new call lands at the head of the archive between pages, shifting page two by one.
  const pages = [
    { total: 4, transactions: [{ id: 't0' }, { id: 't1' }] },
    { total: 5, transactions: [{ id: 't1' }, { id: 't2' }] },
    { total: 5, transactions: [{ id: 't3' }] },
  ]
  let call = 0
  const exported = await collectArchiveExport(async () => pages[call++] || { total: 5, transactions: [] }, { pageSize: 2 })
  assert.deepEqual(exported.transactions.map((row) => row.id), ['t0', 't1', 't2', 't3'])
  assert.equal(new Set(exported.transactions.map((row) => row.id)).size, exported.transactions.length)
})

test('a huge archive stops at the export cap and says so before and after', async () => {
  const { fetchPage, calls } = archive(130)
  const exported = await collectArchiveExport(fetchPage, { pageSize: 50, maxCalls: 100 })
  assert.equal(exported.exported, 100)
  assert.equal(exported.export_cap, 100)
  assert.equal(exported.truncated_export, true)
  assert.deepEqual(calls.map((call) => call.limit), [50, 50])
  assert.match(exportShortfallMessage(exported), /first 100 of 130 matching calls/)
  assert.match(exportCapNotice(130, 100), /holds the first 100/)
  assert.equal(exportCapNotice(92), null)
  assert.ok(EXPORT_MAX_CALLS >= 10000)
})
