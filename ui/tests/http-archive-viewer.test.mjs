import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const source = readFileSync(path.join(uiRoot, 'src/components/HttpArchiveExport.tsx'), 'utf8')

test('request archive is browsable as well as downloadable', () => {
  assert.match(source, /Browse recorded calls/)
  assert.match(source, /archive\.transactions\.map/)
  assert.match(source, /Request/)
  assert.match(source, /Response/)
})

test('archive browser supports server-side search, method, status and pagination', () => {
  assert.match(source, /params\.set\('search'/)
  assert.match(source, /params\.set\('method'/)
  assert.match(source, /params\.set\('status_code'/)
  assert.match(source, /void load\(offset \+ PAGE_SIZE\)/)
  assert.match(source, /fetchRetryingBusy\(archiveUrl\(raw \? 'har' : format, 0, raw \? 'raw' : 'redacted'\), undefined, whenBusy\)/)
  // The masked HAR asks for masking; only the verbatim option asks for raw.
  assert.match(source, /HAR 1\.2 \(masked\)/)
  assert.match(source, /masked\.har/)
})

test('HAR export is explicitly raw, sensitive, and confirmation-gated', () => {
  assert.match(source, /Raw HAR 1\.2/)
  assert.match(source, /window\.confirm/)
  assert.match(source, /authentication headers, cookies, request bodies, and response data/)
  assert.match(source, /RAW\.har/)
})

test('archive viewer explains historical and partial capture instead of implying completeness', () => {
  assert.match(source, /archive\.fidelity_detail/)
  assert.match(source, /useEffect/)
  assert.match(source, /Raw HAR 1\.2.*archive\.fidelity/s)
  assert.match(source, /No request archive is available for this historical run/)
  assert.match(source, /archive\.archive_total/)
})

test('Hunt archive offers a full explicit decision record separately from requests only', () => {
  assert.match(source, /Full Hunt record/)
  assert.match(source, /\/hunts\/\$\{encodeURIComponent\(ownerId\)\}\/record/)
  assert.match(source, /ownerKind === 'hunt'/)
})

test('archive header never calls a partial archive the traffic recorded during the run', () => {
  // External scanner tools reach the target through an opaque pinned tunnel, so their
  // traffic is absent from the archive. The header must not imply a full capture.
  assert.doesNotMatch(source, /replay-ready HAR recorded during this/)
  assert.match(source, /download a HAR of the calls archived for this \{ownerKind\}/)
  assert.match(source, /archive\.fidelity !== 'complete'/)
  assert.match(source, /Not a full traffic capture/)
  assert.match(source, /unarchived_external_tool_capabilities/)
  assert.match(source, /send their traffic through an opaque tunnel/)
})

test('raw HAR is disabled with the deployment reason and a refused export is shown', () => {
  // The server declares whether verbatim HAR is exported here; the option follows it.
  assert.match(source, /archive\?\.raw_har\?\.available === false/)
  assert.match(source, /disabled=\{downloading !== null \|\| rawHarUnavailable\}/)
  assert.match(source, /disabled=\{rawHarUnavailable\}/)
  assert.match(source, /Raw HAR unavailable: \{rawHarReason\}/)
  // A refusal is kept on screen, not only toasted.
  assert.match(source, /setExportError\(message\)/)
  assert.match(source, /role="alert"[^>]*>\{exportError\}/)
})

test('Requests JSON exports every matching call and says so when it cannot', () => {
  // The browse page size (25) was sent as the export limit, so a 92-call scan saved 25.
  assert.match(source, /collectArchiveExport\(async \(pageOffset, limit\)/)
  assert.match(source, /archiveUrl\('transactions', pageOffset, 'redacted', limit\)/)
  assert.match(source, /exportShortfallMessage\(exported\)/)
  assert.match(source, /setExportError\(shortfall\)/)
  // A capped export is announced before the download, and the file is compact JSON.
  assert.match(source, /exportCapNotice\(archive\.total\)/)
  assert.match(source, /JSON\.stringify\(exported\)/)
  assert.match(source, /cause instanceof RangeError/)
})
