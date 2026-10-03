import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const tabs = readFileSync(path.join(root, 'src/components/ui/SectionTabs.tsx'), 'utf8')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')
const report = readFileSync(path.join(root, 'src/components/ReportView.tsx'), 'utf8')

test('report sections are WAI-ARIA tabs that keyboard users can move through', () => {
  assert.match(tabs, /role="tablist"/)
  assert.match(tabs, /role="tab"/)
  assert.match(tabs, /role="tabpanel"/)
  assert.match(tabs, /aria-selected=\{selected\}/)
  assert.match(tabs, /aria-controls=\{`\$\{id\}-panel-\$\{tab\.key\}`\}/)
  assert.match(tabs, /tabIndex=\{selected \? 0 : -1\}/)
  for (const key of ['ArrowRight', 'ArrowLeft', 'Home', 'End']) assert.match(tabs, new RegExp(`event\\.key === '${key}'`))
})

test('the selected section is in the URL without a navigation, and every section prints', () => {
  assert.match(tabs, /window\.history\.replaceState/)
  assert.match(tabs, /new URLSearchParams\(window\.location\.search\)\.get\(param\)/)
  // Hidden by class, not the hidden attribute: the base layer's !important would beat print:block.
  assert.match(tabs, /'pt-5 print:block print:pt-2', !selected && 'hidden'/)
  assert.doesNotMatch(tabs, /hidden=\{!selected\}/)
})

test('the scan report shows each report block in exactly one tab', () => {
  for (const key of ['findings', 'posture', 'coverage', 'release', 'activity']) {
    assert.match(detail, new RegExp(`tab="${key}" active=\\{reportTab\\}`))
  }
  for (const part of ['findings', 'posture', 'coverage']) {
    assert.match(detail, new RegExp(`<ReportView scan=\\{scan\\} isAuthenticated=\\{true\\} section="${part}" />`))
  }
  // The standalone report's summary, raw findings list and per-scan remediation tracking are not
  // repeated on the scan page: the verdict card and the Findings tab replace them.
  assert.match(report, /!isModelIntakeScan && section === 'all' && <div/)
  assert.match(report, /\{section === 'all' && <details open=\{!isModelIntakeScan\}/)
  // Downloads stay in the page header, beside deleting the scan.
  assert.match(detail, /actions=\{<div[^>]*><ReportDownloads scan=\{scan\} isAuthenticated=\{true\} \/>\{deleteScan\}<\/div>\}/)
})
