import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DEFAULT_ICON, FALLBACK_SECTION, ICON_NAMES, LIMITS, NO_EXTENSIONS, SCHEMA,
  hostedPageSrc, parseUiExtensions, placeNavigation, safePath, safeText, sameOriginPath, slotPanelSrc,
} from './uiExtensions.mjs'

const block = () => ({
  schema: SCHEMA,
  sections: [{ id: 'remediation', label: 'Remediation', after: 'Testing' }],
  pages: [
    { id: 'schedules', title: 'Schedules', src: '/deployment/embed/schedules' },
    { id: 'retests', title: 'Retests and fixes', src: '/deployment/embed/retests' },
  ],
  nav: [
    { label: 'Schedules', page: 'schedules', section: 'Testing', after: '/scans', icon: 'calendar-clock' },
    { label: 'Retests and fixes', page: 'retests', section: 'remediation', icon: 'refresh' },
    { label: 'Status page', href: '/deployment/status', section: 'remediation' },
  ],
  slots: { 'finding.detail': [{ id: 'remediation', title: 'Remediation', src: '/deployment/embed/finding/{finding_id}' }] },
  account: {
    name: 'ada', detail: 'Administrator', sign_out: '/deployment/logout',
    links: [{ label: 'My account', href: '/deployment/#account' }, { label: 'Administration', href: '/deployment/' }],
  },
})

test('a well-formed block is kept as declared', () => {
  const parsed = parseUiExtensions(block())
  assert.deepEqual(parsed.sections, [{ id: 'remediation', label: 'Remediation', after: 'Testing' }])
  assert.deepEqual(parsed.pages.map((page) => page.id), ['schedules', 'retests'])
  assert.deepEqual(parsed.nav, [
    { label: 'Schedules', icon: 'calendar-clock', page: 'schedules', href: '/ext/schedules', section: 'Testing', after: '/scans' },
    { label: 'Retests and fixes', icon: 'refresh', page: 'retests', href: '/ext/retests', section: 'remediation' },
    { label: 'Status page', icon: DEFAULT_ICON, href: '/deployment/status', section: 'remediation' },
  ])
  assert.deepEqual(parsed.slots, {
    'finding.detail': [{ id: 'remediation', title: 'Remediation', src: '/deployment/embed/finding/{finding_id}' }],
  })
  assert.deepEqual(parsed.account, {
    name: 'ada', detail: 'Administrator', sign_out: '/deployment/logout',
    links: [{ label: 'My account', href: '/deployment/#account' }, { label: 'Administration', href: '/deployment/' }],
  })
})

test('no block, another schema or another shape is no extensions at all', () => {
  for (const value of [undefined, null, '', 0, [], 'x', { schema: 'shakerscan.ui-extensions/v2', nav: block().nav },
    { ...block(), schema: undefined }, [block()]]) {
    assert.equal(parseUiExtensions(value), NO_EXTENSIONS)
  }
  assert.deepEqual(parseUiExtensions({ schema: SCHEMA }), { sections: [], pages: [], nav: [], slots: {}, account: null })
  // Members of the wrong type are empty, not an error.
  assert.deepEqual(
    parseUiExtensions({ schema: SCHEMA, sections: 'x', pages: {}, nav: 7, slots: [], account: 'ada' }),
    { sections: [], pages: [], nav: [], slots: {}, account: null },
  )
})

test('unknown members are ignored and never copied', () => {
  const declared = block()
  declared.future = { anything: true }
  declared.pages[0].html = '<img src=x onerror=alert(1)>'
  declared.nav[0].onClick = 'alert(1)'
  declared.account.avatar = 'https://elsewhere.example/a.png'
  declared.slots['dashboard.top'] = [{ id: 'x', title: 'X', src: '/deployment/x' }]
  const parsed = parseUiExtensions(declared)
  assert.deepEqual(Object.keys(parsed).sort(), ['account', 'nav', 'pages', 'sections', 'slots'])
  assert.deepEqual(Object.keys(parsed.pages[0]).sort(), ['id', 'src', 'title'])
  assert.equal('onClick' in parsed.nav[0], false)
  assert.deepEqual(Object.keys(parsed.account).sort(), ['detail', 'links', 'name', 'sign_out'])
  assert.deepEqual(Object.keys(parsed.slots), ['finding.detail'], 'only the slots this UI has')
})

test('paths stay on this origin: anything that could leave it is refused', () => {
  const refused = [
    'https://elsewhere.example/', 'http://elsewhere.example', '//elsewhere.example/x', '/\\elsewhere.example',
    '\\\\elsewhere.example', 'javascript:alert(1)', 'data:text/html,<p>', 'relative/path', '', ' /x', '/x y',
    '/a//b', '/a/../b', '/..', '/a/..', '/a/%2e%2e/b', '/a/%2E%2e', '/a%2fb', '/a%5Cb', '/a\tb', '/a\nb',
    '/a<b', '/a"b', "/a'b", '/a`b', '/a{b}', '/a|b', '/a;b', '/\u202e/x', '/é', `/${'a'.repeat(LIMITS.path)}`,
    null, undefined, 7, {}, ['/x'],
  ]
  for (const value of refused) assert.equal(safePath(value), null, JSON.stringify(value))
  for (const value of ['/', '/x', '/deployment/embed/schedules', '/deployment/#account', '/x?target=1&new=1',
    '/x?next=%2Fy', '/a.b/c_d-e~f', '/x?u=a@b,c:d+e', `/${'a'.repeat(LIMITS.path - 1)}`]) {
    assert.equal(safePath(value), value, value)
  }
  // A dot segment in the query is data, not a path.
  assert.equal(safePath('/x?back=../y'), '/x?back=../y')
})

test('a path is resolved against the page origin before it is used', () => {
  const origin = 'https://scanner.example.test'
  assert.equal(sameOriginPath('/deployment/embed/schedules?target=1#top', origin), '/deployment/embed/schedules?target=1#top')
  assert.equal(sameOriginPath('/a/./b', origin), '/a/b', 'spelled as the browser will request it')
  for (const value of ['//elsewhere.example/x', 'https://elsewhere.example/', '/\\elsewhere.example', 'x', null]) {
    assert.equal(sameOriginPath(value, origin), null, String(value))
  }
  assert.equal(sameOriginPath('/x', 'not an origin'), null)
  assert.equal(sameOriginPath('/x', undefined), null)
})

test('text is bounded plain text', () => {
  assert.equal(safeText('  Retests and fixes '), 'Retests and fixes')
  assert.equal(safeText('<b>bold</b>'), '<b>bold</b>', 'markup is kept as characters: the UI draws text only')
  for (const value of ['', '   ', 'x'.repeat(LIMITS.text + 1), 'a\u0000b', 'a\nb', 'a\u202eb', 'a\u2028b', 7, null, undefined, {}, ['x']]) {
    assert.equal(safeText(value), null, JSON.stringify(value))
  }
  assert.equal(safeText('x'.repeat(LIMITS.text)), 'x'.repeat(LIMITS.text))
})

test('an entry that fails a check is dropped; the rest of the block stays', () => {
  const declared = block()
  declared.pages.push(
    { id: 'Bad Id', title: 'X', src: '/deployment/x' },
    { id: 'no-title', src: '/deployment/x' },
    { id: 'away', title: 'Away', src: 'https://elsewhere.example/' },
    { id: 'schedules', title: 'Duplicate id', src: '/deployment/other' },
    { id: 'marker', title: 'Marker', src: '/deployment/{finding_id}' },
    'page', null,
  )
  declared.nav.push(
    { label: 'Unknown page', page: 'nowhere' },
    { label: 'Two destinations', page: 'retests', href: '/deployment/x' },
    { label: 'No destination' },
    { label: 'Leaves', href: '//elsewhere.example' },
    { label: 'Script', href: 'javascript:alert(1)' },
    { href: '/deployment/unnamed' },
    { label: 'Dropped page', page: 'away' },
    { label: 'Odd icon', href: '/deployment/ok', icon: '<svg onload=alert(1)>', section: 7, after: 'https://x' },
  )
  declared.sections.push({ id: 'UPPER', label: 'X' }, { id: 'unnamed' }, { id: 'remediation', label: 'Again' })
  declared.slots['finding.detail'].push({ id: 'two', title: 'Two', src: '/deployment/{other}' })
  declared.account.links.push({ label: 'Away', href: 'https://elsewhere.example' }, { href: '/x' }, 'link')
  declared.account.sign_out = 'https://elsewhere.example/logout'
  const parsed = parseUiExtensions(declared)
  assert.deepEqual(parsed.pages.map((page) => [page.id, page.src]), [
    ['schedules', '/deployment/embed/schedules'], ['retests', '/deployment/embed/retests'],
  ])
  assert.deepEqual(parsed.nav.map((entry) => entry.label), ['Schedules', 'Retests and fixes', 'Status page', 'Odd icon'])
  assert.deepEqual(parsed.nav.at(-1), { label: 'Odd icon', icon: DEFAULT_ICON, href: '/deployment/ok' })
  assert.deepEqual(parsed.sections.map((entry) => entry.id), ['remediation'])
  assert.deepEqual(parsed.slots['finding.detail'].map((panel) => panel.id), ['remediation'])
  assert.deepEqual(parsed.account.links.map((link) => link.label), ['My account', 'Administration'])
  assert.equal(parsed.account.sign_out, null)
})

test('an account block needs a name; everything else in it is optional', () => {
  assert.equal(parseUiExtensions({ schema: SCHEMA, account: { detail: 'Administrator' } }).account, null)
  assert.equal(parseUiExtensions({ schema: SCHEMA, account: { name: '<script>' .repeat(20) } }).account, null)
  assert.deepEqual(parseUiExtensions({ schema: SCHEMA, account: { name: 'ada' } }).account,
    { name: 'ada', detail: null, links: [], sign_out: null })
})

test('counts are bounded: what is declared beyond a limit is not read', () => {
  const many = (count, make) => Array.from({ length: count }, (_, index) => make(index))
  const parsed = parseUiExtensions({
    schema: SCHEMA,
    sections: many(50, (i) => ({ id: `s${i}`, label: `Section ${i}` })),
    pages: many(500, (i) => ({ id: `p${i}`, title: `Page ${i}`, src: `/deployment/p${i}` })),
    nav: many(500, (i) => ({ label: `Entry ${i}`, href: `/deployment/e${i}` })),
    slots: { 'finding.detail': many(50, (i) => ({ id: `f${i}`, title: `Panel ${i}`, src: '/deployment/f/{finding_id}' })) },
    account: { name: 'ada', links: many(50, (i) => ({ label: `Link ${i}`, href: `/deployment/l${i}` })) },
  })
  assert.equal(parsed.sections.length, LIMITS.sections)
  assert.equal(parsed.pages.length, LIMITS.pages)
  assert.equal(parsed.nav.length, LIMITS.nav)
  assert.equal(parsed.slots['finding.detail'].length, LIMITS.slotPanels)
  assert.equal(parsed.account.links.length, LIMITS.accountLinks)
})

test('the icon list is fixed and has a default', () => {
  assert.ok(ICON_NAMES.includes(DEFAULT_ICON))
  assert.equal(new Set(ICON_NAMES).size, ICON_NAMES.length)
  for (const icon of ['constructor', '__proto__', 'toString', '', null, 3, 'Ticket']) {
    const [entry] = parseUiExtensions({ schema: SCHEMA, nav: [{ label: 'X', href: '/x', icon }] }).nav
    assert.equal(entry.icon, DEFAULT_ICON, String(icon))
  }
})

test("a hosted page receives the outer page's query string", () => {
  assert.equal(hostedPageSrc('/deployment/embed/schedules'), '/deployment/embed/schedules')
  assert.equal(hostedPageSrc('/deployment/embed/schedules', ''), '/deployment/embed/schedules')
  assert.equal(hostedPageSrc('/deployment/embed/schedules', '?target=1&new=1'), '/deployment/embed/schedules?target=1&new=1')
  assert.equal(hostedPageSrc('/deployment/embed/schedules', 'target=1'), '/deployment/embed/schedules?target=1')
  assert.equal(hostedPageSrc('/deployment/embed?view=schedules', 'target=1'), '/deployment/embed?view=schedules&target=1')
  assert.equal(hostedPageSrc('/deployment/embed#list', 'target=1'), '/deployment/embed?target=1#list')
  // What the browser would not have written as a query is not passed on.
  assert.equal(hostedPageSrc('/deployment/embed', 'a=1#/elsewhere'), '/deployment/embed')
  assert.equal(hostedPageSrc('/deployment/embed', `a=${'1'.repeat(LIMITS.query)}`), '/deployment/embed')
})

test('a slot placeholder is filled only with an identifier', () => {
  const src = '/deployment/embed/finding/{finding_id}'
  const id = '00000000-0000-4000-8000-0000000009AB'
  assert.equal(slotPanelSrc(src, { finding_id: id }), `/deployment/embed/finding/${id.toLowerCase()}`)
  assert.equal(slotPanelSrc('/deployment/embed/static', { finding_id: id }), '/deployment/embed/static')
  for (const value of [undefined, '', '../../x', '1', 'x/y', `${id}/..`, `${id}?a=1`, 7]) {
    assert.equal(slotPanelSrc(src, { finding_id: value }), null, String(value))
  }
  assert.equal(slotPanelSrc(src, {}), null, 'an unfilled placeholder is not requested')
})

const groups = () => [
  { heading: null, items: [{ href: '/' }, { href: '/docs' }] },
  { heading: 'Testing', items: [{ href: '/targets' }, { href: '/scans' }, { href: '/findings' }] },
  { heading: 'Operations', items: [{ href: '/workers' }] },
]
const outline = (placed) => placed.map((group) => [group.heading, group.items.map((item) => item.href)])

test('entries and sections are placed where they ask to be', () => {
  const before = groups()
  const placed = placeNavigation(before, parseUiExtensions(block()))
  assert.deepEqual(outline(placed), [
    [null, ['/', '/docs']],
    ['Testing', ['/targets', '/scans', '/ext/schedules', '/findings']],
    ['Remediation', ['/ext/retests', '/deployment/status']],
    ['Operations', ['/workers']],
  ])
  assert.deepEqual(outline(before), outline(groups()), 'the list given is not changed')
  const [schedules] = placed[1].items.filter((item) => item.extension)
  assert.deepEqual(
    { label: schedules.label, icon: schedules.icon, hosted: schedules.hosted },
    { label: 'Schedules', icon: 'calendar-clock', hosted: true },
  )
  assert.equal(placed[2].items[1].hosted, false, 'an href entry is an ordinary navigation')
})

test('no extensions leaves the menu exactly as it is', () => {
  for (const extensions of [NO_EXTENSIONS, null, undefined, parseUiExtensions({ schema: 'other' })]) {
    assert.deepEqual(placeNavigation(groups(), extensions), groups())
  }
})

test('entries that name the same place keep their declared order', () => {
  const placed = placeNavigation(groups(), parseUiExtensions({
    schema: SCHEMA,
    nav: [
      { label: 'One', href: '/deployment/one', section: 'Testing', after: '/scans' },
      { label: 'Two', href: '/deployment/two', section: 'Testing', after: '/scans' },
      { label: 'Last', href: '/deployment/last', section: 'Testing' },
      { label: 'No anchor here', href: '/deployment/end', section: 'Testing', after: '/nowhere' },
    ],
  }))
  assert.deepEqual(outline(placed)[1], ['Testing', [
    '/targets', '/scans', '/deployment/one', '/deployment/two', '/findings', '/deployment/last', '/deployment/end',
  ]])
})

test('an entry whose section this menu does not have goes under More; an empty section is not drawn', () => {
  const placed = placeNavigation(groups(), parseUiExtensions({
    schema: SCHEMA,
    sections: [{ id: 'empty', label: 'Nothing here' }, { id: 'late', label: 'Reports', after: 'No such heading' }],
    nav: [
      { label: 'Renamed', href: '/deployment/a', section: 'A heading from another release' },
      { label: 'Unplaced', href: '/deployment/b' },
      { label: 'Report', href: '/deployment/r', section: 'late' },
    ],
  }))
  assert.deepEqual(outline(placed).slice(3), [
    ['Reports', ['/deployment/r']],
    [FALLBACK_SECTION, ['/deployment/a', '/deployment/b']],
  ])
})
