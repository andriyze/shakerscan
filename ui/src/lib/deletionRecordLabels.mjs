// Names for the record kinds a deletion preview counts. The preview keys are storage names;
// people approve a deletion by what the records are. Kinds without a name here are working
// records of the scans and are listed under one total.
const NAMED = [
  ['targets', 'Targets'],
  ['scans', 'Scans'],
  ['findings', 'Findings'],
  ['hunts', 'Hunts'],
  ['schedules', 'Schedules'],
  ['evidence_objects', 'Evidence files'],
  ['http_transactions', 'Recorded requests and responses'],
  ['discovered_secrets', 'Discovered secrets'],
  ['target_endpoints', 'Discovered routes'],
  ['credential_profiles', 'Credentials'],
  ['request_collections', 'Request collections'],
]

const spaced = (key) => {
  const text = String(key).replaceAll('_', ' ').trim()
  return text ? text[0].toUpperCase() + text.slice(1) : 'Other records'
}

/** {storage_name: {count}} -> named rows first, the rest gathered with one total. */
export function deletionRecordRows(records) {
  const entries = Object.entries(records && typeof records === 'object' ? records : {})
    .map(([key, value]) => [key, Number(value?.count) || 0])
  const named = []
  for (const [key, label] of NAMED) {
    const found = entries.find(([name]) => name === key)
    if (found) named.push({ key, label, count: found[1] })
  }
  const known = new Set(NAMED.map(([key]) => key))
  const other = entries.filter(([key]) => !known.has(key)).map(([key, count]) => ({ key, label: spaced(key), count }))
  return { named, other, otherTotal: other.reduce((sum, row) => sum + row.count, 0) }
}
