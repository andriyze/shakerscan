function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function finiteNumber(value, fallback = 0) {
  const number = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(number) ? number : fallback
}

export function scanPhasePresentation(scan) {
  const status = String(record(scan).status || 'pending').toLowerCase()
  const rawPhase = String(record(scan).current_phase || '').trim().toLowerCase()
  const progress = Math.max(0, Math.min(100, finiteNumber(record(scan).progress)))

  if (status === 'pending' || status === 'queued') {
    return {
      label: 'Waiting for a worker',
      description: 'The scan is queued. Testing will begin as soon as a compatible worker is available.',
      progress,
    }
  }

  const phases = [
    {
      terms: ['final', 'report', 'complete'],
      label: 'Preparing the report',
      description: 'Consolidating evidence, coverage, findings, and the final decision record.',
    },
    {
      terms: ['validat', 'verif', 'proof', 'attack_chain'],
      label: 'Validating evidence',
      description: 'Checking candidate findings against deterministic proof requirements.',
    },
    {
      terms: ['active', 'test', 'template', 'nuclei', 'phase_'],
      label: 'Testing the attack surface',
      description: 'Running the checks permitted by this scan’s policy and resource budget.',
    },
    {
      terms: ['discover', 'crawl', 'recon', 'probe', 'baseline', 'pre_scan', 'init'],
      label: 'Mapping the application',
      description: 'Discovering reachable pages, APIs, technologies, and baseline security posture.',
    },
  ]
  const match = phases.find((phase) => phase.terms.some((term) => rawPhase.includes(term)))
  return match ? {
    label: match.label,
    description: match.description,
    progress,
  } : {
    label: rawPhase ? rawPhase.replaceAll('_', ' ') : 'Scan in progress',
    description: 'The worker is executing the current scan plan. Activity appears below as it is recorded.',
    progress,
  }
}

export function scanLogEntry(rawLine) {
  const raw = String(rawLine || '').trim()
  const sourceMatch = raw.match(/^\[([^\]]+)\]\s*/)
  const source = sourceMatch ? sourceMatch[1] : ''
  let message = sourceMatch ? raw.slice(sourceMatch[0].length) : raw
  let kind = 'detail'
  let label = source ? source.replaceAll('_', ' ') : 'activity'
  let meta = ''

  const progress = raw.match(/\[progress\]\s+phase=([^\s]+)\s+pct=(\d+)\s+message=(.*)$/i)
  if (progress) {
    kind = 'milestone'
    label = 'milestone'
    message = progress[3].trim() || progress[1].replaceAll('_', ' ')
    meta = `${progress[2]}% · ${progress[1].replaceAll('_', ' ')}`
  } else if (/\b(error|failed|failure|traceback|exception|fatal)\b/i.test(raw)) {
    kind = 'error'
    label = 'error'
  } else if (/\b(warn(?:ing)?|timed?\s*out|partial|degraded|budget reached|skipping)\b/i.test(raw)) {
    kind = 'warning'
    label = 'attention'
  } else if (/\b(finding|vulnerab|verified|candidate|exploit)\b/i.test(raw)) {
    kind = 'finding'
    label = 'finding'
  } else if (/\b(starting|started|complete|completed|discovered|found \d+|phase)\b/i.test(raw)) {
    kind = 'milestone'
    label = 'milestone'
  }

  return { raw, source, message, kind, label, meta }
}
