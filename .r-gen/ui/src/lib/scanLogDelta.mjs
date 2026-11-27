/** Merge a numbered Scan log window; legacy replies remain full-tail replacements. */
export function emptyScanLogState() {
  return { lines: [], nextSeq: null, partial: false }
}

export function mergeScanLogReply(previous, reply, limit = 500) {
  if (!reply || !Array.isArray(reply.lines) || reply.lines.some(line => typeof line !== 'string')) {
    throw new Error('The scan log reply is malformed')
  }
  const numbered = reply.seq_supported === true
  let lines = reply.lines
  let nextSeq = null
  let partial = false
  if (numbered) {
    const last = reply.next_seq
    const first = reply.first_seq
    if (!Number.isSafeInteger(last) || last < 0 || !Number.isSafeInteger(first) || first < 1 ||
        first + lines.length - 1 !== last) {
      throw new Error('The scan log sequence is malformed')
    }
    // A late answer never rewinds a newer poll. An actual reset is explicitly truncated.
    if (previous.nextSeq !== null && last < previous.nextSeq && !reply.truncated) return previous
    nextSeq = last
    if (previous.nextSeq !== null && !reply.truncated && first <= previous.nextSeq + 1) {
      const overlap = Math.max(0, previous.nextSeq - first + 1)
      lines = [...previous.lines, ...lines.slice(overlap)]
      partial = previous.partial
    } else {
      partial = reply.truncated === true || first > 1
    }
  }
  partial ||= lines.length > limit
  lines = lines.slice(-limit)
  if (nextSeq === previous.nextSeq && partial === previous.partial &&
      lines.length === previous.lines.length && lines.every((line, index) => line === previous.lines[index])) {
    return previous
  }
  return { lines, nextSeq, partial }
}
