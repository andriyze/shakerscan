export function scanFailureRecommendation(message: unknown, isShard = false): string {
  if (isShard) {
    return 'Open the parent Scan to review sibling status and the authoritative final result.'
  }
  const text = String(message || '')
  if (/heartbeat|queue delivery|worker job|worker ownership|reclaimed/i.test(text)) {
    return 'Review worker and queue health plus the execution log, then retry. A heartbeat timeout does not by itself mean the target was unreachable.'
  }
  if (/\bdns\b|resolve|connection refused|connection reset|unreachable|name or service not known|network is unreachable/i.test(text)) {
    return 'Confirm the target address is correct and reachable from the scanner, then try again.'
  }
  return 'Review the failure above, then retry this target when the underlying problem is resolved.'
}
