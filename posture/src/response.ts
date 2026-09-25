export const ERRORS = {
  invalid_request: [400, 'Expected a JSON object with a string target and optional DKIM selector.'],
  target_not_allowed: [403, 'Public checks require a public DNS hostname.'],
  target_restricted: [403, 'Public checks of government and military domains are not supported.'],
  region_not_supported: [403, 'Public checks are unavailable from this region.'],
  route_not_found: [404, 'Route not found.'],
  method_not_allowed: [405, 'Method not allowed.'],
  body_too_large: [413, 'Request body exceeds the allowed size.'],
  unsupported_media_type: [415, 'Use application/json encoded as UTF-8.'],
  rate_limited: [429, 'Public check rate limit reached; try again later.'],
  hourly_quota_exceeded: [429, 'Hourly limit of 25 uncached checks reached; resets at the next UTC hour.'],
  daily_quota_exceeded: [429, 'Daily limit of 100 uncached checks reached; resets at midnight UTC.'],
  dns_unavailable: [502, 'DNS evidence is unavailable; try again later.'],
  service_unavailable: [503, 'Public checks are temporarily unavailable.'],
  timeout: [504, 'Public check deadline exceeded.']
} as const;
export class PublicError extends Error {
  constructor(public readonly code: keyof typeof ERRORS, public readonly retryAfter = 60) { super(code); }
}
export function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  const encoded = JSON.stringify(body);
  if (new TextEncoder().encode(encoded).length > 32768) throw new PublicError('service_unavailable');
  return new Response(encoded, { status, headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra
  } });
}
export function errorResponse(error: unknown, requestId: string, allow?: string): Response {
  const code = error instanceof PublicError ? error.code : 'service_unavailable';
  const [status, message] = ERRORS[code];
  return json({ error: { code, message }, request_id: requestId }, status, {
    ...(status === 429 ? { 'Retry-After': String(error instanceof PublicError ? error.retryAfter : 60) } : {}),
    ...(status === 405 && allow ? { Allow: allow } : {})
  });
}
