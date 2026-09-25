import { abortable, Budget } from './budget.ts';
import { isPublicAddress } from './safety.ts';
import { normalizeTarget } from './target.ts';
import type { Check } from './types.ts';

export interface Head { status: number; headers: Map<string, string> }
const HEADER_CAP = 16384;
class ProbeError extends Error {
  constructor(readonly stage: string) { super('Probe unavailable'); }
}
export function parseHead(text: string): Head {
  if (text.length > HEADER_CAP || /[^\x09\x0a\x0d\x20-\x7e]/.test(text)) throw new Error('Invalid headers');
  const lines = text.split('\r\n');
  const match = /^HTTP\/1\.[01] ([2-5][0-9]{2})(?: [\x20-\x7e]*)?$/.exec(lines.shift() ?? '');
  if (!match || lines.length > 100) throw new Error('Invalid status');
  const headers = new Map<string, string>();
  for (const line of lines) {
    if (!line) continue;
    const field = /^([!#$%&'*+.^_`|~0-9a-zA-Z-]+):[ \t]*([^\r\n]*)$/.exec(line);
    if (!field || field[2]!.length > 4096) throw new Error('Invalid header');
    const key = field[1]!.toLowerCase();
    if (headers.has(key)) {
      if (['location', 'strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'access-control-allow-origin', 'access-control-allow-credentials'].includes(key)) throw new Error('Duplicate posture header');
      continue;
    }
    headers.set(key, field[2]!.trim());
  }
  return { status: Number(match[1]), headers };
}
export function redirectKind(location: string | undefined, host: string, https: boolean): string {
  if (!location) return 'missing';
  if (location.length > 2048 || /[\x00-\x20\x7f\\]/.test(location)) return 'refused';
  try {
    const url = new URL(location, `${https ? 'https' : 'http'}://${host}/`);
    // Even explicit default ports are refused: URL.port alone erases them.
    const authority = /^(?:[a-z]+:)?\/\/([^/]+)/i.exec(location)?.[1];
    if (authority?.includes(':') || url.username || url.password || !['http:', 'https:'].includes(url.protocol) || (/^[\d.]+$|:/.test(host) ? url.hostname !== host : normalizeTarget(url.hostname) !== host)) return 'refused';
    return url.protocol === 'https:' ? 'same_host_https' : 'same_host_http';
  } catch { return 'refused'; }
}

