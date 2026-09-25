import tr46 from 'tr46';
import { PublicError } from './response.ts';
import { permitsAnyTarget } from './safety.ts';

const SPECIAL = ['localhost', 'local', 'internal', 'intranet', 'lan', 'home', 'test', 'invalid', 'example', 'onion', 'arpa'];
export function normalizeTarget(input: unknown): string {
  if (typeof input !== 'string' || input.length > 1024) throw new PublicError('invalid_request');
  let host = input.replace(/^[\t\n\r ]+|[\t\n\r ]+$/g, '');
  if (!host || /[\u0000-\u0020\u007f/\\?#@:%*\[\]]/u.test(host)) throw new PublicError('target_not_allowed');
  // Normalize Unicode dot separators before handling the single terminal dot.
  host = host.replace(/[\u3002\uff0e\uff61]/g, '.');
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (host.endsWith('.')) throw new PublicError('target_not_allowed');
  const ascii = tr46.toASCII(host, {
    checkHyphens: true, checkBidi: true, checkJoiners: true,
    useSTD3ASCIIRules: true, transitionalProcessing: false, verifyDNSLength: true
  });
  if (!ascii) throw new PublicError('target_not_allowed');
  host = ascii.toLowerCase();
  // An instance also accepts single-label and internal names; the hosted service does not.
  const any = permitsAnyTarget();
  if (!(any ? /^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/ : /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/).test(host)) {
    throw new PublicError('target_not_allowed');
  }
  if (!any && (SPECIAL.some(s => host === s || host.endsWith('.' + s)) || host === 'metadata.google.internal')) {
    throw new PublicError('target_not_allowed');
  }
  // WHATWG recognizes legacy numeric IPv4 spellings, including hexadecimal/octal.
  try {
    const parsed = new URL(`https://${host}/`);
    if (parsed.hostname !== host || /^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)) throw new Error();
  } catch { throw new PublicError('target_not_allowed'); }
  return host;
}
