import { createPublicKey } from 'node:crypto';
import { answers, query } from '../dns.ts';
import { TYPES } from '../wire.ts';
import type { Budget } from '../budget.ts';
import type { Check, Fetcher } from '../types.ts';

export async function dkimCheck(host: string, selector: string, budget: Budget, fetcher: Fetcher): Promise<Check> {
  const owner = `${selector}._domainkey.${host}`;
  const base: Check = { id: 'mail.dkim', name: 'DKIM key', group: 'mail', status: 'unknown',
    detail: 'DKIM selector evidence was unavailable; no message signature was verified.', evidence: { selector } };
  const result = await query(owner, 'TXT', budget, fetcher);
  if (result.state !== 'ok') return base;
  let records: string[];
  try { records = answers(result, owner, TYPES.TXT).map(r => r.value ?? ''); }
  catch { return base; }
  if (!records.length) return { ...base, status: 'warn', detail: 'No DKIM TXT key was found for this selector.' };
  if (records.length !== 1) return { ...base, status: 'warn', detail: 'Multiple TXT records were found at the DKIM selector; the key is ambiguous.' };
  const tags = new Map<string, string>();
  for (const part of records[0]!.split(';').map(s => s.trim()).filter(Boolean)) {
    const match = /^([a-z][a-z0-9]*)\s*=\s*([^;]*)$/i.exec(part);
    if (!match || tags.has(match[1]!.toLowerCase())) return { ...base, status: 'warn', detail: 'The DKIM key record has malformed or duplicate tags.' };
    tags.set(match[1]!.toLowerCase(), match[2]!.trim());
  }
  if ((tags.has('v') && tags.get('v') !== 'DKIM1') || !tags.has('p')) return { ...base, status: 'warn', detail: 'The DKIM key record has an unsupported version or no public key tag.' };
  const declaredType = tags.get('k')?.toLowerCase() ?? 'rsa';
  const keyType = /^[a-z0-9-]{1,40}$/.test(declaredType) ? declaredType : 'other';
  const encoded = tags.get('p')!.replace(/\s+/g, '');
  if (!encoded) return { ...base, status: 'warn', detail: 'The DKIM key has been revoked (empty p= tag).', evidence: { selector, key_type: keyType } };
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length > 4096) return { ...base, status: 'warn', detail: 'The DKIM public key is not valid bounded base64.', evidence: { selector, key_type: keyType } };
  const key = Buffer.from(encoded, 'base64');
  if (key.toString('base64') !== encoded) return { ...base, status: 'warn', detail: 'The DKIM public key is not canonical base64.', evidence: { selector, key_type: keyType } };
  if (keyType === 'ed25519') return { ...base, status: key.length === 32 ? 'pass' : 'warn',
    detail: key.length === 32 ? 'A well-formed Ed25519 DKIM key is published; message signatures were not verified.' : 'The Ed25519 DKIM key is not 32 bytes.',
    evidence: { selector, key_type: keyType, key_bits: key.length * 8 } };
  if (keyType !== 'rsa') return { ...base, detail: 'The DKIM key type is not supported by this check.', evidence: { selector, key_type: keyType } };
  try {
    let parsed;
    try { parsed = createPublicKey({ key, format: 'der', type: 'pkcs1' }); }
    catch { parsed = createPublicKey({ key, format: 'der', type: 'spki' }); }
    const bits = parsed.asymmetricKeyDetails?.modulusLength;
    if (!bits || parsed.asymmetricKeyType !== 'rsa') throw new Error();
    return { ...base, status: bits >= 2048 ? 'pass' : 'warn',
      detail: bits >= 2048 ? 'An RSA DKIM key of at least 2048 bits is published; message signatures were not verified.' : bits >= 1024 ? 'The RSA DKIM key is below the recommended 2048 bits.' : 'The RSA DKIM key is below the 1024-bit minimum.',
      evidence: { selector, key_type: keyType, key_bits: bits } };
  } catch { return { ...base, status: 'warn', detail: 'The RSA DKIM public key could not be parsed.', evidence: { selector, key_type: keyType } }; }
}
