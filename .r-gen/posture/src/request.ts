import { boundedBody, Budget } from './budget.ts';
import { PublicError } from './response.ts';

// Parsing strings with JSON.parse preserves escapes while the small object grammar
// rejects duplicate keys, nested input and unknown fields.
export function parseCheckRequest(text: string, allowSelector = true, allowPath = false): { target: string; dkim_selector?: string; path?: string } {
  let pos = 0;
  const fail = (): never => { throw new PublicError('invalid_request'); };
  const ws = () => { while (/[\x20\t\r\n]/.test(text[pos] ?? '\0')) pos++; };
  const char = (ch: string) => { ws(); if (text[pos++] !== ch) fail(); };
  const string = (): string => {
    ws(); const start = pos;
    if (text[pos++] !== '"') fail();
    while (pos < text.length) {
      const current = text[pos++];
      if (current === '\\') { pos++; continue; }
      if (current === '"') {
        try { return JSON.parse(text.slice(start, pos)) as string; } catch { fail(); }
      }
    }
    return fail();
  };
  char('{');
  const values: Record<string, string> = {};
  while (true) {
    const key = string(); char(':'); const value = string();
    if ((key !== 'target' && (key !== 'dkim_selector' || !allowSelector) && (key !== 'path' || !allowPath)) || Object.hasOwn(values, key)) fail();
    values[key] = value;
    ws(); const next = text[pos++];
    if (next === '}') break;
    if (next !== ',') fail();
  }
  ws();
  if (pos !== text.length || !Object.hasOwn(values, 'target')) fail();
  const selector = values.dkim_selector;
  if (selector !== undefined && (!/^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/i.test(selector) || selector.length > 63)) fail();
  const path = values.path;
  if (path !== undefined && (path.length > 256 || !/^\/[a-zA-Z0-9/_~.-]*$/.test(path) || path.includes('//') || path.split('/').some(part => part === '..' || part === '.'))) fail();
  return { target: values.target!, ...(selector === undefined ? {} : { dkim_selector: selector.toLowerCase() }),
    ...(path === undefined ? {} : { path }) };
}
export function parseRequest(text: string): string { return parseCheckRequest(text, false).target; }
async function readBody(request: Request, budget: Budget): Promise<string> {
  if (!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(request.headers.get('content-type') ?? '') || request.headers.has('content-encoding')) {
    throw new PublicError('unsupported_media_type');
  }
  const length = request.headers.get('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > 2048)) throw new PublicError('body_too_large');
  const bytes = await boundedBody(request.body, 2048, budget.signal, 'body_too_large');
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch (error) { if (error instanceof PublicError) throw error; throw new PublicError('invalid_request'); }
}
export async function readTarget(request: Request, budget: Budget): Promise<string> { return parseRequest(await readBody(request, budget)); }
export async function readCheckRequest(request: Request, budget: Budget, allowPath = false) { return parseCheckRequest(await readBody(request, budget), true, allowPath); }
