import { test } from 'node:test';
import assert from 'node:assert/strict';
import { boundedBody, Budget } from '../src/budget.ts';
import { readTarget } from '../src/request.ts';
test('streamed body cap applies without Content-Length and cancels the reader', async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({ pull(c) { c.enqueue(new Uint8Array(1025)); }, cancel() { cancelled = true; } });
  const budget = new Budget();
  try { await assert.rejects(boundedBody(stream, 2048, budget.signal, 'body_too_large'), { code: 'body_too_large' }); assert.equal(cancelled, true); }
  finally { budget.close(); }
});
test('slow incoming stream respects overall deadline and cancels reader', async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
  const budget = new Budget(10);
  try { await assert.rejects(boundedBody(stream, 2048, budget.signal, 'body_too_large'), { code: 'timeout' }); assert.equal(cancelled, true); }
  finally { budget.close(); }
});
test('invalid UTF-8 and BOM are rejected before JSON parsing', async () => {
  for (const bytes of [new Uint8Array([0xff]), new Uint8Array([0xef, 0xbb, 0xbf, ...Buffer.from('{"target":"example.com"}')])]) {
    const budget = new Budget();
    try { await assert.rejects(readTarget(new Request('https://service.test/v1/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: bytes }), budget), { code: 'invalid_request' }); }
    finally { budget.close(); }
  }
});
test('outbound reservations are bounded even when reserved concurrently', async () => {
  const budget = new Budget();
  try {
    const attempts = await Promise.allSettled(Array.from({ length: 12 }, async () => budget.reserve()));
    assert.equal(attempts.filter(a => a.status === 'fulfilled').length, 7);
    assert.equal(budget.operations, 7);
  } finally { budget.close(); }
});
