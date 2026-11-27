import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import dgram from 'node:dgram';
import https from 'node:https';
import { Budget } from '../src/budget.ts';
import { checkCallerCountry } from '../src/checks/geo.ts';
import { ipNetworks } from '../src/checks/ipinfo.ts';
import { pinnedHead, pinnedText } from '../src/checks/probe.ts';
import { udpExchange } from '../src/checks/nameservers.ts';
import type { Fetcher } from '../src/types.ts';

// Each operation below is bounded by the budget deadline, not its own cap. The wall clock is
// frozen 10 ms into a 30 ms budget, so the operation's timer is due 10 ms before the budget's
// own timer and Date.now() never reaches the deadline: only a deadline-bound timer that
// expires the budget can make the following reserve() refuse.
function spentBudget(): Budget {
  const budget = new Budget(30);
  mock.timers.enable({ apis: ['Date'], now: Date.now() + 10 });
  return budget;
}
function assertExpired(budget: Budget) {
  assert.equal(budget.signal.aborted, true);
  assert.throws(() => budget.reserve(), { code: 'timeout' });
}
const hungFetch: Fetcher = (_url, init) => new Promise((_resolve, reject) => {
  init.signal!.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
});

test('geo: a deadline-bound lookup timeout expires the budget and reports a timeout', async () => {
  const budget = spentBudget();
  try {
    await assert.rejects(checkCallerCountry('198.51.100.5', 'caller', 'token', budget, hungFetch), { code: 'timeout' });
    assertExpired(budget);
  } finally { budget.close(); mock.timers.reset(); }
});

test('ipinfo: a deadline-bound batch timeout expires the budget', async () => {
  const budget = spentBudget();
  try {
    const result = await ipNetworks(['1.1.1.1'], ['1.1.1.1'], {}, [], 'token', budget, hungFetch);
    assert.equal(result.enrichment, 'unavailable');
    assertExpired(budget);
  } finally { budget.close(); mock.timers.reset(); }
});

test('probe: deadline-bound HEAD and text requests expire the budget', async () => {
  const requests = mock.method(https, 'request', ((options: https.RequestOptions) => {
    const request = Object.assign(new EventEmitter(), { maxHeadersCount: 0, end() {}, destroy() {} });
    options.signal!.addEventListener('abort', () => request.emit('error', new Error('aborted')), { once: true });
    return request;
  }) as unknown as typeof https.request);
  try {
    for (const run of [(b: Budget) => pinnedHead('example.com', '8.8.8.8', true, b), (b: Budget) => pinnedText('example.com', '8.8.8.8', '/', b)]) {
      const budget = spentBudget();
      try { await assert.rejects(run(budget)); assertExpired(budget); }
      finally { budget.close(); mock.timers.reset(); }
    }
    assert.equal(requests.mock.callCount(), 2);
  } finally { requests.mock.restore(); }
});

test('nameservers: a deadline-bound UDP exchange timeout expires the budget', async () => {
  const sockets = mock.method(dgram, 'createSocket', (() =>
    Object.assign(new EventEmitter(), { connect() {}, send() {}, close() {} })) as unknown as typeof dgram.createSocket);
  const budget = spentBudget();
  try {
    await assert.rejects(udpExchange('8.8.8.8', new Uint8Array(12), budget), { message: 'timeout' });
    assertExpired(budget);
    assert.equal(sockets.mock.callCount(), 1);
  } finally { budget.close(); mock.timers.reset(); sockets.mock.restore(); }
});
