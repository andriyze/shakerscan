import { PublicError } from './response.ts';

export class Budget {
  readonly controller = new AbortController();
  readonly signal = this.controller.signal;
  readonly deadline: number;
  operations = 0;
  private timer: ReturnType<typeof setTimeout>;
  private onCancel = () => this.controller.abort();
  constructor(ms = 8000, private parent?: AbortSignal, readonly maxOperations = 7) {
    this.deadline = Date.now() + ms;
    this.timer = setTimeout(() => this.controller.abort(), ms);
    parent?.addEventListener('abort', this.onCancel, { once: true });
    if (parent?.aborted) this.controller.abort();
  }
  // A timer derived from the deadline can fire before this budget's own timer (both are
  // scheduled against the event loop's cached clock, the deadline against Date.now()),
  // so whichever deadline-bound timer fires first expires the whole budget.
  expire() { this.controller.abort(); }
  // Milliseconds an operation capped at `cap` may run, and whether the deadline (not the cap)
  // is what bounds it; deadline-bound timers must call expire() rather than abort locally.
  operationWindow(cap: number, min = 0): { ms: number; deadlineBound: boolean } {
    const remaining = this.deadline - Date.now();
    return remaining <= cap ? { ms: Math.max(min, remaining), deadlineBound: true } : { ms: cap, deadlineBound: false };
  }
  // Signal for one operation capped at `cap` ms. When the deadline bounds it, reaching the
  // deadline expires this budget, so a timed-out operation never leaves it admitting more.
  operationSignal(cap: number): AbortSignal {
    const { ms, deadlineBound } = this.operationWindow(cap, 1);
    if (!deadlineBound) return AbortSignal.any([this.signal, AbortSignal.timeout(ms)]);
    const timer = setTimeout(() => this.expire(), ms);
    timer.unref?.();
    this.signal.addEventListener('abort', () => clearTimeout(timer), { once: true });
    return this.signal;
  }
  assert() { if (this.signal.aborted || Date.now() >= this.deadline) throw new PublicError('timeout'); }
  reserve() {
    this.assert();
    if (this.operations >= this.maxOperations) throw new PublicError('dns_unavailable');
    this.operations++;
  }
  close() {
    clearTimeout(this.timer);
    this.parent?.removeEventListener('abort', this.onCancel);
    this.controller.abort();
  }
}
export function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    // The operation may already have started; consume its eventual rejection too.
    void promise.catch(() => {});
    return Promise.reject(new PublicError('timeout'));
  }
  return new Promise((resolve, reject) => {
    const abort = () => reject(new PublicError('timeout'));
    signal.addEventListener('abort', abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}
export async function boundedBody(body: ReadableStream<Uint8Array> | null, max: number, signal: AbortSignal, code: 'body_too_large' | 'dns_unavailable'): Promise<Uint8Array> {
  if (!body) return new Uint8Array();
  const reader = body.getReader();
  let length = 0;
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const { done, value } = await abortable(reader.read(), signal);
      if (done) break;
      length += value.byteLength;
      if (length > max) throw new PublicError(code);
      chunks.push(value);
    }
    const result = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return result;
  } finally {
    // Do not wait indefinitely for an upstream cancellation acknowledgement.
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
