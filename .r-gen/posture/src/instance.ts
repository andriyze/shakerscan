// Self-hosted entry point: one check per process. The API writes the JSON request body to
// stdin and reads {"status", "body"} from stdout. No quota, cache or target restrictions apply;
// the instance operator decides what to check.
import { randomBytes } from 'node:crypto';
import { configureTargetPolicy } from './safety.ts';
import { handle, INSTANCE_POLICY } from './checks/service.ts';
import { unlimitedStore } from './checks/store.ts';
import { systemNameserver, systemResolverFetcher } from './resolver.ts';

const MAX_INPUT = 4096;

async function readInput(): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    size += (chunk as Buffer).length;
    if (size > MAX_INPUT) return 'x'.repeat(MAX_INPUT + 1);
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export async function runInstanceCheck(body: string, env: NodeJS.ProcessEnv = process.env) {
  configureTargetPolicy('any');
  const nameserver = env.POSTURE_RESOLVER === 'system' ? systemNameserver() : null;
  const fetcher = nameserver ? systemResolverFetcher(nameserver) : fetch;
  const response = await handle({ version: '2.0', rawPath: '/v1/check', rawQueryString: '',
    headers: { 'content-type': 'application/json' }, body,
    requestContext: { http: { method: 'POST', sourceIp: '127.0.0.1' } } },
  unlimitedStore(), randomBytes(32).toString('hex'), true, fetcher, env.POSTURE_IPINFO_TOKEN ?? '', fetch, false, INSTANCE_POLICY);
  return { status: response.statusCode, body: JSON.parse(response.body) as unknown };
}

async function main(): Promise<void> {
  // stdout carries only the result document; the engine's request log goes to stderr.
  console.log = (...values: unknown[]) => console.error(...values);
  try {
    process.stdout.write(JSON.stringify(await runInstanceCheck(await readInput())));
  } catch {
    process.stdout.write(JSON.stringify({ status: 503, body: { error: { code: 'service_unavailable', message: 'The check engine failed.' } } }));
    process.exitCode = 1;
  }
}

if (process.argv[1] && /instance\.(?:ts|cjs|js)$/.test(process.argv[1])) void main();
