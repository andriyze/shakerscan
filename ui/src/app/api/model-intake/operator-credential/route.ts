import { createHmac, randomBytes } from 'node:crypto'
import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

const SESSION_VERSION = 'mi-local-v1'
const SESSION_LIFETIME_SECONDS = 8 * 60 * 60
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]'])

function localSessionIsAllowed(): boolean {
  const bindHost = (process.env.SHAKERSCAN_BIND_HOST || '127.0.0.1').trim()
  const publicHost = (process.env.SHAKERSCAN_PUBLIC_HOST || '').trim()
  return LOOPBACK_HOSTS.has(bindHost)
    && (!publicHost || LOOPBACK_HOSTS.has(publicHost))
}

export async function GET() {
  const secret = (process.env.MODEL_INTAKE_LOCAL_SESSION_SECRET || '').trim()
  if (!localSessionIsAllowed()) {
    return NextResponse.json({
      available: false,
      reason: 'manual_required',
      detail: 'This remote or managed deployment requires a named Model Intake reviewer credential.',
      hint: 'Obtain the credential through your organization’s approved secret or identity channel.',
    }, { headers: { 'Cache-Control': 'no-store' } })
  }
  if (secret.length < 32) {
    return NextResponse.json({
      available: false,
      reason: 'not_configured',
      detail: 'The local Model Intake session is not configured. Restart ShakerScan to repair it.',
    }, { headers: { 'Cache-Control': 'no-store' } })
  }

  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_LIFETIME_SECONDS
  const nonce = randomBytes(16).toString('hex')
  const unsigned = `${SESSION_VERSION}.${expiresAt}.${nonce}`
  const signature = createHmac('sha256', secret).update(unsigned).digest('hex')
  return NextResponse.json({
    available: true,
    reason: 'local_session',
    token: `${unsigned}.${signature}`,
    expires_at: new Date(expiresAt * 1000).toISOString(),
  }, { headers: { 'Cache-Control': 'no-store' } })
}
