import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

export async function GET() {
  const secret = (process.env.MODEL_INTAKE_LOCAL_SESSION_SECRET || '').trim()
  if (secret.length < 32) {
    return NextResponse.json({
      available: false,
      reason: 'not_configured',
      detail: 'The local Model Intake session is not configured. Restart ShakerScan to repair it.',
    }, { headers: { 'Cache-Control': 'no-store' } })
  }

  try {
    const response = await fetch('http://api:8080/model-intake/operator-session', {
      headers: { 'X-Shakerscan-Local-Session-Secret': secret },
      cache: 'no-store',
    })
    const payload = await response.json()
    return NextResponse.json(payload, {
      status: response.status,
      headers: { 'Cache-Control': 'no-store' },
    })
  } catch {
    return NextResponse.json({
      available: false,
      reason: 'unavailable',
      detail: 'The API is not ready to create a local Model Intake session.',
    }, { status: 503, headers: { 'Cache-Control': 'no-store' } })
  }
}
