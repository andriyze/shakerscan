import { NextResponse } from 'next/server'

// Never serialize the Model Intake bearer credential to a browser endpoint.
// Host and forwarding headers are caller-controlled and cannot prove that a
// request reached a loopback-published container directly rather than through
// a reverse proxy. The browser may retain a credential the operator explicitly
// entered for this session, but the UI server is not a secret-distribution
// service.
export const dynamic = 'force-dynamic'

export async function GET() {
  return NextResponse.json(
    {
      available: false,
      reason: 'manual_required',
      detail: 'Corporate admission actions require an operator credential for this browser session.',
      hint: 'Use the local ShakerScan command shown in the Admission step, or obtain a reviewer credential through the approved secret channel.',
    },
    { headers: { 'Cache-Control': 'no-store' } },
  )
}
