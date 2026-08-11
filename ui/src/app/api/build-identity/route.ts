import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

// The Docker build writes this immutable file from its build argument and the
// runner image copies it in. Do not report the Compose runtime environment:
// that would let an old UI image claim it is the requested release.
function bakedUiVersion(): string {
  try {
    return readFileSync(join(process.cwd(), 'UI_BUILD_VERSION'), 'utf8').trim() || 'dev'
  } catch {
    return process.env.NEXT_PUBLIC_APP_VERSION || 'dev'
  }
}

export async function GET() {
  return NextResponse.json(
    { ui_version: bakedUiVersion() },
    { headers: { 'Cache-Control': 'no-store' } },
  )
}
