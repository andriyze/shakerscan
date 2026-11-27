import { NextResponse } from 'next/server'


export const dynamic = 'force-dynamic'


function runtimeApiUrl(): string {
  const value = String(process.env.NEXT_PUBLIC_API_URL || '').trim()
  if (!value) return ''
  try {
    const parsed = new URL(value)
    if (!['http:', 'https:'].includes(parsed.protocol)) return ''
    if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
      return ''
    }
    return parsed.origin
  } catch {
    return ''
  }
}


export async function GET() {
  const value = JSON.stringify(runtimeApiUrl()).replaceAll('<', '\\u003c')
  return new NextResponse(`window.__SHAKERSCAN_API_URL__=${value};\n`, {
    status: 200,
    headers: {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'no-store, max-age=0',
      'X-Content-Type-Options': 'nosniff',
    },
  })
}
