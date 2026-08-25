import { redirect } from 'next/navigation'

export default async function LegacyDeviceHuntPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>
  searchParams: Promise<{ run?: string | string[] }>
}) {
  const { id } = await params
  const query = new URLSearchParams({ target: id })
  const requestedRun = (await searchParams).run
  const run = Array.isArray(requestedRun) ? requestedRun[0] : requestedRun
  if (run) query.set('legacy_run', run)
  redirect(`/hunt?${query.toString()}`)
}
