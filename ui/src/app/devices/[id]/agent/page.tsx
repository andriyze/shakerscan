import { redirect } from 'next/navigation'

export default async function LegacyDeviceHuntPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  redirect(`/hunt?target=${encodeURIComponent(id)}`)
}
