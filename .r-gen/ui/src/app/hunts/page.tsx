import { redirect } from 'next/navigation'

// Hunts, their history and each run live on one page (/hunt). Old links keep their filters.
export default async function HuntsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(await searchParams)) {
    for (const item of Array.isArray(value) ? value : value === undefined ? [] : [value]) params.append(key, item)
  }
  redirect(`/hunt${params.size ? `?${params}` : ''}`)
}
