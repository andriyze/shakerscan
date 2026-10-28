import type { Metadata } from 'next'
import DashboardPage from '@/components/DashboardPage'
import { rootPageTitle } from '@/lib/pageTitle'

// A server page so the dashboard names its own tab ("Dashboard · ShakerScan") while the root
// layout's default stays the bare product name; the dashboard itself is a client component.
export const metadata: Metadata = rootPageTitle('Dashboard')

export default function Home() {
  return <DashboardPage />
}
