import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Fleet')

export default function FleetLayout({ children }: { children: ReactNode }) {
  return children
}
