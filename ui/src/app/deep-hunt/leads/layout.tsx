import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Leads')

export default function DeepHuntLeadsLayout({ children }: { children: ReactNode }) {
  return children
}
