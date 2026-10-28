import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Autonomous run')

export default function DeepHuntRunsDetailLayout({ children }: { children: ReactNode }) {
  return children
}
