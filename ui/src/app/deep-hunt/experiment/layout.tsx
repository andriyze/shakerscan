import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Test plan')

export default function DeepHuntExperimentLayout({ children }: { children: ReactNode }) {
  return children
}
