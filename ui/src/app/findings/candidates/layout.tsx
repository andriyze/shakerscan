import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Investigation candidates')

export default function FindingsCandidatesLayout({ children }: { children: ReactNode }) {
  return children
}
