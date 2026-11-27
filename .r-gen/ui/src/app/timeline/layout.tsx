import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Timeline')

export default function TimelineLayout({ children }: { children: ReactNode }) {
  return children
}
