import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('AI Gate')

export default function AiGateLayout({ children }: { children: ReactNode }) {
  return children
}
