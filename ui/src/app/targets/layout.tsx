import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Targets')

export default function TargetsLayout({ children }: { children: ReactNode }) {
  return children
}
