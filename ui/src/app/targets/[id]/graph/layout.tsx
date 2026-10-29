import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Application graph')

export default function TargetsGraphLayout({ children }: { children: ReactNode }) {
  return children
}
