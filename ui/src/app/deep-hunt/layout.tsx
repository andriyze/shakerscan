import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Hunts')

export default function DeepHuntLayout({ children }: { children: ReactNode }) {
  return children
}
