import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Hunts')

export default function HuntLayout({ children }: { children: ReactNode }) {
  return <>{children}</>
}
