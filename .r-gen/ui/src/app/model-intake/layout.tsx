import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Model Intake')

export default function ModelIntakeLayout({ children }: { children: ReactNode }) {
  return children
}
