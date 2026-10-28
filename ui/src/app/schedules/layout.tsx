import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Schedules')

export default function SchedulesLayout({ children }: { children: ReactNode }) {
  return children
}
