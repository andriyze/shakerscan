import { Suspense, type ReactNode } from 'react'
import InvestigationReviewPanel from '@/components/hunt/InvestigationReviewPanel'

export default function HuntLayout({ children }: { children: ReactNode }) {
  return <>
    <Suspense fallback={null}><InvestigationReviewPanel /></Suspense>
    {children}
  </>
}
