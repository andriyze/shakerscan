'use client'

import { Suspense } from 'react'
import { TargetInventory } from '@/components/targets/TargetInventory'
import { CardSkeleton } from '@/components/ui'

// One target type: domains, hosts and devices share this inventory. The former domain view
// (?view=domains) and type tabs (?type=web|network) are read as filters of the same list.
export default function TargetsPage() {
  return <Suspense fallback={<CardSkeleton count={3} />}>
    <TargetInventory />
  </Suspense>
}
