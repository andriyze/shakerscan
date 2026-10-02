'use client'

import { useParams } from 'next/navigation'
import { TargetAssetDetail } from '@/components/targets/TargetAssetDetail'

export default function AssetPage() {
  const params = useParams<{id: string}>()
  return <TargetAssetDetail key={params.id} id={params.id} />
}
