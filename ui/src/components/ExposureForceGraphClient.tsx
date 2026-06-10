'use client'

// Thin forwardRef wrapper so the imperative ForceGraph2D ref (zoomToFit,
// centerAt) survives next/dynamic ssr:false loading.
import { forwardRef } from 'react'
import ForceGraph2D from 'react-force-graph-2d'

const ExposureForceGraphClient = forwardRef<unknown, Record<string, unknown>>(
  function ExposureForceGraphClient(props, ref) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return <ForceGraph2D ref={ref as any} {...(props as any)} />
  }
)

export default ExposureForceGraphClient
