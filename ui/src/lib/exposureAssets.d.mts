import type { ExposureAssetsResponse } from './api'

export function exposureAssetsParams(input?: {
  limit?: number
  root_domain?: string
  kind?: string
  cohort?: string
}): Record<string, string>

export function exposureAssetsFromBody(body: unknown): ExposureAssetsResponse
