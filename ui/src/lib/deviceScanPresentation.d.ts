export type DeviceScorePresentation = {
  isDevice: boolean
  status: 'final' | 'provisional' | 'unavailable'
  grade: string | null
  score: number | null
  note: string | null
}

export function deviceScorePresentation(scan: unknown): DeviceScorePresentation
