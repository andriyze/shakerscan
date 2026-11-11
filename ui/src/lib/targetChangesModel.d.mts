export interface ChangesView {
  resolved: boolean
  sinceLabel: string
  sinceAt: string | null
  note: string
  groups: Array<{ label: string; items: string[] }>
  states: string
}
export const SINCE_CHOICES: ReadonlyArray<{ value: string; label: string }>
export function changesView(report: unknown): ChangesView
