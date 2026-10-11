export interface InterpretationView {
  id: string
  label: string
  title: string
  body: string
  quoted: boolean
  trust: string
  writer: string
  status: string
  inactive: boolean
  evidenceCount: number
  applicability: string
}
export interface NegativeView extends InterpretationView { source: string; serverOwned: boolean }
export const KIND_LABELS: Readonly<Record<string, string>>
export const NEGATIVE_LABELS: Readonly<Record<string, string>>
export const SOURCE_LABELS: Readonly<Record<string, string>>
export function interpretationView(entry: unknown): InterpretationView
export function negativeView(row: unknown): NegativeView
export function summarize(entries: unknown): { groups: Array<{ kind: string; label: string; items: InterpretationView[] }>; total: number; active: number }
