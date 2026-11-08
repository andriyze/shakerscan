export interface CandidateTargetFields {
  target_id?: string | null
  device_target_id?: string | null
  target_name?: string | null
  target_url?: string | null
}
export function candidateTargetLabel(candidate: CandidateTargetFields): string
export interface CandidateGroup<T> { key: string; label: string; url: string | null; candidates: T[] }
export function groupCandidatesByTarget<T extends CandidateTargetFields>(candidates: ReadonlyArray<T>): CandidateGroup<T>[]
export function candidatePageRange(input: { offset: number; count: number; total: number }): string
