export interface SharedServicePresenceInput {
  transport?: string
  port?: number
  state?: string | null
  presence?: string | null
  binding_status?: string
}
export function presenceOf(service: SharedServicePresenceInput | null | undefined): string
export function partitionSharedServices<T extends SharedServicePresenceInput>(services: T[] | null | undefined): {
  confirmed: T[]
  unconfirmed: T[]
  notObservedCount: number
}
export function sharedServiceHuntHref(service: SharedServicePresenceInput, targetId: string): string | null
export function summarizeEvidence(evidence: ReadonlyArray<{hunt_id?: string | null; scan_id?: string | null; status?: string}> | null | undefined, fallbackStatus?: string): Array<{label: string; count: number}>
