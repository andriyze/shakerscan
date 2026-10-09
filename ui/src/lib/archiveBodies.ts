/**
 * Whether an archive export left a call's body out. A masked export lists such a body under
 * `payload_omitted` (past its masking budget, over the masking size limit, or stored externally
 * past its read budget) and sends `null` for it, so an empty body is not "no body recorded".
 */
export const BODY_WITHHELD_LABEL = 'Body withheld from this export (size/budget limit)'

export interface ArchiveOmissions {
  payload_omitted?: string[] | null
}

export function bodyWithheld(transaction: ArchiveOmissions, side: 'request' | 'response'): boolean {
  return (transaction.payload_omitted || []).includes(`${side}_body`)
}
