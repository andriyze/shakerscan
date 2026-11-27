export interface ArchiveOmissions {
  payload_omitted?: string[] | null
  payload_omitted_reasons?: Record<string, string> | null
}

export const BODY_WITHHELD_LABEL: string
export const BODY_UNMASKABLE_LABEL: string
export function bodyWithheldLabel(transaction: ArchiveOmissions, side: 'request' | 'response'): string | null
