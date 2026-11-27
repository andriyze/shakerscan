// How the ASM page names the scan that is already active on a target. Only an ASM batch/recon
// scan is hidden from the Scans list; an ordinary DAST scan must not be labelled as one (E1-N4).

export type AsmActiveScanKind = 'asm' | 'scan'

export interface AsmActiveScanBlocker {
  kind: string
  scan_id?: string
  scan_kind?: AsmActiveScanKind | string
  hidden_from_scans_list?: boolean
}

export function activeScanNote(blocker: AsmActiveScanBlocker): string | null {
  return blocker.hidden_from_scans_list === true ? 'ASM batch/recon — hidden from the Scans list' : null
}

export function activeScanLinkLabel(kind: AsmActiveScanKind | string | null | undefined): string {
  return kind === 'asm' ? 'View active ASM scan' : 'View active scan'
}
