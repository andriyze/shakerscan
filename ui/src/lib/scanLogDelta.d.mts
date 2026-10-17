export interface ScanLogState { lines: string[]; nextSeq: number | null; partial: boolean }
export interface ScanLogReply {
  lines: string[]; seq_supported?: boolean; next_seq?: number | null;
  first_seq?: number | null; truncated?: boolean
}
export function emptyScanLogState(): ScanLogState
export function mergeScanLogReply(previous: ScanLogState, reply: ScanLogReply, limit?: number): ScanLogState
