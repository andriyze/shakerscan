export declare const EXPORT_PAGE_SIZE: number
export declare const EXPORT_MAX_CALLS: number

export interface ArchiveExportPage {
  total?: number
  fidelity?: string
  fidelity_detail?: string
  capture_stats?: object
  transactions?: unknown[]
}

export declare function collectArchiveExport<T extends ArchiveExportPage>(
  fetchPage: (offset: number, limit: number) => Promise<T>,
  options?: { pageSize?: number; maxCalls?: number },
): Promise<T & { exported: number; total: number; truncated_export: boolean; export_cap?: number; transactions: unknown[] }>

export declare function exportCapNotice(total: number | null | undefined, maxCalls?: number): string | null

export declare function exportShortfallMessage(document: { exported?: number; total?: number; export_cap?: number } | null | undefined): string | null
