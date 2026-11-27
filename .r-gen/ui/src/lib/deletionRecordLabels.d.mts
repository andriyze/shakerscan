export interface DeletionRecordRow { key: string; label: string; count: number }
export function deletionRecordRows(records: unknown): { named: DeletionRecordRow[]; other: DeletionRecordRow[]; otherTotal: number }
