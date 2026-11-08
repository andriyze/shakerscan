export interface SessionCapabilities {
  default: 'allow' | 'deny'
  actions: Readonly<Record<string, boolean>>
  pages: Readonly<Record<string, boolean>>
  reasons: Readonly<Record<string, string>>
  role: string | null
}
export type SessionAction =
  | 'targets.add' | 'targets.edit' | 'targets.check' | 'scans.start'
  | 'findings.retest' | 'findings.verify' | 'findings.triage' | 'findings.accept_risk'
  | 'hunts.manage' | 'secrets.read' | 'secrets.manage' | 'secrets.decide' | 'records.delete'
export const SCHEMA_VERSION: 'session-capabilities/v1'
export const ALL_ALLOWED: SessionCapabilities
export function parseSessionCapabilities(body: unknown): SessionCapabilities
export function actionAllowed(capabilities: SessionCapabilities | null | undefined, action: SessionAction): boolean
export function pageAllowed(capabilities: SessionCapabilities | null | undefined, href: string): boolean
export function capabilityReason(capabilities: SessionCapabilities | null | undefined, key: string): string | undefined
export function fetchSessionCapabilities(url: string, fetchImpl?: typeof fetch, timeoutMs?: number): Promise<SessionCapabilities>
