export type ExpectedAccess = 'allow' | 'deny' | 'requires_role' | 'unknown'

export interface PrincipalExpectationDraft {
  method: string
  path: string
  principalId: string
  principalRole: string
  tenantId: string
  expectedAccess: ExpectedAccess
  expectedHttpStatus: string
}

export interface PrincipalExpectationPayload {
  method: string
  path: string
  principal_id?: string
  principal_role?: string
  tenant_id?: string
  expected_access: ExpectedAccess
  expected_http_status?: number
  expectation_source: 'manual'
}

export function emptyPrincipalExpectationDraft(): PrincipalExpectationDraft {
  return {
    method: 'GET',
    path: '',
    principalId: '',
    principalRole: '',
    tenantId: '',
    expectedAccess: 'deny',
    expectedHttpStatus: '',
  }
}

export function buildPrincipalExpectationPayload(draft: PrincipalExpectationDraft): PrincipalExpectationPayload {
  const payload: PrincipalExpectationPayload = {
    method: draft.method.trim().toUpperCase() || 'GET',
    path: draft.path.trim(),
    expected_access: draft.expectedAccess,
    expectation_source: 'manual',
  }
  const status = draft.expectedHttpStatus.trim()
  if (status) {
    const parsed = Number(status)
    if (!Number.isInteger(parsed) || parsed < 100 || parsed > 599) {
      throw new Error('Expected HTTP status must be an integer from 100 to 599')
    }
    payload.expected_http_status = parsed
  }
  if (draft.principalId.trim()) payload.principal_id = draft.principalId.trim()
  if (draft.principalRole.trim()) payload.principal_role = draft.principalRole.trim()
  if (draft.tenantId.trim()) payload.tenant_id = draft.tenantId.trim()
  return payload
}
