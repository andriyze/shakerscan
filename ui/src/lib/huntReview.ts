import { API_URL, getApiErrorMessage } from './apiConfig'
import { isReviewId } from './huntReviewModel'

export interface ReviewCandidate {
  id: string
  status: string
  authoritative: boolean
  created_from_attempt: number
}

export interface InvestigationReview {
  hunt_id: string
  proposal_id: string
  route: string
  explanation: string
  authorization_assessment?: string
  expected_access?: string
  expectation_source?: string
  candidate?: ReviewCandidate | null
  candidate_history?: ReviewCandidate[]
  candidate_relation?: string
  deferral_recorded: boolean
  selected_request_examined: boolean
  evidence_needed: string[]
  limitations: string[]
  resume?: { open_questions?: string[]; retained_candidate_ids?: string[] }
  attempts: Array<{
    attempt: number
    action_id: string
    receipt_id?: string | null
    transaction_ids?: string[]
    execution_status: string
    authorization_assessment?: string
    proof_state?: string
    reason: string
  }>
}

export interface ProposalPage {
  supported: boolean
  ids: string[]
  nextCursor: string | null
}

function runPath(huntId: string): string {
  if (!isReviewId(huntId)) throw new Error('Invalid Hunt reference')
  return `${API_URL}/hunts/${encodeURIComponent(huntId)}`
}

export async function listReviewProposals(huntId: string, cursor: string | null, signal?: AbortSignal): Promise<ProposalPage> {
  const response = await fetch(`${runPath(huntId)}/query`, {
    method: 'POST', signal, headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'graph_nodes', filter: { node_type: 'authorization_proposal', hunt_id: huntId }, limit: 20, cursor }),
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not read investigation history'))
  const page = await response.json()
  if (page.supported === false) return { supported: false, ids: [], nextCursor: null }
  if (page.hunt_id !== huntId || !Array.isArray(page.rows) || typeof page.has_more !== 'boolean') {
    throw new Error('Investigation history response is incomplete; it is not an empty history')
  }
  const ids = page.rows.map((row: { node_type?: string; attributes?: { hunt_id?: string; proposal_id?: string } }) => {
    if (row.node_type !== 'authorization_proposal' || row.attributes?.hunt_id !== huntId || !isReviewId(row.attributes?.proposal_id)) {
      throw new Error('An investigation reference is unavailable; refresh the API before reviewing it')
    }
    return row.attributes.proposal_id
  })
  if (page.has_more && (typeof page.next_cursor !== 'string' || !page.next_cursor || page.next_cursor === cursor)) {
    throw new Error('Investigation history is incomplete: continuation is unavailable')
  }
  return { supported: true, ids, nextCursor: page.has_more ? page.next_cursor : null }
}

export async function readInvestigation(huntId: string, proposalId: string, signal?: AbortSignal): Promise<InvestigationReview> {
  if (!isReviewId(proposalId)) throw new Error('Invalid investigation reference')
  const response = await fetch(`${runPath(huntId)}/authorization-investigations/${encodeURIComponent(proposalId)}`, { signal })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not read the saved investigation'))
  const result = await response.json()
  if (result.hunt_id !== huntId || result.proposal_id !== proposalId || !Array.isArray(result.attempts)) {
    throw new Error('Saved investigation does not match the requested references')
  }
  return result
}
