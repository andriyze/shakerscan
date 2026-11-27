import assert from 'node:assert/strict'
import test from 'node:test'

import { detailUrlWithReturn } from './detailReturnUrl.ts'

const DEFAULTS = { sort_by: 'severity', sort_order: 'desc', page: 1 }

test('every filter in effect travels to the detail page; defaults and blanks do not', () => {
  const url = detailUrlWithReturn('/findings/f1', {
    sort_by: 'severity', sort_order: 'desc', page: 3,
    device_target_id: 'd1', research_campaign_id: 'c1', driven_by: 'autonomous_research',
    freshness: 'all', last_seen: 7, group: 'off', proof_state: 'verified', severity: 'critical,high', search: '',
  }, DEFAULTS)
  const params = new URL(url, 'http://x').searchParams
  assert.deepEqual(Object.fromEntries(params), {
    return_page: '3', return_device_target_id: 'd1', return_research_campaign_id: 'c1',
    return_driven_by: 'autonomous_research', return_freshness: 'all', return_last_seen: '7',
    return_group: 'off', return_proof_state: 'verified', return_severity: 'critical,high',
  })
})

test('an unfiltered list links to the bare detail page', () => {
  assert.equal(detailUrlWithReturn('/findings/f1', { ...DEFAULTS }, DEFAULTS), '/findings/f1')
})
