'use client'

import {
  FindingStatusBadge,
  Modal,
  ProofStateBadge,
  RetestVerdictBadge,
  SeverityBadge,
} from '@/components/ui'

// Severity / Proof / Retest / Status answer four different questions; spell them out so
// newcomers don't conflate them, and say when a row leaves one out.
export function BadgeLegendModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Modal open={open} title="What the badges mean" onClose={onClose} size="lg">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex items-start gap-3">
          <SeverityBadge severity="high" />
          <p className="text-xs leading-5 text-gray-400"><span className="font-medium text-gray-200">Severity</span> — how serious it would be if real, from Critical down to Info.</p>
        </div>
        <div className="flex items-start gap-3">
          <div className="shrink-0"><ProofStateBadge proofState="verified" /></div>
          <p className="text-xs leading-5 text-gray-400"><span className="font-medium text-gray-200">Proof</span> — how sure ShakerScan is it is real: <span className="text-gray-200">Proven</span> (evidence captured), <span className="text-gray-200">Suspected</span> (a lead, not confirmed), Refuted, or Inconclusive.</p>
        </div>
        <div className="flex items-start gap-3">
          <div className="shrink-0"><RetestVerdictBadge verdict="likely_vulnerable" /></div>
          <p className="text-xs leading-5 text-gray-400"><span className="font-medium text-gray-200">Retest</span> — what the most recent automated re-check found. Rows show it only when it adds something: an open finding a retest could not reproduce, a closed one it still reproduces, or a re-check that could not decide.</p>
        </div>
        <div className="flex items-start gap-3">
          <FindingStatusBadge status="active" />
          <p className="text-xs leading-5 text-gray-400"><span className="font-medium text-gray-200">Status</span> — your triage decision: open (active), resolved, false positive, or accepted risk. Rows show it in the All view; the other views are one status each.</p>
        </div>
      </div>
    </Modal>
  )
}
