'use client'

import type { ReactNode } from 'react'
import Link from '@/components/WorkspaceLink'
import { Card, PageHeader } from '@/components/ui'
import { featureEnabled } from '@/lib/workspaceCapabilities'

// The server still ships the installed standalone documentation. Managed workspaces
// use their server-owned capability manifest, not a second hard-coded product edition.
export default function WorkspaceDocs({ children }: { children: ReactNode }) {
  const policy = typeof window === 'undefined' ? undefined : window.__SHAKERSCAN_CAPABILITIES__
  if (!policy) return children
  if (policy.schema !== 'shakerscan.workspace-capabilities/v1' || policy.mode !== 'managed') {
    return <p role="alert">Workspace documentation is unavailable until configuration is restored.</p>
  }
  const unavailable = Object.entries(policy.features)
    .filter(([, value]) => value.state === 'unavailable' || value.state === 'setup_required')
    .map(([key]) => key.replaceAll('_', ' '))

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PageHeader title="Workspace guide" description="Use your hosted workspace. No local Docker installation is required." />
      <Card className="space-y-4 p-6 text-gray-300">
        <h2 className="text-xl font-semibold text-white">Start with an approved target</h2>
        <p>Your platform administrator controls approved domains, testing permissions, subscription expiry and capacity. Adding a target does not grant permission to test another domain.</p>
        <ol className="list-decimal space-y-3 pl-5">
          <li>Open <Link href="/targets" className="text-blue-400 underline">Targets</Link> and add your application URL within an approved domain. If it is rejected, ask your platform administrator to review the domain policy.</li>
          <li>Open <Link href="/scan/new" className="text-blue-400 underline">New Scan</Link>, select the target and choose a coverage budget. Start with passive checks. Active checks require the administrator's testing permission and can affect the target application.</li>
          <li>Follow progress under <Link href="/scans" className="text-blue-400 underline">DAST Scans</Link>. Keep the scan ID if you need help. Refresh the existing run after a connection interruption rather than submitting it again.</li>
          <li>Review the conclusion, examination strength, coverage gaps and <Link href="/findings" className="text-blue-400 underline">Findings</Link>. A completed run or a high observed-risk score is not proof that the application is safe.</li>
        </ol>
      </Card>
      {(featureEnabled('credentials') || featureEnabled('collections')) && <Card className="space-y-3 p-6 text-gray-300">
        <h2 className="text-xl font-semibold text-white">Test authenticated workflows</h2>
        {featureEnabled('credentials') && <p>Store exact-target test credentials in <Link href="/credentials" className="text-blue-400 underline">Credentials</Link>, then select the saved profile in New Scan. Do not paste passwords or tokens into target URLs. A profile's configuration check is not proof that login to the target succeeded; inspect the scan's authentication outcome.</p>}
        {featureEnabled('collections') && <p>Use <Link href="/request-collections" className="text-blue-400 underline">Request Collections</Link> for supported imported workflows. Imports and selected requests do not expand approved domains or grant active-testing permission.</p>}
      </Card>}
      <Card className="space-y-3 p-6 text-gray-300">
        <h2 className="text-xl font-semibold text-white">Evidence and retesting</h2>
        <p>Open a finding to inspect its proof state and linked evidence. Analyst triage does not turn a suspected finding into verified proof. Retest is available only when that finding type has supported verification.</p>
        <p>The scan's request archive distinguishes recorded calls from total traffic. Partial capture stays partial. Prefer masked JSON; raw HAR can contain sensitive traffic and should be exported only deliberately.</p>
        <Link href="/evidence" className="text-blue-400 underline">Browse evidence</Link>
      </Card>
      <Card className="space-y-3 p-6 text-gray-300">
        <h2 className="text-xl font-semibold text-white">Workspace availability</h2>
        <p>Capacity, worker operations, infrastructure and retention administration are managed by the platform operator. Contact that administrator for limits, backups or operational problems; local scanner commands do not manage this tenant.</p>
        {unavailable.length > 0 && <p>Not available in this workspace: {unavailable.join(', ')}. These are not promised release dates or enabled features.</p>}
        <p>For support, provide the workspace address, operation ID and error message. Never include passwords, API tokens, raw traffic or unredacted evidence.</p>
      </Card>
    </div>
  )
}
