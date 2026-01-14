'use client'

type RemediationStatus = 'open' | 'in_progress' | 'remediated' | 'false_positive' | 'accepted_risk'

type RemediationData = {
  finding_id: string
  status: RemediationStatus
  notes?: string
}

type Props = {
  remediations: RemediationData[]
  totalFindings: number
}

export default function RemediationSummary({ remediations, totalFindings }: Props) {
  const stats = {
    open: remediations.filter(r => r.status === 'open').length,
    in_progress: remediations.filter(r => r.status === 'in_progress').length,
    remediated: remediations.filter(r => r.status === 'remediated').length,
    false_positive: remediations.filter(r => r.status === 'false_positive').length,
    accepted_risk: remediations.filter(r => r.status === 'accepted_risk').length
  }

  const trackedCount = remediations.length
  const untrackedCount = totalFindings - trackedCount
  const resolvedCount = stats.remediated + stats.false_positive + stats.accepted_risk
  const progressPercent = totalFindings > 0 ? Math.round((resolvedCount / totalFindings) * 100) : 0

  return (
    <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold">Remediation Progress</h2>
        <span className="text-2xl font-bold text-blue-400">{progressPercent}%</span>
      </div>

      <div className="w-full bg-gray-700 rounded-full h-3 mb-6">
        <div
          className="bg-gradient-to-r from-blue-500 to-green-500 h-3 rounded-full transition-all duration-500"
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-xs mb-1">Open</p>
          <p className="text-xl font-semibold text-red-400">{stats.open + untrackedCount}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-xs mb-1">In Progress</p>
          <p className="text-xl font-semibold text-yellow-400">{stats.in_progress}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-xs mb-1">Remediated</p>
          <p className="text-xl font-semibold text-green-400">{stats.remediated}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-xs mb-1">False Positive</p>
          <p className="text-xl font-semibold text-blue-400">{stats.false_positive}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-xs mb-1">Accepted Risk</p>
          <p className="text-xl font-semibold text-purple-400">{stats.accepted_risk}</p>
        </div>
      </div>
    </div>
  )
}
