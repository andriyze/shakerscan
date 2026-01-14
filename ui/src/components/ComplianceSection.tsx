'use client'

type ComplianceData = {
  owasp_top10?: string[]
  cwe_ids?: string[]
  pci_dss?: string[]
  gdpr?: string[]
  hipaa?: string[]
  soc2?: string[]
}

type Props = {
  compliance: ComplianceData
}

export default function ComplianceSection({ compliance }: Props) {
  if (!compliance) return null

  const hasData = Object.values(compliance).some(arr => arr && arr.length > 0)
  if (!hasData) return null

  return (
    <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
      <h2 className="text-2xl font-bold mb-4">Compliance Framework Mapping</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {compliance.owasp_top10 && compliance.owasp_top10.length > 0 && (
          <div className="bg-gray-900 rounded-lg p-4">
            <h3 className="text-sm font-medium text-orange-400 mb-3">OWASP Top 10</h3>
            <div className="flex flex-wrap gap-2">
              {compliance.owasp_top10.map((item, i) => (
                <span key={i} className="px-2 py-1 bg-orange-900/30 text-orange-300 text-xs rounded">
                  {item}
                </span>
              ))}
            </div>
          </div>
        )}

        {compliance.cwe_ids && compliance.cwe_ids.length > 0 && (
          <div className="bg-gray-900 rounded-lg p-4">
            <h3 className="text-sm font-medium text-blue-400 mb-3">CWE IDs</h3>
            <div className="flex flex-wrap gap-2">
              {compliance.cwe_ids.map((item, i) => (
                <a
                  key={i}
                  href={`https://cwe.mitre.org/data/definitions/${item.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-2 py-1 bg-blue-900/30 text-blue-300 text-xs rounded hover:bg-blue-900/50"
                >
                  {item}
                </a>
              ))}
            </div>
          </div>
        )}

        {compliance.pci_dss && compliance.pci_dss.length > 0 && (
          <div className="bg-gray-900 rounded-lg p-4">
            <h3 className="text-sm font-medium text-purple-400 mb-3">PCI DSS</h3>
            <div className="flex flex-wrap gap-2">
              {compliance.pci_dss.map((item, i) => (
                <span key={i} className="px-2 py-1 bg-purple-900/30 text-purple-300 text-xs rounded">
                  {item}
                </span>
              ))}
            </div>
          </div>
        )}

        {compliance.gdpr && compliance.gdpr.length > 0 && (
          <div className="bg-gray-900 rounded-lg p-4">
            <h3 className="text-sm font-medium text-green-400 mb-3">GDPR</h3>
            <div className="flex flex-wrap gap-2">
              {compliance.gdpr.map((item, i) => (
                <span key={i} className="px-2 py-1 bg-green-900/30 text-green-300 text-xs rounded">
                  {item}
                </span>
              ))}
            </div>
          </div>
        )}

        {compliance.hipaa && compliance.hipaa.length > 0 && (
          <div className="bg-gray-900 rounded-lg p-4">
            <h3 className="text-sm font-medium text-red-400 mb-3">HIPAA</h3>
            <div className="flex flex-wrap gap-2">
              {compliance.hipaa.map((item, i) => (
                <span key={i} className="px-2 py-1 bg-red-900/30 text-red-300 text-xs rounded">
                  {item}
                </span>
              ))}
            </div>
          </div>
        )}

        {compliance.soc2 && compliance.soc2.length > 0 && (
          <div className="bg-gray-900 rounded-lg p-4">
            <h3 className="text-sm font-medium text-yellow-400 mb-3">SOC 2</h3>
            <div className="flex flex-wrap gap-2">
              {compliance.soc2.map((item, i) => (
                <span key={i} className="px-2 py-1 bg-yellow-900/30 text-yellow-300 text-xs rounded">
                  {item}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
