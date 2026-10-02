import { Card } from '@/components/ui'
import { devicePortCoverage } from '@/lib/networkScanCoverage.mjs'

type Coverage = NonNullable<ReturnType<typeof devicePortCoverage>>
const number = (value: number | null | undefined) => value == null ? '—' : value.toLocaleString()
function ExecutionStatus({ complete }: { complete: boolean }) {
  return <span className={complete ? 'text-emerald-300' : 'text-amber-200'}>{complete ? 'completed' : 'incomplete'}</span>
}

/** Tool execution and final observations are deliberately labelled as separate populations. */
export function DevicePortCoverage({ coverage }: { coverage: Coverage }) {
  const { tcp, udp, fingerprint, identification } = coverage
  const udpUncertain = udp?.noResponse != null && udp?.filtered != null ? udp.noResponse + udp.filtered : null
  return (
    <section className="mb-6" data-testid="device-port-coverage">
      <h2 className="mb-1 text-lg font-semibold text-white">Network examination</h2>
      <p className="mb-3 text-sm text-gray-500">Requested scope, completed execution, and confirmed services are different measures. Silence is not proof that a port is closed.</p>
      <Card className="overflow-hidden p-0">
        <div className="overflow-x-auto"><table className="w-full text-left text-sm">
          <thead className="bg-gray-900 text-xs uppercase text-gray-500"><tr>
            <th className="px-4 py-3">Scope / evidence source</th><th className="px-4 py-3">Examined</th><th className="px-4 py-3">Open</th><th className="px-4 py-3">Closed</th><th className="px-4 py-3">Filtered / no response</th><th className="px-4 py-3">Execution</th>
          </tr></thead>
          <tbody className="divide-y divide-gray-800 bg-gray-950/50">
            <tr>
              <td className="px-4 py-3 text-white">{tcp.scopeLabel}</td>
              <td className="px-4 py-3 text-gray-300">{tcp.examined != null ? number(tcp.examined) : tcp.examinedLowerBound > 0 ? <>{`≥ ${number(tcp.examinedLowerBound)}`}<span className="block text-xs text-gray-500">lower bound only</span></> : 'Not recorded'}</td>
              <td className="px-4 py-3 font-semibold text-emerald-300">{number(tcp.open)}</td>
              {tcp.classified ? <>
                <td className="px-4 py-3 text-gray-300">{number(tcp.closed)}</td>
                <td className="px-4 py-3 text-amber-200">{number(tcp.filtered)}</td>
              </> : <td colSpan={2} className="px-4 py-3 text-gray-400">{tcp.notOpen == null ? 'Not classified' : `${number(tcp.notOpen)} not confirmed open`}<span className="block text-xs text-gray-500">Closed and filtered were not distinguished.</span></td>}
              <td className="px-4 py-3 text-xs"><ExecutionStatus complete={tcp.complete} /></td>
            </tr>
            {udp && <tr>
              <td className="px-4 py-3 text-white">{udp.basis}</td>
              <td className="px-4 py-3 text-gray-300">{number(udp.examined)}</td>
              <td className="px-4 py-3 font-semibold text-emerald-300">{number(udp.open)}</td>
              <td className="px-4 py-3 text-gray-300">{number(udp.closed)}</td>
              <td className="px-4 py-3 text-amber-200">{number(udpUncertain)}{udp.other != null && udp.other > 0 && <span className="block text-xs">{number(udp.other)} other states</span>}</td>
              <td className="px-4 py-3 text-xs"><ExecutionStatus complete={udp.complete} /></td>
            </tr>}
          </tbody>
        </table></div>
        <div className="space-y-2 border-t border-gray-800 px-4 py-3 text-xs text-gray-400">
          <p>{tcp.note}</p>
          {udp && <p>UDP counts above belong only to the original Nmap stage. The final inventory contains <strong className="text-gray-200">{number(udp.confirmedOpen)} confirmed-open UDP services</strong>, including later protocol responses; these are not added to the earlier state counts.</p>}
          {fingerprint && <p>Nmap fingerprinting: {fingerprint.ports == null ? 'no port-state total recorded' : `port-state evidence returned for ${number(fingerprint.ports)} TCP ports (${number(fingerprint.open)} open at that stage)`}; <ExecutionStatus complete={fingerprint.complete} />{fingerprint.truncated != null && fingerprint.truncated > 0 ? `; ${number(fingerprint.truncated)} omitted by the fingerprint port cap` : ''}.</p>}
          <p>{identification.basis}: <strong className="text-gray-200">{number(identification.identified)} of {number(identification.total)} identified</strong>; {number(identification.withVersion)} with a version. This is not a count of successful Nmap fingerprints.</p>
          {(tcp.stages.length > 0 || (udp?.requestedPorts.length ?? 0) > 0) && <details className="pt-1">
            <summary className="cursor-pointer text-blue-300">Requested ports and TCP stage receipts</summary>
            {udp && udp.requestedPorts.length > 0 && <p className="mt-2 break-words">Requested UDP ports: <span className="font-mono">{udp.requestedPorts.join(', ')}</span></p>}
            {tcp.stages.length > 0 && <ul className="mt-2 space-y-1">{tcp.stages.map((stage) => <li key={stage.stage}>
              <span className="font-mono">{stage.stage}</span>{stage.portSpec ? ` · ${stage.portSpec}` : ''} · <ExecutionStatus complete={stage.complete} />{stage.attempt != null ? ` · attempt ${stage.attempt}` : ''}{stage.reasons.length > 0 ? ` · ${stage.reasons.join(', ')}` : ''}
            </li>)}</ul>}
          </details>}
        </div>
      </Card>
    </section>
  )
}
