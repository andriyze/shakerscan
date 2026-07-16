import AISettingsPanel from '@/components/AISettingsPanel'
import ScanExecutionSettingsPanel from '@/components/ScanExecutionSettingsPanel'
import Link from 'next/link'
import { Boxes, BrainCircuit, ShieldCheck, Wand2 } from 'lucide-react'

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-gray-400 mt-1">
          Runtime configuration for scan execution, scan-time AI triage, retest verification, and smart-scan output policy. Hover the
          <span className="mx-1 inline-flex h-4 w-4 items-center justify-center rounded-full border border-gray-600 text-[10px] font-semibold text-gray-300">?</span>
          icons for quick explanations.
        </p>
      </div>

      <ScanExecutionSettingsPanel />

      <Link
        href="/settings/policy-profiles"
        className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-900 p-4 hover:bg-gray-800/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950"
      >
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-600/20 text-indigo-300">
            <ShieldCheck className="h-5 w-5" />
          </span>
          <div>
            <h2 className="text-sm font-medium text-white">Policy Profiles</h2>
            <p className="mt-1 text-sm text-gray-400">Deployment gates, exception policy, and strict Model Intake profiles</p>
          </div>
        </div>
        <span className="text-sm text-indigo-300">Open</span>
      </Link>

      <Link
        href="/settings/arsenal"
        className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-900 p-4 hover:bg-gray-800/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950"
      >
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-600/20 text-teal-300">
            <Boxes className="h-5 w-5" />
          </span>
          <div>
            <h2 className="text-sm font-medium text-white">Command Arsenal</h2>
            <p className="mt-1 text-sm text-gray-400">Read-only command schemas and integrated tool status</p>
          </div>
        </div>
        <span className="text-sm text-teal-300">Open</span>
      </Link>

      <Link
        href="/settings/research-agent"
        className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-900 p-4 hover:bg-gray-800/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950"
      >
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-600/20 text-cyan-300">
            <BrainCircuit className="h-5 w-5" />
          </span>
          <div>
            <h2 className="text-sm font-medium text-white">Research Agent</h2>
            <p className="mt-1 text-sm text-gray-400">Bounded one-step planning over registered scanner actions</p>
          </div>
        </div>
        <span className="text-sm text-cyan-300">Open</span>
      </Link>

      <Link
        href="/settings/ai-ops-router"
        className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-900 p-4 hover:bg-gray-800/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950"
      >
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-purple-600/20 text-purple-300">
            <Wand2 className="h-5 w-5" />
          </span>
          <div>
            <h2 className="text-sm font-medium text-white">AI Operations Router</h2>
            <p className="mt-1 text-sm text-gray-400">Translate natural-language requests into safe, explicit API plans</p>
          </div>
        </div>
        <span className="text-sm text-purple-300">Open</span>
      </Link>

      <AISettingsPanel />
    </div>
  )
}
