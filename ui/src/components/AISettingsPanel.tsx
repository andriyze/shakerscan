'use client'

import { useEffect, useState } from 'react'
import {
  getAISettings,
  testAISettings,
  updateAISettings,
  type AISettings,
  type AISettingsUpdate,
} from '@/lib/api'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

const SEVERITY_OPTIONS: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const INPUT_CLASS =
  'mt-1 w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500'
const CHECKBOX_CLASS =
  'h-4 w-4 rounded border-gray-700 bg-gray-800 text-blue-600 focus:ring-blue-500'

export default function AISettingsPanel() {
  const [aiSettings, setAISettings] = useState<AISettings | null>(null)
  const [aiSettingsError, setAISettingsError] = useState<string | null>(null)
  const [aiSettingsMessage, setAISettingsMessage] = useState<string | null>(null)
  const [aiSaving, setAISaving] = useState(false)
  const [loading, setLoading] = useState(true)
  const [scanAPIKeyInput, setScanAPIKeyInput] = useState('')
  const [clearScanAPIKey, setClearScanAPIKey] = useState(false)
  const [persistAIToEnv, setPersistAIToEnv] = useState(false)
  const [aiURLInput, setAIURLInput] = useState('')
  const [aiModelInput, setAIModelInput] = useState('')
  const [aiModelFallbackInput, setAIModelFallbackInput] = useState('')
  const [aiMaskHostInput, setAIMaskHostInput] = useState('')
  const [aiScanClassificationEnabledInput, setAIScanClassificationEnabledInput] = useState(false)
  const [aiClassifyMinSeverityInput, setAIClassifyMinSeverityInput] = useState<Severity>('high')
  const [aiVerifyEnabledInput, setAIVerifyEnabledInput] = useState(false)
  const [aiVerifyMinSeverityInput, setAIVerifyMinSeverityInput] = useState<Severity>('high')
  const [autoRetestEnabledInput, setAutoRetestEnabledInput] = useState(true)
  const [autoRetestMinSeverityInput, setAutoRetestMinSeverityInput] = useState<Severity>('medium')
  const [autoRetestMaxPerScanInput, setAutoRetestMaxPerScanInput] = useState('25')
  const [verificationMinSeverityInput, setVerificationMinSeverityInput] = useState<Severity>('medium')
  const [aiEscalationMinSeverityInput, setAIEscalationMinSeverityInput] = useState<Severity>('high')
  const [proofRequiredForSmartInput, setProofRequiredForSmartInput] = useState(false)
  const [demoModeEnabledInput, setDemoModeEnabledInput] = useState(false)
  const [demoHoneyPublicURLInput, setDemoHoneyPublicURLInput] = useState('https://honey.shakerscan.com')
  const [demoHoneyScannerURLInput, setDemoHoneyScannerURLInput] = useState('https://honey.shakerscan.com')
  const [settingsMode, setSettingsMode] = useState<'basic' | 'advanced'>('basic')
  const [testingScope, setTestingScope] = useState<'scan' | 'verify' | null>(null)
  const [scanProbeMessage, setScanProbeMessage] = useState<string | null>(null)
  const [verifyProbeMessage, setVerifyProbeMessage] = useState<string | null>(null)

  const applyAISettingsToForm = (settings: AISettings) => {
    setAIURLInput(settings.ai_url || '')
    setAIModelInput(settings.ai_model || '')
    setAIModelFallbackInput(settings.ai_model_fallback || '')
    setAIMaskHostInput(settings.ai_mask_host || '')
    setAIScanClassificationEnabledInput(Boolean(settings.ai_scan_classification_enabled))
    setAIClassifyMinSeverityInput(settings.ai_classify_min_severity || settings.ai_verify_min_severity || 'high')
    setAIVerifyEnabledInput(Boolean(settings.ai_verify_enabled))
    setAIVerifyMinSeverityInput(settings.ai_verify_min_severity || 'high')
    setAutoRetestEnabledInput(Boolean(settings.auto_retest_on_scan_complete))
    setAutoRetestMinSeverityInput(settings.auto_retest_min_severity || 'medium')
    setAutoRetestMaxPerScanInput(String(settings.auto_retest_max_per_scan ?? 25))
    setVerificationMinSeverityInput(settings.verification_min_severity || settings.auto_retest_min_severity || 'medium')
    setAIEscalationMinSeverityInput(settings.ai_escalation_min_severity || settings.ai_verify_min_severity || 'high')
    setProofRequiredForSmartInput(Boolean(settings.proof_required_for_smart))
    setDemoModeEnabledInput(Boolean(settings.demo_mode_enabled))
    setDemoHoneyPublicURLInput(settings.demo_honey_public_url || 'https://honey.shakerscan.com')
    setDemoHoneyScannerURLInput(settings.demo_honey_scanner_url || 'https://honey.shakerscan.com')
    setScanAPIKeyInput('')
    setClearScanAPIKey(false)
    setScanProbeMessage(null)
    setVerifyProbeMessage(null)
  }

  const fetchAISettings = async () => {
    try {
      const settings = await getAISettings()
      setAISettings(settings)
      setAISettingsError(null)
      applyAISettingsToForm(settings)
    } catch {
      setAISettingsError('AI settings unavailable')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAISettings()
  }, [])

  const handleSaveAISettings = async () => {
    if (aiSaving) return
    setAISettingsError(null)
    setAISettingsMessage(null)
    setAISaving(true)

    try {
      const payload: AISettingsUpdate = {
        ai_url: aiURLInput,
        ai_model: aiModelInput,
        ai_model_fallback: aiModelFallbackInput,
        ai_mask_host: aiMaskHostInput,
        ai_scan_classification_enabled: aiScanClassificationEnabledInput,
        ai_classify_min_severity: aiClassifyMinSeverityInput,
        ai_verify_enabled: aiVerifyEnabledInput,
        ai_verify_min_severity: aiVerifyMinSeverityInput,
        auto_retest_on_scan_complete: autoRetestEnabledInput,
        auto_retest_min_severity: autoRetestMinSeverityInput,
        auto_retest_max_per_scan: Math.max(0, Number.parseInt(autoRetestMaxPerScanInput || '0', 10) || 0),
        verification_min_severity: verificationMinSeverityInput,
        ai_escalation_min_severity: aiEscalationMinSeverityInput,
        proof_required_for_smart: proofRequiredForSmartInput,
        demo_mode_enabled: demoModeEnabledInput,
        demo_honey_public_url: demoHoneyPublicURLInput,
        demo_honey_scanner_url: demoHoneyScannerURLInput,
        persist_to_env: persistAIToEnv,
      }

      if (clearScanAPIKey) {
        payload.ai_api_key = ''
      } else if (scanAPIKeyInput.trim()) {
        payload.ai_api_key = scanAPIKeyInput.trim()
      }

      const result = await updateAISettings(payload)
      setAISettings(result.settings)
      applyAISettingsToForm(result.settings)
      setAISettingsMessage(
        result.persisted_to_env
          ? result.persist_message || 'AI settings updated and persisted to .env'
          : 'AI runtime settings updated'
      )
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to update AI settings'
      setAISettingsError(message)
    } finally {
      setAISaving(false)
    }
  }

  const handleTestAISettings = async (scope: 'scan' | 'verify') => {
    if (aiSaving || testingScope) return
    setAISettingsError(null)
    if (scope === 'scan') {
      setScanProbeMessage(null)
    } else {
      setVerifyProbeMessage(null)
    }
    setTestingScope(scope)

    try {
      const result = await testAISettings({
        scope,
        ai_url: aiURLInput || undefined,
        ai_api_key: scanAPIKeyInput.trim() || undefined,
        ai_model: aiModelInput || undefined,
        ai_fallback_model: aiModelFallbackInput || undefined,
      })

      const usedModel = String(result.probe?.provider_meta?.model_used || '').trim()
      const latency = result.probe?.latency_ms
      const detail = usedModel ? `model ${usedModel}` : 'provider responded'
      const latencyLabel = typeof latency === 'number' ? ` in ${latency}ms` : ''
      const message =
        result.status === 'ok'
          ? `Probe succeeded (${detail}${latencyLabel}).`
          : `Probe failed: ${result.probe?.error || 'unknown error'}`

      if (scope === 'scan') {
        setScanProbeMessage(message)
      } else {
        setVerifyProbeMessage(message)
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to test AI settings'
      if (scope === 'scan') {
        setScanProbeMessage(`Probe failed: ${message}`)
      } else {
        setVerifyProbeMessage(`Probe failed: ${message}`)
      }
      setAISettingsError(message)
    } finally {
      setTestingScope(null)
    }
  }

  const setUnifiedVerificationSeverity = (severity: Severity) => {
    setAIVerifyMinSeverityInput(severity)
    setVerificationMinSeverityInput(severity)
    setAIEscalationMinSeverityInput(severity)
    setAutoRetestMinSeverityInput(severity)
  }

  if (loading && !aiSettings) {
    return (
      <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-sm text-gray-400">
        Loading AI settings...
      </div>
    )
  }

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium text-gray-200">AI & Verification Settings</h2>
          <p className="text-xs text-gray-500 mt-1">
            Configure scan-time triage, authoritative retest verification, and smart-scan reporting behavior.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchAISettings}
            disabled={loading || aiSaving}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white rounded text-sm"
          >
            Refresh
          </button>
          <button
            onClick={handleSaveAISettings}
            disabled={aiSaving || loading}
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded text-sm"
          >
            {aiSaving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>

      {aiSettings && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-xs">
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Shared key: {aiSettings.ai_api_key_configured ? 'configured' : 'not set'}
          </div>
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            AI retest: {aiSettings.ai_verify_enabled ? 'enabled' : 'disabled'}
          </div>
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Scan classification:{' '}
            {aiSettings.ai_scan_classification_enabled ? `on (${aiSettings.ai_classify_min_severity}+)` : 'off'}
          </div>
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Smart proof filter: {aiSettings.proof_required_for_smart ? 'on' : 'off'}
          </div>
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Demo mode: {aiSettings.demo_mode_enabled ? 'enabled' : 'disabled'}
          </div>
        </div>
      )}

      <SectionCard
        title="Demo & Calibration"
        description="Controls whether Honey demo actions appear in AI Gate. Keep off for production-facing use."
      >
        <ToggleRow
          label="Enable Honey AI demo controls"
          description="Shows a demo run button on the AI Gate page and allows the demo API to queue hidden Honey targets."
          hint="Demo targets are excluded from the normal AI target list by default."
          checked={demoModeEnabledInput}
          onChange={setDemoModeEnabledInput}
        />
        <div className="grid gap-3 md:grid-cols-2">
          <Field
            label="Honey public URL"
            hint="Browser-facing Honey URL shown in links and labels."
          >
            <input
              type="url"
              value={demoHoneyPublicURLInput}
              onChange={(e) => setDemoHoneyPublicURLInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="https://honey.shakerscan.com"
            />
          </Field>
          <Field
            label="Honey scanner URL"
            hint="URL that API/workers can reach. For local Honey from Docker, use http://host.docker.internal:18080."
          >
            <input
              type="url"
              value={demoHoneyScannerURLInput}
              onChange={(e) => setDemoHoneyScannerURLInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="http://host.docker.internal:18080"
            />
          </Field>
        </div>
      </SectionCard>

      <div className="inline-flex items-center gap-1 rounded-lg border border-gray-700 bg-gray-800 p-1">
        <button
          onClick={() => setSettingsMode('basic')}
          className={`px-2.5 py-1 text-xs rounded ${
            settingsMode === 'basic' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-gray-700'
          }`}
          aria-pressed={settingsMode === 'basic'}
        >
          Basic
        </button>
        <button
          onClick={() => setSettingsMode('advanced')}
          className={`px-2.5 py-1 text-xs rounded ${
            settingsMode === 'advanced' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-gray-700'
          }`}
          aria-pressed={settingsMode === 'advanced'}
        >
          Advanced
        </button>
      </div>

      <div className="rounded border border-blue-500/30 bg-blue-500/10 px-3 py-2">
        <p className="text-xs font-medium text-blue-200">Pipeline flow</p>
        <p className="text-xs text-blue-100/90 mt-1">
          Scanner tools run first. Optional scan-time AI helps with triage. Retests run deterministic proofs first, then
          optional AI escalation for hard cases.
        </p>
      </div>

      {settingsMode === 'basic' ? (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <SectionCard
            title="Quick Setup"
            description="Recommended defaults for most teams: configure one key, enable retest AI, set severity threshold."
          >
            <Field
              label="AI API Key"
              hint="Primary key used for AI provider access. Advanced mode supports separate retest key/provider."
            >
              <input
                type="password"
                value={scanAPIKeyInput}
                onChange={(e) => setScanAPIKeyInput(e.target.value)}
                className={INPUT_CLASS}
                placeholder={aiSettings?.ai_api_key_configured ? 'Configured (enter to replace)' : 'sk-...'}
              />
            </Field>
            <ToggleRow
              label="Enable AI verification for retests"
              description="Uses AI only when deterministic retest cannot confidently conclude."
              hint="Deterministic proof checks still run first."
              checked={aiVerifyEnabledInput}
              onChange={setAIVerifyEnabledInput}
            />
            <Field
              label="Minimum Severity for AI Verification"
              hint="Findings below this severity are not escalated to AI retest."
            >
              <select
                value={aiVerifyMinSeverityInput}
                onChange={(e) => setUnifiedVerificationSeverity(e.target.value as Severity)}
                className={INPUT_CLASS}
              >
                {SEVERITY_OPTIONS.map((sev) => (
                  <option key={sev} value={sev}>
                    {sev}
                  </option>
                ))}
              </select>
            </Field>
            <p className="text-xs text-gray-500">
              Need provider/model overrides, proof-gated smart mode, scan-time AI classification, or auto-retest tuning?
              Switch to <span className="text-gray-300">Advanced</span>.
            </p>
            <div className="flex items-center gap-2 pt-1">
              <button
                onClick={() => handleTestAISettings('verify')}
                disabled={loading || aiSaving || testingScope !== null}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white rounded text-xs"
              >
                {testingScope === 'verify' ? 'Testing retest AI...' : 'Test AI Verification'}
              </button>
              {verifyProbeMessage && (
                <span className={`text-xs ${verifyProbeMessage.startsWith('Probe succeeded') ? 'text-green-400' : 'text-red-400'}`}>
                  {verifyProbeMessage}
                </span>
              )}
            </div>
          </SectionCard>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <SectionCard
          title="Shared Provider"
          description="Default provider used for scan-time classification and as fallback for retest verification."
        >
          <Field
            label="AI URL"
            hint="OpenAI-compatible endpoint used for scan-time AI, and as fallback for retest AI if verify URL is empty."
          >
            <input
              type="text"
              value={aiURLInput}
              onChange={(e) => setAIURLInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="https://api.openai.com/v1/chat/completions"
            />
          </Field>
          <Field label="AI Model" hint="Primary model for scan-time AI calls.">
            <input
              type="text"
              value={aiModelInput}
              onChange={(e) => setAIModelInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="gpt-4o-mini"
            />
          </Field>
          <Field
            label="Fallback Models (comma-separated)"
            hint="Tried in order when the primary model fails or returns incompatible output."
          >
            <input
              type="text"
              value={aiModelFallbackInput}
              onChange={(e) => setAIModelFallbackInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="moonshotai/kimi-k2.5,openai/gpt-4o-mini"
            />
          </Field>
          <Field
            label="Mask Host"
            hint="Host used to redact sensitive domains/URLs in prompts sent to AI providers."
          >
            <input
              type="text"
              value={aiMaskHostInput}
              onChange={(e) => setAIMaskHostInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="example.com"
            />
          </Field>
          <Field label="AI API Key" hint="Shared provider key used unless a dedicated retest key is configured.">
            <input
              type="password"
              value={scanAPIKeyInput}
              onChange={(e) => setScanAPIKeyInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder={aiSettings?.ai_api_key_configured ? 'Configured (enter to replace)' : 'sk-...'}
            />
          </Field>
          <ToggleRow
            label="Clear shared provider API key"
            description="Removes the currently stored shared key when you click Save."
            hint="Only applies on save."
            checked={clearScanAPIKey}
            onChange={setClearScanAPIKey}
          />
          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={() => handleTestAISettings('scan')}
              disabled={loading || aiSaving || testingScope !== null}
              className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white rounded text-xs"
            >
              {testingScope === 'scan' ? 'Testing provider...' : 'Test Shared Provider'}
            </button>
            {scanProbeMessage && (
              <span className={`text-xs ${scanProbeMessage.startsWith('Probe succeeded') ? 'text-green-400' : 'text-red-400'}`}>
                {scanProbeMessage}
              </span>
            )}
          </div>
        </SectionCard>

        <SectionCard
          title="Scan-Time Classification"
          description="Optional AI triage during report generation. This does not replace retest verification."
        >
          <ToggleRow
            label="Enable scan-time AI classification"
            description="Uses AI during scan result processing to help classify findings."
            hint="When off, scan findings rely only on scanner/tool logic."
            checked={aiScanClassificationEnabledInput}
            onChange={setAIScanClassificationEnabledInput}
          />
          <Field
            label="Scan Classification Min Severity"
            hint="Only findings at or above this severity are sent to scan-time AI classification."
          >
            <select
              value={aiClassifyMinSeverityInput}
              onChange={(e) => setAIClassifyMinSeverityInput(e.target.value as Severity)}
              disabled={!aiScanClassificationEnabledInput}
              className={`${INPUT_CLASS} disabled:opacity-50`}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          </Field>
          <p className="text-xs text-gray-500">
            Recommendation: keep this at <code>medium</code> or higher for lower noise.
          </p>
        </SectionCard>

        <SectionCard
          title="Retest Verification (Authoritative)"
          description="AI settings used for post-scan retest verification and exploit validation."
        >
          <ToggleRow
            label="Enable AI verification for retests"
            description="Allows AI escalation when deterministic retest cannot confidently conclude."
            hint="Deterministic checks still run first."
            checked={aiVerifyEnabledInput}
            onChange={setAIVerifyEnabledInput}
          />
          <p className="text-xs text-gray-500">
            Retest AI uses the shared provider settings from <span className="text-gray-300">Shared Provider</span>.
          </p>
          <Field
            label="Verification Min Severity"
            hint="Only retest findings at or above this severity can be escalated to AI."
          >
            <select
              value={aiVerifyMinSeverityInput}
              onChange={(e) => setAIVerifyMinSeverityInput(e.target.value as Severity)}
              className={INPUT_CLASS}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          </Field>
          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={() => handleTestAISettings('verify')}
              disabled={loading || aiSaving || testingScope !== null}
              className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white rounded text-xs"
            >
              {testingScope === 'verify' ? 'Testing retest AI...' : 'Test Retest AI'}
            </button>
            {verifyProbeMessage && (
              <span className={`text-xs ${verifyProbeMessage.startsWith('Probe succeeded') ? 'text-green-400' : 'text-red-400'}`}>
                {verifyProbeMessage}
              </span>
            )}
          </div>
        </SectionCard>

        <SectionCard
          title="Verification Policy"
          description="Controls proof-gating and escalation thresholds used by smart scan and retest workflows."
        >
          <ToggleRow
            label="Proof required for smart scan reports"
            description="When on, only findings with verification evidence are kept in primary smart-scan output."
            hint="Can reduce visible findings and attack chains when proof collection fails."
            checked={proofRequiredForSmartInput}
            onChange={setProofRequiredForSmartInput}
          />
          <Field
            label="Verification Min Severity (scan-time + retest)"
            hint="Baseline minimum severity for verification workflows across scan-time checks and retests."
          >
            <select
              value={verificationMinSeverityInput}
              onChange={(e) => setVerificationMinSeverityInput(e.target.value as Severity)}
              className={INPUT_CLASS}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          </Field>
          <Field
            label="AI Escalation Min Severity"
            hint="Minimum severity required before deterministic retest can escalate to AI."
          >
            <select
              value={aiEscalationMinSeverityInput}
              onChange={(e) => setAIEscalationMinSeverityInput(e.target.value as Severity)}
              className={INPUT_CLASS}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          </Field>
          <p className="text-xs text-yellow-400/90 bg-yellow-500/10 border border-yellow-500/20 rounded px-2 py-1.5">
            If proof-required is enabled, smart scans can look quieter because unverified findings are filtered out of
            the primary report.
          </p>
        </SectionCard>

        <SectionCard
          title="Auto Retest Policy"
          description="Queues retests automatically after scan completion."
        >
          <ToggleRow
            label="Auto-queue retests after each scan"
            description="Creates retest jobs for eligible findings when a scan completes."
            hint="Useful for continuous validation with less manual work."
            checked={autoRetestEnabledInput}
            onChange={setAutoRetestEnabledInput}
          />
          <Field
            label="Auto Retest Min Severity"
            hint="Only findings at or above this severity are auto-queued for retest."
          >
            <select
              value={autoRetestMinSeverityInput}
              onChange={(e) => setAutoRetestMinSeverityInput(e.target.value as Severity)}
              className={INPUT_CLASS}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          </Field>
          <Field
            label="Auto Retest Max Findings Per Scan"
            hint="Hard cap on number of findings auto-queued for retest from one scan."
          >
            <input
              type="number"
              min={0}
              max={500}
              value={autoRetestMaxPerScanInput}
              onChange={(e) => setAutoRetestMaxPerScanInput(e.target.value)}
              className={INPUT_CLASS}
            />
          </Field>
        </SectionCard>
        </div>
      )}

      <div className="pt-2 border-t border-gray-800">
        <ToggleRow
          label="Persist changes to local .env"
          description="When on, saved settings survive container restarts. When off, changes are runtime-only."
          hint="Use runtime-only for temporary experiments."
          checked={persistAIToEnv}
          onChange={setPersistAIToEnv}
        />
      </div>

      {aiSettingsMessage && <p className="text-xs text-green-400">{aiSettingsMessage}</p>}
      {aiSettingsError && <p className="text-xs text-red-400">{aiSettingsError}</p>}
    </div>
  )
}

function SectionCard({
  title,
  description,
  children,
}: {
  title: string
  description: string
  children: React.ReactNode
}) {
  return (
    <section className="bg-gray-950/60 border border-gray-800 rounded-lg p-3 space-y-2">
      <div>
        <h3 className="text-xs font-medium text-gray-200 uppercase tracking-wide">{title}</h3>
        <p className="text-xs text-gray-500 mt-1">{description}</p>
      </div>
      {children}
    </section>
  )
}

function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <label className="block">
      <span className="text-xs text-gray-400 inline-flex items-center gap-1">
        {label}
        {hint && <HelpHint text={hint} />}
      </span>
      {children}
    </label>
  )
}

function ToggleRow({
  label,
  description,
  hint,
  checked,
  onChange,
}: {
  label: string
  description: string
  hint?: string
  checked: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <label className="flex items-start gap-2 rounded border border-gray-800 bg-gray-900/50 px-2.5 py-2">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className={`${CHECKBOX_CLASS} mt-0.5`}
      />
      <span className="space-y-0.5">
        <span className="text-xs text-gray-200 inline-flex items-center gap-1">
          {label}
          {hint && <HelpHint text={hint} />}
        </span>
        <span className="block text-[11px] text-gray-500">{description}</span>
      </span>
    </label>
  )
}

function HelpHint({ text }: { text: string }) {
  return (
    <span
      className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-gray-600 text-[10px] font-semibold text-gray-300 cursor-help"
      title={text}
      aria-label={text}
    >
      ?
    </span>
  )
}
