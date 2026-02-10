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
  const [verifyAPIKeyInput, setVerifyAPIKeyInput] = useState('')
  const [clearScanAPIKey, setClearScanAPIKey] = useState(false)
  const [clearVerifyAPIKey, setClearVerifyAPIKey] = useState(false)
  const [persistAIToEnv, setPersistAIToEnv] = useState(false)
  const [aiURLInput, setAIURLInput] = useState('')
  const [aiModelInput, setAIModelInput] = useState('')
  const [aiModelFallbackInput, setAIModelFallbackInput] = useState('')
  const [aiMaskHostInput, setAIMaskHostInput] = useState('')
  const [aiScanClassificationEnabledInput, setAIScanClassificationEnabledInput] = useState(false)
  const [aiClassifyMinSeverityInput, setAIClassifyMinSeverityInput] = useState<Severity>('high')
  const [aiVerifyEnabledInput, setAIVerifyEnabledInput] = useState(false)
  const [aiVerifyURLInput, setAIVerifyURLInput] = useState('')
  const [aiVerifyModelInput, setAIVerifyModelInput] = useState('')
  const [aiVerifyModelFallbackInput, setAIVerifyModelFallbackInput] = useState('')
  const [aiVerifyMinSeverityInput, setAIVerifyMinSeverityInput] = useState<Severity>('high')
  const [autoRetestEnabledInput, setAutoRetestEnabledInput] = useState(true)
  const [autoRetestMinSeverityInput, setAutoRetestMinSeverityInput] = useState<Severity>('medium')
  const [autoRetestMaxPerScanInput, setAutoRetestMaxPerScanInput] = useState('25')
  const [verificationMinSeverityInput, setVerificationMinSeverityInput] = useState<Severity>('medium')
  const [aiEscalationMinSeverityInput, setAIEscalationMinSeverityInput] = useState<Severity>('high')
  const [proofRequiredForSmartInput, setProofRequiredForSmartInput] = useState(true)
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
    setAIVerifyURLInput(settings.ai_verify_url || '')
    setAIVerifyModelInput(settings.ai_verify_model || '')
    setAIVerifyModelFallbackInput(settings.ai_verify_model_fallback || '')
    setAIVerifyMinSeverityInput(settings.ai_verify_min_severity || 'high')
    setAutoRetestEnabledInput(Boolean(settings.auto_retest_on_scan_complete))
    setAutoRetestMinSeverityInput(settings.auto_retest_min_severity || 'medium')
    setAutoRetestMaxPerScanInput(String(settings.auto_retest_max_per_scan ?? 25))
    setVerificationMinSeverityInput(settings.verification_min_severity || settings.auto_retest_min_severity || 'medium')
    setAIEscalationMinSeverityInput(settings.ai_escalation_min_severity || settings.ai_verify_min_severity || 'high')
    setProofRequiredForSmartInput(settings.proof_required_for_smart !== false)
    setScanAPIKeyInput('')
    setVerifyAPIKeyInput('')
    setClearScanAPIKey(false)
    setClearVerifyAPIKey(false)
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
        ai_verify_url: aiVerifyURLInput,
        ai_verify_model: aiVerifyModelInput,
        ai_verify_model_fallback: aiVerifyModelFallbackInput,
        ai_verify_min_severity: aiVerifyMinSeverityInput,
        auto_retest_on_scan_complete: autoRetestEnabledInput,
        auto_retest_min_severity: autoRetestMinSeverityInput,
        auto_retest_max_per_scan: Math.max(0, Number.parseInt(autoRetestMaxPerScanInput || '0', 10) || 0),
        verification_min_severity: verificationMinSeverityInput,
        ai_escalation_min_severity: aiEscalationMinSeverityInput,
        proof_required_for_smart: proofRequiredForSmartInput,
        persist_to_env: persistAIToEnv,
      }

      if (clearScanAPIKey) {
        payload.ai_api_key = ''
      } else if (scanAPIKeyInput.trim()) {
        payload.ai_api_key = scanAPIKeyInput.trim()
      }

      if (clearVerifyAPIKey) {
        payload.ai_verify_api_key = ''
      } else if (verifyAPIKeyInput.trim()) {
        payload.ai_verify_api_key = verifyAPIKeyInput.trim()
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
        ai_url: scope === 'scan' ? aiURLInput || undefined : aiVerifyURLInput || undefined,
        ai_api_key: scope === 'scan' ? scanAPIKeyInput.trim() || undefined : verifyAPIKeyInput.trim() || undefined,
        ai_model: scope === 'scan' ? aiModelInput || undefined : aiVerifyModelInput || undefined,
        ai_fallback_model:
          scope === 'scan'
            ? aiModelFallbackInput || undefined
            : aiVerifyModelFallbackInput || undefined,
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
            Retest verification is authoritative. Scan-time AI classification is optional triage assistance.
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
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Shared key: {aiSettings.ai_api_key_configured ? 'configured' : 'not set'}
          </div>
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Retest key: {aiSettings.ai_verify_api_key_configured ? 'configured' : 'not set'}
          </div>
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Scan classification:{' '}
            {aiSettings.ai_scan_classification_enabled ? `on (${aiSettings.ai_classify_min_severity}+)` : 'off'}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <SectionCard
          title="Shared Provider"
          description="Default provider used for scan-time classification and as fallback for retest verification."
        >
          <Field label="AI URL">
            <input
              type="text"
              value={aiURLInput}
              onChange={(e) => setAIURLInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="https://api.openai.com/v1/chat/completions"
            />
          </Field>
          <Field label="AI Model">
            <input
              type="text"
              value={aiModelInput}
              onChange={(e) => setAIModelInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="gpt-4o-mini"
            />
          </Field>
          <Field label="Fallback Models (comma-separated)">
            <input
              type="text"
              value={aiModelFallbackInput}
              onChange={(e) => setAIModelFallbackInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="moonshotai/kimi-k2.5,openai/gpt-4o-mini"
            />
          </Field>
          <Field label="Mask Host">
            <input
              type="text"
              value={aiMaskHostInput}
              onChange={(e) => setAIMaskHostInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="example.com"
            />
          </Field>
          <Field label="AI API Key">
            <input
              type="password"
              value={scanAPIKeyInput}
              onChange={(e) => setScanAPIKeyInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder={aiSettings?.ai_api_key_configured ? 'Configured (enter to replace)' : 'sk-...'}
            />
          </Field>
          <label className="inline-flex items-center gap-2 text-xs text-gray-400">
            <input
              type="checkbox"
              checked={clearScanAPIKey}
              onChange={(e) => setClearScanAPIKey(e.target.checked)}
              className={CHECKBOX_CLASS}
            />
            Clear shared provider API key
          </label>
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
          description="Optional AI triage during scan reporting. Does not replace retest verification."
        >
          <label className="inline-flex items-center gap-2 text-xs text-gray-300">
            <input
              type="checkbox"
              checked={aiScanClassificationEnabledInput}
              onChange={(e) => setAIScanClassificationEnabledInput(e.target.checked)}
              className={CHECKBOX_CLASS}
            />
            Enable scan-time AI classification
          </label>
          <Field label="Scan Classification Min Severity">
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
          description="Used for retest AI decisions and exploit validation workflow."
        >
          <label className="inline-flex items-center gap-2 text-xs text-gray-300">
            <input
              type="checkbox"
              checked={aiVerifyEnabledInput}
              onChange={(e) => setAIVerifyEnabledInput(e.target.checked)}
              className={CHECKBOX_CLASS}
            />
            Enable AI verification for retests
          </label>
          <Field label="AI Verify URL">
            <input
              type="text"
              value={aiVerifyURLInput}
              onChange={(e) => setAIVerifyURLInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="Leave empty to use shared AI URL"
            />
          </Field>
          <Field label="AI Verify Model">
            <input
              type="text"
              value={aiVerifyModelInput}
              onChange={(e) => setAIVerifyModelInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="moonshotai/kimi-k2.5"
            />
          </Field>
          <Field label="Verify Fallback Models (comma-separated)">
            <input
              type="text"
              value={aiVerifyModelFallbackInput}
              onChange={(e) => setAIVerifyModelFallbackInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="openai/gpt-4o-mini,anthropic/claude-3-5-sonnet"
            />
          </Field>
          <Field label="Verification Min Severity">
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
          <Field label="AI Verify API Key">
            <input
              type="password"
              value={verifyAPIKeyInput}
              onChange={(e) => setVerifyAPIKeyInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder={aiSettings?.ai_verify_api_key_configured ? 'Configured (enter to replace)' : 'sk-...'}
            />
          </Field>
          <label className="inline-flex items-center gap-2 text-xs text-gray-400">
            <input
              type="checkbox"
              checked={clearVerifyAPIKey}
              onChange={(e) => setClearVerifyAPIKey(e.target.checked)}
              className={CHECKBOX_CLASS}
            />
            Clear retest AI API key
          </label>
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
          description="Controls proof-gated reporting and how strict chain-visible findings are."
        >
          <label className="inline-flex items-center gap-2 text-xs text-gray-300">
            <input
              type="checkbox"
              checked={proofRequiredForSmartInput}
              onChange={(e) => setProofRequiredForSmartInput(e.target.checked)}
              className={CHECKBOX_CLASS}
            />
            Proof required for smart scan reports (no exploit = no report)
          </label>
          <Field label="Verification Min Severity (scan-time + retest)">
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
          <Field label="AI Escalation Min Severity">
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
            If proof-required is enabled, smart scans may show fewer findings and fewer attack chains unless exploit
            evidence is collected.
          </p>
        </SectionCard>

        <SectionCard
          title="Auto Retest Policy"
          description="Automatically queue retests after scan completion."
        >
          <label className="inline-flex items-center gap-2 text-xs text-gray-300">
            <input
              type="checkbox"
              checked={autoRetestEnabledInput}
              onChange={(e) => setAutoRetestEnabledInput(e.target.checked)}
              className={CHECKBOX_CLASS}
            />
            Auto-queue retests after each scan
          </label>
          <Field label="Auto Retest Min Severity">
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
          <Field label="Auto Retest Max Findings Per Scan">
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

      <div className="pt-2 border-t border-gray-800">
        <label className="inline-flex items-center gap-2 text-xs text-gray-300">
          <input
            type="checkbox"
            checked={persistAIToEnv}
            onChange={(e) => setPersistAIToEnv(e.target.checked)}
            className={CHECKBOX_CLASS}
          />
          Persist changes to local <code>.env</code>
        </label>
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
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <label className="block">
      <span className="text-xs text-gray-400">{label}</span>
      {children}
    </label>
  )
}
