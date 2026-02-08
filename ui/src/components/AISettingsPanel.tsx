'use client'

import { useEffect, useState } from 'react'
import {
  getAISettings,
  updateAISettings,
  type AISettings,
  type AISettingsUpdate,
} from '@/lib/api'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

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
  const [aiMaskHostInput, setAIMaskHostInput] = useState('')
  const [aiVerifyEnabledInput, setAIVerifyEnabledInput] = useState(false)
  const [aiVerifyURLInput, setAIVerifyURLInput] = useState('')
  const [aiVerifyModelInput, setAIVerifyModelInput] = useState('')
  const [aiVerifyMinSeverityInput, setAIVerifyMinSeverityInput] = useState<Severity>('high')

  const applyAISettingsToForm = (settings: AISettings) => {
    setAIURLInput(settings.ai_url || '')
    setAIModelInput(settings.ai_model || '')
    setAIMaskHostInput(settings.ai_mask_host || '')
    setAIVerifyEnabledInput(Boolean(settings.ai_verify_enabled))
    setAIVerifyURLInput(settings.ai_verify_url || '')
    setAIVerifyModelInput(settings.ai_verify_model || '')
    setAIVerifyMinSeverityInput(settings.ai_verify_min_severity || 'high')
    setScanAPIKeyInput('')
    setVerifyAPIKeyInput('')
    setClearScanAPIKey(false)
    setClearVerifyAPIKey(false)
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
        ai_mask_host: aiMaskHostInput,
        ai_verify_enabled: aiVerifyEnabledInput,
        ai_verify_url: aiVerifyURLInput,
        ai_verify_model: aiVerifyModelInput,
        ai_verify_min_severity: aiVerifyMinSeverityInput,
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

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-medium text-gray-400">AI Settings</h2>
          <p className="text-xs text-gray-500 mt-1">
            Configure scan AI and retest AI verification. Changes apply to new jobs immediately.
          </p>
        </div>
        <button
          onClick={fetchAISettings}
          disabled={loading || aiSaving}
          className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white rounded text-sm"
        >
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="space-y-2">
          <h3 className="text-xs font-medium text-gray-300 uppercase tracking-wide">Scan AI</h3>
          <label className="block">
            <span className="text-xs text-gray-400">AI URL</span>
            <input
              type="text"
              value={aiURLInput}
              onChange={(e) => setAIURLInput(e.target.value)}
              className="mt-1 w-full px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="https://api.openai.com/v1/chat/completions"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">AI Model</span>
            <input
              type="text"
              value={aiModelInput}
              onChange={(e) => setAIModelInput(e.target.value)}
              className="mt-1 w-full px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="gpt-4o-mini"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Mask Host</span>
            <input
              type="text"
              value={aiMaskHostInput}
              onChange={(e) => setAIMaskHostInput(e.target.value)}
              className="mt-1 w-full px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="example.com"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">AI API Key</span>
            <input
              type="password"
              value={scanAPIKeyInput}
              onChange={(e) => setScanAPIKeyInput(e.target.value)}
              className="mt-1 w-full px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder={aiSettings?.ai_api_key_configured ? 'Configured (enter to replace)' : 'sk-...'}
            />
          </label>
          <label className="inline-flex items-center gap-2 text-xs text-gray-400">
            <input
              type="checkbox"
              checked={clearScanAPIKey}
              onChange={(e) => setClearScanAPIKey(e.target.checked)}
              className="h-4 w-4 rounded border-gray-700 bg-gray-800 text-blue-600 focus:ring-blue-500"
            />
            Clear scan AI API key
          </label>
        </div>

        <div className="space-y-2">
          <h3 className="text-xs font-medium text-gray-300 uppercase tracking-wide">Retest AI Verification</h3>
          <label className="inline-flex items-center gap-2 text-xs text-gray-300">
            <input
              type="checkbox"
              checked={aiVerifyEnabledInput}
              onChange={(e) => setAIVerifyEnabledInput(e.target.checked)}
              className="h-4 w-4 rounded border-gray-700 bg-gray-800 text-blue-600 focus:ring-blue-500"
            />
            Enable AI verification for retests
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">AI Verify URL</span>
            <input
              type="text"
              value={aiVerifyURLInput}
              onChange={(e) => setAIVerifyURLInput(e.target.value)}
              className="mt-1 w-full px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="Leave empty to fall back to Scan AI URL"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">AI Verify Model</span>
            <input
              type="text"
              value={aiVerifyModelInput}
              onChange={(e) => setAIVerifyModelInput(e.target.value)}
              className="mt-1 w-full px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="claude-sonnet-4-5-20250929"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Min Severity</span>
            <select
              value={aiVerifyMinSeverityInput}
              onChange={(e) => setAIVerifyMinSeverityInput(e.target.value as Severity)}
              className="mt-1 w-full px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
            >
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">AI Verify API Key</span>
            <input
              type="password"
              value={verifyAPIKeyInput}
              onChange={(e) => setVerifyAPIKeyInput(e.target.value)}
              className="mt-1 w-full px-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder={aiSettings?.ai_verify_api_key_configured ? 'Configured (enter to replace)' : 'sk-...'}
            />
          </label>
          <label className="inline-flex items-center gap-2 text-xs text-gray-400">
            <input
              type="checkbox"
              checked={clearVerifyAPIKey}
              onChange={(e) => setClearVerifyAPIKey(e.target.checked)}
              className="h-4 w-4 rounded border-gray-700 bg-gray-800 text-blue-600 focus:ring-blue-500"
            />
            Clear retest AI API key
          </label>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <label className="inline-flex items-center gap-2 text-xs text-gray-300">
          <input
            type="checkbox"
            checked={persistAIToEnv}
            onChange={(e) => setPersistAIToEnv(e.target.checked)}
            className="h-4 w-4 rounded border-gray-700 bg-gray-800 text-blue-600 focus:ring-blue-500"
          />
          Persist changes to local <code>.env</code>
        </label>
        <button
          onClick={handleSaveAISettings}
          disabled={aiSaving || loading}
          className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded text-sm"
        >
          {aiSaving ? 'Saving...' : 'Save AI Settings'}
        </button>
      </div>

      {aiSettings && (
        <p className="text-xs text-gray-500">
          Scan key: {aiSettings.ai_api_key_configured ? 'configured' : 'not set'} · Retest key:{' '}
          {aiSettings.ai_verify_api_key_configured ? 'configured' : 'not set'}
        </p>
      )}
      {aiSettingsMessage && <p className="text-xs text-green-400">{aiSettingsMessage}</p>}
      {aiSettingsError && <p className="text-xs text-red-400">{aiSettingsError}</p>}
    </div>
  )
}
