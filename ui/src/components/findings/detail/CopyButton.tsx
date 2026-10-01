'use client'

import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { useToast } from '@/components/ui'

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const [failed, setFailed] = useState(false)
  const toast = useToast()

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setFailed(false)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
      setFailed(true)
      toast.error('Clipboard access failed. Select and copy the adjacent text instead.')
    }
  }

  return (
    <span className="inline-flex shrink-0 items-center gap-1">
      <button
        onClick={handleCopy}
        className="rounded-sm p-1 transition-colors hover:bg-gray-800 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
        title={label || 'Copy'}
        aria-label={label || 'Copy'}
        type="button"
      >
        {copied ? <Check className="h-3.5 w-3.5 text-green-400" aria-hidden="true" /> : <Copy className={`h-3.5 w-3.5 ${failed ? 'text-red-400' : 'text-gray-400'}`} aria-hidden="true" />}
      </button>
      {failed && <span role="status" className="text-[10px] text-red-300">select text</span>}
    </span>
  )
}
