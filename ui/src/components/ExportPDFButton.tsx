'use client'

import { useState } from 'react'

export default function ExportPDFButton() {
  const [exporting, setExporting] = useState(false)

  const handleExport = async () => {
    setExporting(true)
    try {
      window.print()
    } finally {
      setExporting(false)
    }
  }

  return (
    <button
      onClick={handleExport}
      disabled={exporting}
      className="px-3 py-2 rounded border border-gray-600 text-gray-300 text-sm hover:bg-gray-700 disabled:opacity-50 no-print"
      aria-label="Export PDF"
    >
      {exporting ? 'Exporting...' : 'Export PDF'}
    </button>
  )
}
