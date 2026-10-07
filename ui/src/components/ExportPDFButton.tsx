'use client'

import { useState } from 'react'
import { buttonClasses } from '@/components/ui'

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
      className={`${buttonClasses('secondary', 'md')} no-print`}
      aria-label="Export PDF"
    >
      {exporting ? 'Exporting...' : 'Export PDF'}
    </button>
  )
}
