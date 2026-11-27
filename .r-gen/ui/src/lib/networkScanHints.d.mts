export function networkScanTcpHints(detail: {
  device?: { metadata_json?: Record<string, unknown> }
  services?: Array<{ port: number; transport?: string; state?: string; binding_status?: string }>
  service_intelligence?: { services: Array<{ port: number; transport?: string; state?: string; binding_status?: string }> }
} | null): string
