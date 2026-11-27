// Ephemeral retry identity. Never persist collection documents or credentials.
export class UploadAttempt {
  private previous: { digest: string; key: string } | null = null

  async keyFor(payload: unknown): Promise<string | undefined> {
    // Hosted HTTPS and localhost provide Web Crypto. Preserve legacy uploads on
    // insecure standalone origins without inventing a weak content fingerprint.
    if (!globalThis.crypto?.subtle) return undefined
    const bytes = new TextEncoder().encode(JSON.stringify(payload))
    const hash = await crypto.subtle.digest('SHA-256', bytes)
    const digest = Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('')
    if (this.previous?.digest !== digest) {
      this.previous = { digest, key: `ui-upload:${crypto.randomUUID()}` }
    }
    return this.previous.key
  }

  reset() { this.previous = null }
}
