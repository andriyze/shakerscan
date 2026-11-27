// Plain names for certificate signature algorithms. Scanners report them three ways: the OID
// ("1.2.840.10045.4.3.3"), the library name ("ecdsa-with-SHA384", "sha256WithRSAEncryption"),
// or only the hash ("sha384"). Every place that shows a signature uses this one label.

const HASHES = { md5: 'MD5', sha1: 'SHA-1', sha224: 'SHA-224', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' }

const OIDS = {
  '1.2.840.113549.1.1.4': ['RSA', 'md5'],
  '1.2.840.113549.1.1.5': ['RSA', 'sha1'],
  '1.2.840.113549.1.1.11': ['RSA', 'sha256'],
  '1.2.840.113549.1.1.12': ['RSA', 'sha384'],
  '1.2.840.113549.1.1.13': ['RSA', 'sha512'],
  '1.2.840.113549.1.1.14': ['RSA', 'sha224'],
  '1.2.840.113549.1.1.10': ['RSA-PSS', null],
  '1.2.840.10045.4.1': ['ECDSA', 'sha1'],
  '1.2.840.10045.4.3.1': ['ECDSA', 'sha224'],
  '1.2.840.10045.4.3.2': ['ECDSA', 'sha256'],
  '1.2.840.10045.4.3.3': ['ECDSA', 'sha384'],
  '1.2.840.10045.4.3.4': ['ECDSA', 'sha512'],
  '1.3.101.112': ['Ed25519', null],
  '1.3.101.113': ['Ed448', null],
}

function hashOf(text) {
  const match = /sha-?(1|224|256|384|512)(?!\d)|md5/i.exec(text)
  if (!match) return null
  return match[0].toLowerCase().startsWith('md5') ? 'md5' : `sha${match[1]}`
}

function familyOf(text) {
  const lower = text.toLowerCase()
  if (lower.includes('ed25519')) return 'Ed25519'
  if (lower.includes('ed448')) return 'Ed448'
  if (lower.includes('pss')) return 'RSA-PSS'
  if (lower.includes('ecdsa')) return 'ECDSA'
  if (lower.includes('rsa')) return 'RSA'
  if (lower.includes('dsa')) return 'DSA'
  return null
}

function join(family, hash) {
  if (family && hash) return `${family} with ${HASHES[hash]}`
  return family || (hash ? HASHES[hash] : '')
}

/**
 * One readable name for a certificate signature algorithm, e.g. "ECDSA with SHA-384".
 * A value that is only a hash stays a hash: the key that signed is the issuer's, so the
 * certificate's own key type does not say which family it was. A value this does not
 * recognise is returned unchanged; nothing is returned for no value.
 */
export function signatureAlgorithmLabel(value) {
  const text = typeof value === 'string' ? value.trim() : ''
  if (!text) return ''
  const known = OIDS[text]
  if (known) return join(known[0], known[1])
  if (/^\d+(\.\d+)+$/.test(text)) return `Algorithm ${text}`
  return join(familyOf(text), hashOf(text)) || text
}
