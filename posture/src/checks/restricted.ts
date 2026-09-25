// Government, military and intergovernmental targets are refused before any cache
// read, quota charge or probe. Matching is on normalized A-label hostnames.

// Whole top-level domains: US government and military, intergovernmental
// organizations, and the Chinese-script "government" TLD (政府).
const TLDS = new Set(['gov', 'mil', 'int', 'xn--mxtq1m']);
// Second-level labels that national registries reserve for government or military use
// under a two-letter country code, e.g. gov.uk, gouv.fr, gob.mx, go.jp, govt.nz, mil.br.
const COUNTRY_SLDS = new Set(['gov', 'govt', 'gouv', 'gob', 'gub', 'go', 'gv', 'mil', 'army', 'navy', 'nic']);
// Government zones that do not follow the patterns above.
const SUFFIXES = [
  'fed.us', 'nsn.us', 'gc.ca', 'canada.ca', 'bund.de', 'admin.ch', 'europa.eu', 'gov.eu',
  // US government-owned or government-chartered organizations on commercial TLDs.
  'usps.com', 'si.edu', 'tva.com', 'amtrak.com'
];
// US state and local government zones under the RFC 1480 locality hierarchy:
// <agency>.state.<xx>.us and ci.<city>.<xx>.us, co.<county>.<xx>.us, etc.
const US_LOCALITY = /(?:^|\.)(?:state|dst|cog)\.[a-z]{2}\.us$|(?:^|\.)(?:ci|co|city|county|town|twp|vil)\.[a-z0-9-]+\.[a-z]{2}\.us$/;

export function isRestrictedTarget(host: string): boolean {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  const tld = labels.at(-1) ?? '', sld = labels.at(-2) ?? '';
  if (TLDS.has(tld)) return true;
  if (tld.length === 2 && COUNTRY_SLDS.has(sld)) return true;
  const name = labels.join('.');
  if (SUFFIXES.some(suffix => name === suffix || name.endsWith('.' + suffix))) return true;
  return US_LOCALITY.test(name);
}
