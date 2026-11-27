import { SCAN_PUBLIC_CONTRACT_SNAPSHOT } from './scanContract.generated'

const LABELS = new Map<string, string>(
  SCAN_PUBLIC_CONTRACT_SNAPSHOT.families.map((family) => [family.name, family.label]),
)

/** The published label of a check family ("nuclei_passive" reads "Nuclei (passive reviewed pack)"),
 *  the one the New Scan page offers it under. A name the contract does not list is shown as words. */
export function checkFamilyLabel(name: string): string {
  const raw = String(name || '')
  return LABELS.get(raw) || raw.replace(/_/g, ' ')
}
