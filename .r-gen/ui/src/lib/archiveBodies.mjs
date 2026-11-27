/**
 * What an archive view says about a call's body that an export left out. A masked export lists
 * such a body under `payload_omitted` and its reason under `payload_omitted_reasons`, and sends
 * `null` for it, so a missing body is not "no body recorded".
 */
export const BODY_WITHHELD_LABEL = 'Body withheld from this export (size/budget limit)'
export const BODY_UNMASKABLE_LABEL = 'Body withheld: it could not be masked safely'

export function bodyWithheldLabel(transaction, side) {
  const field = `${side}_body`
  const reason = transaction?.payload_omitted_reasons?.[field]
  if (reason === 'masking_failed') return BODY_UNMASKABLE_LABEL
  if (reason || (transaction?.payload_omitted || []).includes(field)) return BODY_WITHHELD_LABEL
  return null
}
