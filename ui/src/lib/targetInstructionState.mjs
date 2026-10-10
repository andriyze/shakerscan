/** Operator (or explicitly opted-in delegated) instructions are effective; knowledge is a separate input.
 * Agent-written, unconfirmed instructions are advisory until an operator saves them. */
export function targetInstructionState(saved) {
  const current = saved?.skill ?? null
  const trusted = ['operator', 'operator_delegated'].includes(saved?.trust)
  const operator = saved?.operator_skill ?? (trusted ? current : null)
  const unconfirmed = operator ? null : (saved?.unconfirmed_instructions ?? null)
  const editable = operator ?? unconfirmed ?? current ?? saved?.knowledge ?? null
  return {
    editable,
    operator,
    unconfirmed: Boolean(unconfirmed),
    advisory: Boolean(editable && !operator),
    exists: Boolean(operator),
    needsOperatorSave: Boolean(editable && !operator),
  }
}
