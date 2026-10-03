/** Saved delegation makes Hunt instruction edits effective; knowledge is a separate input. */
export function targetInstructionState(saved) {
  const current = saved?.skill ?? null
  const trusted = ['operator', 'operator_delegated'].includes(saved?.trust)
  const operator = saved?.operator_skill ?? (trusted ? current : null)
  const editable = operator ?? current ?? saved?.knowledge ?? null
  return {
    editable,
    operator,
    advisory: Boolean(editable && !operator),
    exists: Boolean(operator),
    needsOperatorSave: Boolean(editable && !operator),
  }
}
