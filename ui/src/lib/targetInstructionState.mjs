/** Operator intent and advisory drafts are distinct even when the text matches. */
export function targetInstructionState(saved) {
  const current = saved?.skill ?? null
  const operator = saved?.operator_skill ?? null
  const editable = current ?? operator
  return {
    editable,
    operator,
    advisory: Boolean(current && saved?.trust !== 'operator'),
    exists: Boolean(current || operator),
    needsOperatorSave: Boolean(editable && saved?.trust !== 'operator'),
  }
}
