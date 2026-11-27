// The observed-posture grade as lists show it.
//
// A stored grade ends in an asterisk when the run that produced it was incomplete. The Scan page
// shows the letter and says in words that the result is provisional; lists show the same letter
// and the same word, so one run does not read "F*" in a list and "F" on its page.

/** `{ letter, provisional }` for a stored grade, or null when there is none. */
export function observedGrade(grade) {
  const stored = grade === null || grade === undefined ? '' : String(grade).trim()
  if (!stored) return null
  const letter = stored.replace(/\*+$/, '')
  if (!letter) return null
  return { letter, provisional: letter !== stored }
}

export const PROVISIONAL_GRADE_TITLE = 'Provisional: the run was incomplete, so this is not a clean bill of health.'
export const OBSERVED_GRADE_TITLE = 'Risk observed by this run; this is not an overall safety score.'
