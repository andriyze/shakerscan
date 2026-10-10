import type { TargetSkill, TargetSkillState } from './targetSkillApi'
export function targetInstructionState(saved: TargetSkillState | null): {
  editable: TargetSkill | null
  operator: TargetSkill | null
  unconfirmed: boolean
  advisory: boolean
  exists: boolean
  needsOperatorSave: boolean
}
