import { create } from 'zustand'
import type {
  ThreatModelUpdated,
  InvariantViolated,
  CrossRoleDiff,
  TemporalAnomaly,
  WafSignature,
  GoalReached,
  PreconditionMissing,
} from '../types/hdwp'

const MAX_V3 = 100

interface V3Store {
  threatScores: Record<string, number>
  threatClassifications: Record<string, string>
  threatScoreMax: number
  invariantViolations: InvariantViolated[]
  crossRoleDiffs: CrossRoleDiff[]
  temporalAnomalies: TemporalAnomaly[]
  wafSignatures: WafSignature[]
  goalsReached: GoalReached[]
  preconditionsMissing: PreconditionMissing[]
  setThreatModel(p: ThreatModelUpdated): void
  addInvariantViolation(e: InvariantViolated): void
  addCrossRoleDiff(e: CrossRoleDiff): void
  addTemporalAnomaly(e: TemporalAnomaly): void
  addWafSignature(e: WafSignature): void
  addGoalReached(e: GoalReached): void
  addPreconditionMissing(e: PreconditionMissing): void
  reset(): void
}

export const useV3Store = create<V3Store>((set) => ({
  threatScores: {},
  threatClassifications: {},
  threatScoreMax: 0,
  invariantViolations: [],
  crossRoleDiffs: [],
  temporalAnomalies: [],
  wafSignatures: [],
  goalsReached: [],
  preconditionsMissing: [],

  setThreatModel: (p) => set({
    threatScores: p.scores,
    threatClassifications: p.classifications,
    threatScoreMax: Object.values(p.scores).length > 0 ? Math.max(...Object.values(p.scores)) : 0,
  }),

  addInvariantViolation: (e) => set((s) => ({
    invariantViolations: [...s.invariantViolations.slice(-(MAX_V3 - 1)), e],
  })),
  addCrossRoleDiff: (e) => set((s) => ({
    crossRoleDiffs: [...s.crossRoleDiffs.slice(-(MAX_V3 - 1)), e],
  })),
  addTemporalAnomaly: (e) => set((s) => ({
    temporalAnomalies: [...s.temporalAnomalies.slice(-(MAX_V3 - 1)), e],
  })),
  addWafSignature: (e) => set((s) => ({
    wafSignatures: [...s.wafSignatures.slice(-(MAX_V3 - 1)), e],
  })),
  addGoalReached: (e) => set((s) => ({
    goalsReached: [...s.goalsReached.slice(-(MAX_V3 - 1)), e],
  })),
  addPreconditionMissing: (e) => set((s) => ({
    preconditionsMissing: [...s.preconditionsMissing.slice(-(MAX_V3 - 1)), e],
  })),

  reset: () => set({
    threatScores: {},
    threatClassifications: {},
    threatScoreMax: 0,
    invariantViolations: [],
    crossRoleDiffs: [],
    temporalAnomalies: [],
    wafSignatures: [],
    goalsReached: [],
    preconditionsMissing: [],
  }),
}))
