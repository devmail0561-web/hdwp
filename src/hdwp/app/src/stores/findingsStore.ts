import { create } from 'zustand'
import type { Finding } from '../types/hdwp'

interface FindingsStore {
  findings: Finding[]
  loading: boolean
  addFinding(f: Finding): void
  setFindings(findings: Finding[]): void
  fetchFindings(): Promise<void>
}

export const useFindingsStore = create<FindingsStore>((set) => ({
  findings: [],
  loading: false,
  addFinding: (f) => set((s) => ({
    findings: s.findings.some(e => e.id === f.id) ? s.findings : [...s.findings, f],
  })),
  setFindings: (findings) => set({ findings }),
  fetchFindings: async () => {
    set({ loading: true })
    try {
      const r = await fetch('/api/findings')
      const data = await r.json()
      set({ findings: data })
    } catch (e) {
      console.error('fetchFindings failed', e)
    } finally {
      set({ loading: false })
    }
  },
}))
