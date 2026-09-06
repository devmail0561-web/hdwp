import { create } from 'zustand'
import type { FlowMap } from '../types/hdwp'

interface FlowStore {
  flowMap: FlowMap | null
  loading: boolean
  setFlowMap(fm: FlowMap | null): void
  fetchFlowMap(): Promise<void>
}

export const useFlowStore = create<FlowStore>((set) => ({
  flowMap: null,
  loading: false,

  setFlowMap: (flowMap) => set({ flowMap }),

  fetchFlowMap: async () => {
    set({ loading: true })
    try {
      const r = await fetch('/api/flow/map')
      if (r.ok) set({ flowMap: await r.json() })
    } catch { /* ignore */ } finally {
      set({ loading: false })
    }
  },
}))
