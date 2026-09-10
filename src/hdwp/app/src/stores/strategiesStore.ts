import { create } from 'zustand'
import type { Strategy } from '../types/hdwp'

interface StrategiesStore {
  strategies: Strategy[]
  loading: boolean
  fetchStrategies(): Promise<void>
  toggleStrategy(strategyId: string): Promise<void>
}

export const useStrategiesStore = create<StrategiesStore>((set, get) => ({
  strategies: [],
  loading: false,
  fetchStrategies: async () => {
    set({ loading: true })
    try {
      const r = await fetch('/api/strategies')
      if (r.ok) set({ strategies: await r.json() })
    } catch { /* ignore */ } finally {
      set({ loading: false })
    }
  },
  toggleStrategy: async (strategyId: string) => {
    try {
      await fetch('/api/strategies/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ strategy_id: strategyId }),
      })
      await get().fetchStrategies()
    } catch { /* ignore */ }
  },
}))
