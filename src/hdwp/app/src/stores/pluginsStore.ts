import { create } from 'zustand'
import type { Plugin } from '../types/hdwp'

interface PluginsStore {
  plugins: Plugin[]
  loading: boolean
  fetchPlugins(): Promise<void>
  togglePlugin(pluginId: string): Promise<void>
}

export const usePluginsStore = create<PluginsStore>((set, get) => ({
  plugins: [],
  loading: false,
  fetchPlugins: async () => {
    set({ loading: true })
    try {
      const r = await fetch('/api/plugins')
      if (r.ok) set({ plugins: await r.json() })
    } catch { /* ignore */ } finally {
      set({ loading: false })
    }
  },
  togglePlugin: async (pluginId: string) => {
    try {
      await fetch('/api/plugins/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plugin_id: pluginId }),
      })
      await get().fetchPlugins()
    } catch { /* ignore */ }
  },
}))
