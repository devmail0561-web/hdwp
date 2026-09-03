import { create } from 'zustand'
import type { ApiKeyStatus, LLMModelsResponse, LLMStatus } from '../types/hdwp'

interface LLMStore extends LLMStatus {
  models: string[]
  modelsLoading: boolean
  modelsError: string | null
  apiKeys: Record<string, ApiKeyStatus>
  fetchStatus(): Promise<void>
  fetchModels(provider: string): Promise<void>
  fetchApiKeys(): Promise<void>
  saveApiKey(provider: string, key: string): Promise<boolean>
}

export const useLLMStore = create<LLMStore>((set, get) => ({
  active: false,
  provider: null,
  model: null,
  api_key_valid: false,
  models: [],
  modelsLoading: false,
  modelsError: null,
  apiKeys: {},

  fetchStatus: async () => {
    try {
      const r = await fetch('/api/llm/config')
      const data: LLMStatus = await r.json()
      set(data)
    } catch { /* ignore */ }
  },

  fetchModels: async (provider: string) => {
    set({ modelsLoading: true, modelsError: null, models: [] })
    try {
      const r = await fetch(`/api/llm/models?provider=${encodeURIComponent(provider)}`)
      if (!r.ok) {
        set({ modelsError: await r.text(), modelsLoading: false })
        return
      }
      const data: LLMModelsResponse = await r.json()
      set({
        models: data.models,
        modelsError: data.error,
        modelsLoading: false,
      })
    } catch {
      set({ modelsError: 'Impossible de contacter le serveur', modelsLoading: false })
    }
  },

  fetchApiKeys: async () => {
    try {
      const r = await fetch('/api/llm/api-keys')
      if (r.ok) {
        const data: Record<string, ApiKeyStatus> = await r.json()
        set({ apiKeys: data })
      }
    } catch { /* ignore */ }
  },

  saveApiKey: async (provider: string, key: string) => {
    try {
      const r = await fetch('/api/llm/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, api_key: key }),
      })
      if (!r.ok) return false
      await get().fetchApiKeys()
      await get().fetchModels(provider)
      return true
    } catch {
      return false
    }
  },
}))
