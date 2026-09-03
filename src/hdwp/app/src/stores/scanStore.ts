import { create } from 'zustand'
import type { BusEvent, EndpointNode, StateResponse } from '../types/hdwp'

const MAX_EVENTS = 500

interface ScanStore {
  status: 'idle' | 'running' | 'done' | 'error'
  sessionId: string | null
  target: string
  phase: string
  modelConfidence: number
  endpointCount: number
  hypothesisCount: number
  findingsCount: number
  endpoints: EndpointNode[]
  events: BusEvent[]
  proxyActive: boolean
  idsDetected: boolean
  wsConnected: boolean
  authRequiredUrl: string | null
  setStatus(s: ScanStore['status']): void
  setSessionId(id: string): void
  setTarget(t: string): void
  setEndpoints(eps: EndpointNode[]): void
  addEvent(e: BusEvent): void
  updateFromState(s: StateResponse): void
  setProxyActive(v: boolean): void
  setIdsDetected(v: boolean): void
  setWsConnected(v: boolean): void
  setAuthRequiredUrl(url: string | null): void
  reset(): void
}

export const useScanStore = create<ScanStore>((set) => ({
  status: 'idle',
  sessionId: null,
  target: '',
  phase: 'IDLE',
  modelConfidence: 0,
  endpointCount: 0,
  hypothesisCount: 0,
  findingsCount: 0,
  endpoints: [],
  events: [],
  proxyActive: false,
  idsDetected: false,
  wsConnected: false,
  authRequiredUrl: null,
  setStatus: (status) => set({ status }),
  setSessionId: (sessionId) => set({ sessionId }),
  setTarget: (target) => set({ target }),
  setEndpoints: (endpoints) => set({ endpoints }),
  addEvent: (e) => set((s) => ({
    events: [...s.events.slice(-(MAX_EVENTS - 1)), e],
  })),
  updateFromState: (s) => set({
    status: s.status as ScanStore['status'],
    phase: s.phase,
    modelConfidence: s.model_confidence,
    endpointCount: s.endpoint_count,
    hypothesisCount: s.hypothesis_count,
    findingsCount: s.findings_count,
    proxyActive: s.proxy_active,
    sessionId: s.session_id || null,
    target: s.target_url || '',
  }),
  setProxyActive: (proxyActive) => set({ proxyActive }),
  setIdsDetected: (idsDetected) => set({ idsDetected }),
  setWsConnected: (wsConnected) => set({ wsConnected }),
  setAuthRequiredUrl: (authRequiredUrl) => set({ authRequiredUrl }),
  reset: () => set({
    status: 'idle', sessionId: null, target: '', phase: 'IDLE',
    modelConfidence: 0, endpointCount: 0, hypothesisCount: 0, findingsCount: 0,
    endpoints: [], events: [], proxyActive: false, idsDetected: false,
    authRequiredUrl: null,
  }),
}))
