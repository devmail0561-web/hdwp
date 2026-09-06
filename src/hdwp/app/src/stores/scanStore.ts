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
  propertyCount: number
  experimentCount: number
  errorMessage: string
  endpoints: EndpointNode[]
  events: BusEvent[]
  proxyActive: boolean
  idsDetected: boolean
  wsConnected: boolean
  authRequiredUrl: string | null
  setStatus(s: ScanStore['status']): void
  setPhase(p: string): void
  setSessionId(id: string): void
  setTarget(t: string): void
  setEndpoints(eps: EndpointNode[]): void
  addEvent(e: BusEvent): void
  updateFromState(s: StateResponse): void
  setProxyActive(v: boolean): void
  setIdsDetected(v: boolean): void
  setWsConnected(v: boolean): void
  setAuthRequiredUrl(url: string | null): void
  setErrorMessage(msg: string): void
  incrementHypothesisCount(): void
  incrementPropertyCount(): void
  incrementExperimentCount(): void
  reset(): void
  clearMetrics(): void
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
  propertyCount: 0,
  experimentCount: 0,
  errorMessage: '',
  endpoints: [],
  events: [],
  proxyActive: false,
  idsDetected: false,
  wsConnected: false,
  authRequiredUrl: null,
  setStatus: (status) => set({ status }),
  setPhase: (phase) => set({ phase }),
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
    propertyCount: s.property_count,
    experimentCount: s.experiment_count,
    proxyActive: s.proxy_active,
    sessionId: s.session_id || null,
    target: s.target_url || '',
    errorMessage: s.error_message,
  }),
  setProxyActive: (proxyActive) => set({ proxyActive }),
  setIdsDetected: (idsDetected) => set({ idsDetected }),
  setWsConnected: (wsConnected) => set({ wsConnected }),
  setAuthRequiredUrl: (authRequiredUrl) => set({ authRequiredUrl }),
  setErrorMessage: (errorMessage) => set({ errorMessage }),
  incrementHypothesisCount: () => set((s) => ({ hypothesisCount: s.hypothesisCount + 1 })),
  incrementPropertyCount: () => set((s) => ({ propertyCount: s.propertyCount + 1 })),
  incrementExperimentCount: () => set((s) => ({ experimentCount: s.experimentCount + 1 })),
  reset: () => set({
    status: 'idle', sessionId: null, target: '', phase: 'IDLE',
    modelConfidence: 0, endpointCount: 0, hypothesisCount: 0, findingsCount: 0,
    propertyCount: 0, experimentCount: 0, errorMessage: '',
    endpoints: [], events: [], proxyActive: false, idsDetected: false,
    authRequiredUrl: null,
  }),
  clearMetrics: () => set({
    phase: 'IDLE', modelConfidence: 0,
    endpointCount: 0, hypothesisCount: 0, findingsCount: 0,
    propertyCount: 0, experimentCount: 0, errorMessage: '',
    endpoints: [], events: [], proxyActive: false, idsDetected: false, authRequiredUrl: null,
  }),
}))
