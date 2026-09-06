import { useEffect, useRef, useCallback } from 'react'
import { useScanStore } from '../stores/scanStore'
import { useFindingsStore } from '../stores/findingsStore'
import { useFlowStore } from '../stores/flowStore'
import type { EndpointNode, Finding, FlowMap } from '../types/hdwp'

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null)
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const {
    addEvent, setProxyActive, setIdsDetected, setWsConnected, setEndpoints,
    setStatus, setPhase, setErrorMessage,
    incrementHypothesisCount, incrementPropertyCount, incrementExperimentCount,
  } = useScanStore()
  const { addFinding } = useFindingsStore()
  const { setFlowMap } = useFlowStore()

  const connect = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/ws/events`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      setWsConnected(true)
      if (retryRef.current) clearTimeout(retryRef.current)
    }

    ws.onmessage = ({ data }) => {
      try {
        const event = JSON.parse(data as string)
        // Ignorer les événements qui appartiennent à une autre session active
        const currentSessionId = useScanStore.getState().sessionId
        if (event.session_id && currentSessionId && event.session_id !== currentSessionId) return
        addEvent(event)
        if (event.type === 'observation.raw') {
          const resp = (event.payload as Record<string, unknown>)?.response as Record<string, unknown> | undefined
          const sc = resp?.status_code
          if (sc === 429 || sc === 503) setIdsDetected(true)
        }
        if (event.type === 'model.updated') {
          const eps = (event.payload as Record<string, unknown>)?.endpoints
          if (Array.isArray(eps)) setEndpoints(eps as EndpointNode[])
        }
        if (event.type === 'finding.confirmed' && (event.payload as Record<string, unknown>)?.id) {
          addFinding(event.payload as Finding)
        }
        if (event.type === 'flow.updated') {
          setFlowMap(event.payload as FlowMap)
        }
        if (event.type === 'auth.required') {
          const p = event.payload as Record<string, string>
          useScanStore.getState().setAuthRequiredUrl(p.path_pattern || p.url || '')
        }
        if (event.type === 'hypothesis.generated') incrementHypothesisCount()
        if (event.type === 'property.inferred') incrementPropertyCount()
        if (event.type === 'experiment.result') incrementExperimentCount()
        if (event.type === 'scan.completed') {
          setStatus('done')
          setPhase('DONE')
        }
        if (event.type === 'scan.error') {
          setStatus('error')
          setPhase('ERROR')
          const errMsg = (event.payload as Record<string, unknown>)?.error
          if (typeof errMsg === 'string') setErrorMessage(errMsg)
        }
      } catch {
        // ignore malformed
      }
    }

    ws.onclose = () => {
      setWsConnected(false)
      retryRef.current = setTimeout(connect, 2000)
    }

    ws.onerror = () => ws.close()
  }, [
    addEvent, addFinding, setProxyActive, setIdsDetected, setWsConnected, setEndpoints,
    setFlowMap, setStatus, setPhase, setErrorMessage,
    incrementHypothesisCount, incrementPropertyCount, incrementExperimentCount,
  ])

  useEffect(() => {
    connect()
    return () => {
      wsRef.current?.close()
      if (retryRef.current) clearTimeout(retryRef.current)
    }
  }, [connect])
}
