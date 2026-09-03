import { useEffect, useRef, useCallback } from 'react'
import { useScanStore } from '../stores/scanStore'
import { useFindingsStore } from '../stores/findingsStore'
import { useFlowStore } from '../stores/flowStore'
import type { EndpointNode, Finding, FlowMap } from '../types/hdwp'

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null)
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const { addEvent, setProxyActive, setIdsDetected, setWsConnected, setEndpoints } = useScanStore()
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
        addEvent(event)
        if (event.type === 'proxy.started') setProxyActive(true)
        if (event.type === 'proxy.failed') setProxyActive(false)
        if (event.type === 'observation.raw') {
          const sc = (event.payload as Record<string, unknown>)?.status_code
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
      } catch {
        // ignore malformed
      }
    }

    ws.onclose = () => {
      setWsConnected(false)
      retryRef.current = setTimeout(connect, 2000)
    }

    ws.onerror = () => ws.close()
  }, [addEvent, addFinding, setProxyActive, setIdsDetected, setWsConnected, setEndpoints])

  useEffect(() => {
    connect()
    return () => {
      wsRef.current?.close()
      if (retryRef.current) clearTimeout(retryRef.current)
    }
  }, [connect])
}
