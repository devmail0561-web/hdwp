import { useEffect, useRef, useState } from 'react'
import { TopBar } from './components/TopBar'
import { TabBar } from './components/TabBar'
import { ScanTab } from './components/ScanTab'
import { FindingsTab } from './components/FindingsTab'
import { FlowTab } from './components/FlowTab'
import { ReportTab } from './components/ReportTab'
import { ExploitTab } from './components/ExploitTab'
import { PayloadTab } from './components/PayloadTab'
import { PluginsTab } from './components/PluginsTab'
import { StrategiesTab } from './components/StrategiesTab'
import { SettingsTab } from './components/SettingsTab'
import { IntelTab } from './components/IntelTab'
import { useWebSocket } from './hooks/useWebSocket'
import { useLLMStore } from './stores/llmStore'
import { useScanStore } from './stores/scanStore'
import { useV3Store } from './stores/v3Store'

const SESSION_KEY = 'hdwp_active_session'

function saveSession(sessionId: string, target: string, status: string) {
  try { localStorage.setItem(SESSION_KEY, JSON.stringify({ sessionId, target, status })) } catch { /* ignore */ }
}

function clearSession() {
  try { localStorage.removeItem(SESSION_KEY) } catch { /* ignore */ }
}

export function App() {
  const [activeTab, setActiveTab] = useState('scan')
  const { status, sessionId } = useScanStore()
  const { fetchStatus } = useLLMStore()
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useWebSocket()

  useEffect(() => { fetchStatus() }, [fetchStatus])

  // Persister la session active dans localStorage
  useEffect(() => {
    if (sessionId) {
      saveSession(sessionId, useScanStore.getState().target, status)
    }
  }, [sessionId, status])

  // Restaurer la session au chargement de la page (après refresh)
  useEffect(() => {
    try {
      const saved = localStorage.getItem(SESSION_KEY)
      if (!saved) return
      const { sessionId: sid, target, status: st } = JSON.parse(saved) as { sessionId: string; target: string; status: string }
      if (!sid) return
      const { setSessionId, setTarget, setStatus } = useScanStore.getState()
      // Pré-peupler le store pour déverrouiller les onglets immédiatement
      setSessionId(sid)
      setTarget(target)
      setStatus(st === 'running' ? 'running' : st === 'done' ? 'done' : 'idle')
      // Reprendre la session sur le backend
      fetch(`/api/session/${sid}/resume`, { method: 'POST' }).catch(() => {})
    } catch { /* ignore */ }
  }, [])  // eslint-disable-line react-hooks/exhaustive-deps

  // Polling actif pendant le scan + quelques cycles après pour l'état final
  useEffect(() => {
    if (!sessionId) return
    if (status !== 'running' && status !== 'done') return

    const { updateFromState } = useScanStore.getState()
    let donePolls = 0

    const poll = async () => {
      try {
        const r = await fetch('/api/state')
        if (r.ok) {
          const data = await r.json()
          updateFromState(data)
          if (data.status === 'done' || data.status === 'error') {
            if (++donePolls >= 3 && pollRef.current) {
              clearInterval(pollRef.current)
              pollRef.current = null
            }
          } else {
            donePolls = 0
          }
        }
      } catch { /* ignore */ }
    }

    pollRef.current = setInterval(poll, 1500)
    poll()
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [status, sessionId])

  const handleTabChange = async (tab: string) => {
    if (!sessionId && tab !== 'scan') return  // bloquer si pas de session
    if (tab === 'stop') {
      await fetch('/api/scan/stop', { method: 'POST' }).catch(() => null)
      return
    }
    setActiveTab(tab)
  }

  const handleHome = async () => {
    // Arrêter le scan si en cours
    if (status === 'running') {
      await fetch('/api/scan/stop', { method: 'POST' }).catch(() => null)
    }
    clearSession()
    useScanStore.getState().reset()
    useV3Store.getState().reset()
    setActiveTab('scan')
  }

  return (
    <div style={{
      width: '100%', maxWidth: 960, height: '100vh', maxHeight: 680,
      position: 'relative', overflow: 'hidden',
      border: '1px solid #1a3a1a',
      boxShadow: '0 0 40px #00ff4115, 0 0 80px #00ff4108',
      background: 'var(--bg)',
    }}>
      <div style={{
        position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 10,
        background: 'repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.06) 2px,rgba(0,0,0,0.06) 4px)',
      }} />
      <div style={{
        position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 10,
        background: 'radial-gradient(ellipse at center,transparent 55%,rgba(0,0,0,0.65) 100%)',
      }} />
      <div style={{ position: 'relative', zIndex: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
        <TopBar onHome={sessionId ? handleHome : undefined} />
        <TabBar active={activeTab} onChange={handleTabChange} locked={!sessionId} />
        <div style={{ flex: 1, overflow: 'hidden' }}>
          {activeTab === 'scan'     && <ScanTab />}
          {activeTab === 'findings' && <FindingsTab />}
          {activeTab === 'flow'     && <FlowTab />}
          {activeTab === 'intel'    && <IntelTab />}
          {activeTab === 'report'   && <ReportTab />}
          {activeTab === 'payload'  && <PayloadTab />}
          {activeTab === 'exploit'  && <ExploitTab />}
          {activeTab === 'plugins'     && <PluginsTab />}
          {activeTab === 'strategies'  && <StrategiesTab />}
          {activeTab === 'settings'    && <SettingsTab onTabChange={setActiveTab} />}
        </div>
      </div>
    </div>
  )
}
