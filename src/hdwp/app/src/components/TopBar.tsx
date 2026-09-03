import { useEffect, useState } from 'react'
import { useScanStore } from '../stores/scanStore'
import { useLLMStore } from '../stores/llmStore'

function Chip({ active, label, color = 'green', blink = false }: {
  active: boolean; label: string; color?: 'green' | 'amber' | 'red'; blink?: boolean
}) {
  const colors = { green: '#00ff88', amber: '#ffaa00', red: '#ff0066' }
  const c = colors[color]
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: active ? c : '#445566' }}>
      <span style={{
        width: 6, height: 6, borderRadius: '50%',
        background: active ? c : '#445566',
        display: 'inline-block',
        animation: blink && active ? 'blink 0.8s infinite' : 'none',
      }} />
      {label}
    </div>
  )
}

const LOGO = ` ██╗  ██╗██████╗ ██╗    ██╗██████╗
 ██║  ██║██╔══██╗██║    ██║██╔══██╗
 ███████║██║  ██║██║ █╗ ██║██████╔╝
 ██╔══██║██║  ██║██║███╗██║██╔═══╝
 ██║  ██║██████╔╝╚███╔███╔╝██║
 ╚═╝  ╚═╝╚═════╝  ╚══╝╚══╝╚═╝`

export function TopBar({ onHome }: { onHome?: () => void }) {
  const { phase, sessionId, proxyActive, idsDetected, wsConnected } = useScanStore()
  const { active: llmActive, model } = useLLMStore()
  const [time, setTime] = useState('')

  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString('fr-FR'))
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <header style={{
      background: 'var(--bg-input)', borderBottom: '1px solid var(--border-hi)',
      padding: '5px 14px', display: 'flex',
      alignItems: 'center', justifyContent: 'space-between', flexShrink: 0,
    }}>
      <div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 7, color: 'var(--green)', whiteSpace: 'pre', lineHeight: 1.1 }}>
          {LOGO}
        </div>
        <div style={{ fontFamily: 'var(--font-title)', fontSize: 7, color: 'var(--green-dark)', letterSpacing: 2, marginTop: 1 }}>
          HYPOTHESIS-DRIVEN WEB PENTESTING ENGINE
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dark)', letterSpacing: 2 }}>
            {sessionId ?? 'NO SESSION'}  ·  v0.1.0
          </div>
          {sessionId && onHome && (
            <button
              onClick={onHome}
              title="Retour à l'accueil (nouvelle session)"
              style={{
                background: 'transparent', border: '1px solid #2a4a2a',
                color: '#2a4a2a', fontFamily: 'var(--font-title)', fontSize: 7,
                padding: '1px 6px', cursor: 'pointer', letterSpacing: 1,
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = '#ff0066'; e.currentTarget.style.color = '#ff0066' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a4a2a'; e.currentTarget.style.color = '#2a4a2a' }}
            >
              ⌂ HOME
            </button>
          )}
        </div>
        <div style={{
          fontFamily: 'var(--font-title)', fontSize: 9,
          padding: '2px 10px', border: '1px solid #00ff4444',
          background: '#00ff4808', color: 'var(--green)', letterSpacing: 2,
          animation: 'phase-pulse 1.8s ease-in-out infinite',
        }}>
          ● {phase}
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
        <div style={{ fontFamily: 'var(--font-title)', fontSize: 13, color: 'var(--green)', letterSpacing: 2 }}>
          {time}
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <Chip active={proxyActive} label="PROXY :8080" blink />
          <Chip active={llmActive} label={`LLM ${(model ?? '').toUpperCase()}`} />
          <Chip active={idsDetected} label="IDS DÉTECTÉ" color="amber" blink />
          {!wsConnected && <Chip active blink color="red" label="CONNEXION PERDUE" />}
        </div>
      </div>
    </header>
  )
}
