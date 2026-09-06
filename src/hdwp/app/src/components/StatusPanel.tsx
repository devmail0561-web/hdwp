import { useState } from 'react'
import { useScanStore } from '../stores/scanStore'
import { useFindingsStore } from '../stores/findingsStore'

async function stopProxy() {
  await fetch('/api/proxy/stop', { method: 'POST' }).catch(() => null)
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ff0066', HIGH: '#ff0066', MEDIUM: '#ffaa00', LOW: '#00ccff', INFO: '#445566',
}

const PHASE_COLORS: Record<string, string> = {
  IDLE: '#445566', OBSERVE: '#00ccff', MODEL: '#9966ff',
  INFER: '#ffaa00', HYPOTHESIZE: '#ff8c00',
  EXPERIMENT: '#00aaff', FINDING: '#44ff88', DONE: '#00ff88',
  ERROR: '#ff0066',
}

const PIPELINE = ['OBSERVE', 'MODEL', 'INFER', 'HYPOTHESIZE', 'EXPERIMENT', 'ORACLE', 'FINDING']
const PIPELINE_COLORS = ['#00ccff', '#9966ff', '#ffaa00', '#ff8c00', '#00aaff', '#44ff88', '#ff0066']

function pipelineIndex(phase: string): number {
  const idx = PIPELINE.indexOf(phase)
  return idx >= 0 ? idx : -1
}

export function StatusPanel() {
  const { phase, modelConfidence, endpointCount, hypothesisCount, findingsCount, propertyCount, errorMessage, target, proxyActive, authRequiredUrl } = useScanStore()
  const { findings } = useFindingsStore()
  const phaseColor = PHASE_COLORS[phase] ?? '#00ff88'
  const activeIdx = pipelineIndex(phase)
  const [stopping, setStopping] = useState(false)
  const [caInstalling, setCaInstalling] = useState(false)
  const [caResult, setCaResult] = useState('')

  const handleProxyStop = async () => {
    setStopping(true)
    await stopProxy()
    setStopping(false)
  }

  const handleInstallCA = async () => {
    setCaInstalling(true)
    setCaResult('')
    try {
      const r = await fetch('/api/proxy/install-ca', { method: 'POST' })
      if (r.ok) {
        const d = await r.json() as { summary: string }
        setCaResult(d.summary)
      } else {
        setCaResult('Erreur — voir logs')
      }
    } catch { setCaResult('Erreur réseau') }
    finally { setCaInstalling(false) }
  }

  return (
    <div style={{
      borderRight: '1px solid var(--border)', display: 'flex',
      flexDirection: 'column', overflow: 'hidden', background: 'var(--bg-panel)',
    }}>
      <div style={{ fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)', letterSpacing: 2, padding: '7px 10px 5px', borderBottom: '1px solid var(--border)', background: '#060606', flexShrink: 0 }}>
        <span style={{ color: 'var(--green)' }}>[ </span>STATUS<span style={{ color: 'var(--green)' }}> ]</span>
      </div>

      {/* Phase */}
      <div style={{ padding: '8px 8px 6px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 5 }}>── PHASE COURANTE ──</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            width: 8, height: 8, borderRadius: '50%', background: phaseColor,
            flexShrink: 0, display: 'inline-block', animation: 'blink 0.5s infinite',
          }} />
          <span style={{ color: phaseColor, fontSize: 11, letterSpacing: 1 }}>{phase}</span>
        </div>
      </div>

      {/* Error banner */}
      {phase === 'ERROR' && errorMessage && (
        <div style={{ padding: '5px 8px', background: '#180606', border: '1px solid #ff0066', margin: '4px 8px', flexShrink: 0 }}>
          <div style={{ fontSize: 8, color: '#ff0066', letterSpacing: 1, marginBottom: 2 }}>ERREUR</div>
          <div style={{ fontSize: 8, color: '#ff4466', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{errorMessage}</div>
        </div>
      )}

      {/* Progression */}
      <div style={{ padding: '6px 8px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 4 }}>── PROGRESSION ──</div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#445566', marginBottom: 2 }}>
          <span>CONFIANCE MODÈLE</span>
          <span style={{ color: 'var(--green)' }}>{Math.round(modelConfidence * 100)}%</span>
        </div>
        <div style={{ height: 3, background: '#1a3a1a', borderRadius: 2 }}>
          <div style={{ height: '100%', background: 'var(--green)', borderRadius: 2, width: `${modelConfidence * 100}%`, transition: 'width 1s' }} />
        </div>
      </div>

      {/* Count grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4, padding: '6px 8px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        {[
          { label: 'ENDPOINTS',  value: endpointCount,  color: '#00ccff' },
          { label: 'HYPOTHÈSES', value: hypothesisCount, color: '#ffaa00' },
          { label: 'FINDINGS',   value: findingsCount,  color: '#ff0066' },
          { label: 'PROPRIÉTÉS', value: propertyCount,   color: 'var(--green)' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 2 }}>{label}</div>
            <div style={{ fontFamily: 'var(--font-title)', fontSize: 16, fontWeight: 700, color }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Auth required banner */}
      {authRequiredUrl && (
        <div style={{ padding: '5px 8px', background: '#180606', border: '1px solid #ff4400', margin: '4px 8px', flexShrink: 0 }}>
          <div style={{ fontSize: 8, color: '#ff4400', letterSpacing: 1, marginBottom: 2 }}>⚠ AUTHENTIFICATION REQUISE</div>
          <div style={{ fontSize: 8, color: '#445566', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{authRequiredUrl}</div>
          <div style={{ fontSize: 7, color: '#2a4a2a', marginTop: 3 }}>
            Naviguez dans Firefox (proxy 127.0.0.1:8080) et connectez-vous.
          </div>
        </div>
      )}

      {/* Target + Proxy */}
      {target && (
        <div style={{ padding: '6px 8px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 3 }}>── TARGET ──</div>
          <div style={{ fontSize: 10, color: 'var(--green)', wordBreak: 'break-all', marginBottom: 5 }}>{target}</div>
          {/* Proxy : indicateur read-only + bouton STOP uniquement */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: proxyActive ? 4 : 0 }}>
            <span style={{
              width: 6, height: 6, borderRadius: '50%', display: 'inline-block', flexShrink: 0,
              background: proxyActive ? '#00ff88' : '#2a4a2a',
              animation: proxyActive ? 'blink 0.8s infinite' : 'none',
            }} />
            <span style={{ fontSize: 8, color: proxyActive ? '#00ff88' : '#2a4a2a', letterSpacing: 1, flex: 1 }}>
              {proxyActive ? 'PROXY :8080 ACTIF' : 'PROXY INACTIF'}
            </span>
            {proxyActive && (
              <button onClick={handleProxyStop} disabled={stopping} style={{
                background: 'transparent', border: '1px solid #ff006644',
                color: '#ff006688', fontFamily: 'var(--font-title)', fontSize: 7,
                padding: '1px 6px', cursor: stopping ? 'wait' : 'pointer', letterSpacing: 1,
              }}>
                {stopping ? '…' : '■ STOP'}
              </button>
            )}
          </div>
          {proxyActive && (
            <>
              <div style={{ fontSize: 7, color: '#2a4a2a', marginTop: 2, marginBottom: 3 }}>
                Firefox/Chrome → 127.0.0.1:8080
              </div>
              <button
                onClick={handleInstallCA}
                disabled={caInstalling}
                style={{
                  width: '100%', padding: '2px 0', fontSize: 7,
                  background: 'transparent', border: '1px solid #1a3a1a',
                  color: '#2a4a2a', fontFamily: 'var(--font-title)',
                  letterSpacing: 1, cursor: caInstalling ? 'wait' : 'pointer',
                  transition: 'all 0.1s',
                }}
                onMouseEnter={e => { e.currentTarget.style.color = '#00ff88'; e.currentTarget.style.borderColor = '#00ff88' }}
                onMouseLeave={e => { e.currentTarget.style.color = '#2a4a2a'; e.currentTarget.style.borderColor = '#1a3a1a' }}
              >
                {caInstalling ? '…' : '[ INSTALLER CERT CA ]'}
              </button>
              {caResult && (
                <div style={{ fontSize: 7, color: '#00ccff', marginTop: 2, letterSpacing: 0.5 }}>
                  {caResult}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Pipeline */}
      <div style={{ padding: '4px 8px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 3 }}>── PIPELINE ──</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 2, fontSize: 8 }}>
          {PIPELINE.map((step, i) => {
            const isActive = i === activeIdx
            const isDone = activeIdx >= 0 && i < activeIdx
            const isAllDone = phase === 'DONE' || phase === 'ERROR'
            const color = (isActive || isDone || isAllDone) ? PIPELINE_COLORS[i] : '#1a3a1a'
            return (
              <span key={step}>
                <span style={{
                  color,
                  fontWeight: isActive ? 'bold' : 'normal',
                  textDecoration: isActive ? 'underline' : 'none',
                }}>{step}</span>
                {i < PIPELINE.length - 1 && <span style={{ color: '#1a3a1a' }}> →</span>}
              </span>
            )
          })}
        </div>
      </div>

      {/* Findings list */}
      <div style={{ fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)', letterSpacing: 2, padding: '7px 10px 5px', borderBottom: '1px solid var(--border)', background: '#060606', flexShrink: 0 }}>
        <span style={{ color: 'var(--green)' }}>[ </span>FINDINGS ({findings.length})<span style={{ color: 'var(--green)' }}> ]</span>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '2px 0' }}>
        {findings.length === 0 && (
          <div style={{ padding: '8px 8px', fontSize: 9, color: '#445566', letterSpacing: 1 }}>
            Aucun finding confirmé
          </div>
        )}
        {findings.map(f => {
          const sevColor = SEV_COLORS[f.severity] ?? '#445566'
          return (
            <div key={f.id} style={{
              padding: '4px 6px', marginBottom: 1,
              borderLeft: `2px solid ${sevColor}`,
              background: (f.severity === 'HIGH' || f.severity === 'CRITICAL') ? '#0d0808' : '#080808',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 8, color: '#445566', letterSpacing: 1 }}>
                  {f.id.length > 12 ? f.id.slice(0, 12) + '…' : f.id}
                </span>
                <span style={{ fontSize: 8, color: sevColor, fontWeight: 'bold' }}>{f.severity}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 1 }}>
                <span style={{ fontSize: 9, color: sevColor }}>{f.cwe_id}</span>
                <span style={{ fontSize: 9, color: '#44ff88', fontWeight: 'bold' }}>
                  {Math.round(f.confidence * 100)}%
                </span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
