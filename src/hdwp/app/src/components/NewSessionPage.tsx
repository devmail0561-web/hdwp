import { useEffect, useState } from 'react'
import { useScanStore } from '../stores/scanStore'
import { useFindingsStore } from '../stores/findingsStore'
import { useFlowStore } from '../stores/flowStore'
import type { NewSessionRequest, SessionMeta } from '../types/hdwp'

const STATUS_COLORS: Record<string, string> = {
  done: '#00ff88', running: '#00ccff', error: '#ff0066', ready: '#445566',
}

function relativeDate(iso: string): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'à l\'instant'
  if (mins < 60) return `il y a ${mins}min`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `il y a ${hrs}h`
  return `il y a ${Math.floor(hrs / 24)}j`
}

type ScanMode = 'discover' | 'tokens' | 'yaml'

const MODE_INFO: Record<ScanMode, { label: string; desc: string }> = {
  discover: {
    label: 'DÉCOUVERTE',
    desc: 'Crawl automatique sans credentials. Configurez Firefox sur 127.0.0.1:8080 pour que le proxy capture vos tokens au fil de la navigation.',
  },
  tokens: {
    label: 'AVEC CREDENTIALS',
    desc: 'Vous avez déjà un token Bearer, une session cookie ou une clé API. Renseignez-les directement.',
  },
  yaml: {
    label: 'FICHIER YAML',
    desc: 'Mode avancé — vous avez un fichier de contexte HDWP existant avec credentials, scope et options préconfigurés.',
  },
}

export function NewSessionPage() {
  const [url, setUrl] = useState('')
  const [mode, setMode] = useState<ScanMode>('discover')
  const [tokenType, setTokenType] = useState<'bearer' | 'cookie' | 'api_key'>('bearer')
  const [tokenValue, setTokenValue] = useState('')
  const [roleName, setRoleName] = useState('user')
  const [yamlPath, setYamlPath] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [sessions, setSessions] = useState<SessionMeta[]>([])
  const [sessionsLoading, setSessionsLoading] = useState(true)
  const [resuming, setResuming] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)
  const { setSessionId, setTarget, setStatus } = useScanStore()

  const handleDelete = async (s: SessionMeta, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm(`Supprimer la session ${s.session_id.slice(0, 16)}… ?\nToutes les données seront perdues.`)) return
    setDeleting(s.session_id)
    try {
      await fetch(`/api/session/${s.session_id}`, { method: 'DELETE' })
      setSessions(prev => prev.filter(x => x.session_id !== s.session_id))
      // Nettoyer localStorage si c'est la session active
      try {
        const saved = localStorage.getItem('hdwp_active_session')
        if (saved) {
          const { sessionId: sid } = JSON.parse(saved) as { sessionId: string }
          if (sid === s.session_id) localStorage.removeItem('hdwp_active_session')
        }
      } catch { /* ignore */ }
    } catch { /* ignore */ }
    finally { setDeleting(null) }
  }

  const handlePurgeAll = async () => {
    if (!confirm('Supprimer TOUTES les sessions ?\nCette action est irréversible.')) return
    setSessionsLoading(true)
    try {
      await fetch('/api/sessions', { method: 'DELETE' })
      setSessions([])
      localStorage.removeItem('hdwp_active_session')
    } catch { /* ignore */ }
    finally { setSessionsLoading(false) }
  }

  useEffect(() => {
    setSessionsLoading(true)
    fetch('/api/sessions')
      .then(r => r.ok ? r.json() : [])
      .then((data: SessionMeta[]) => setSessions(data.slice(0, 7)))
      .catch(() => setSessions([]))
      .finally(() => setSessionsLoading(false))
  }, [])

  const handleResume = async (s: SessionMeta) => {
    setResuming(s.session_id)
    try {
      useScanStore.getState().clearMetrics()
      useFindingsStore.getState().setFindings([])
      useFlowStore.getState().setFlowMap(null)
      const r = await fetch(`/api/session/${s.session_id}/resume`, { method: 'POST' })
      if (!r.ok) { setError(await r.text()); return }
      const data = await r.json() as { session_id: string; target_url: string; status: string }
      setSessionId(data.session_id)
      setTarget(data.target_url)
      const validStatuses = ['running', 'done', 'error'] as const
      setStatus(validStatuses.includes(data.status as typeof validStatuses[number]) ? data.status as typeof validStatuses[number] : 'idle')
    } catch (e) { setError(String(e)) }
    finally { setResuming(null) }
  }

  const handleLaunch = async () => {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      setError('URL invalide — doit commencer par http:// ou https://')
      return
    }
    if (mode === 'yaml' && !yamlPath.trim()) {
      setError('Chemin du fichier YAML requis')
      return
    }
    setError('')
    useScanStore.getState().reset()
    useFindingsStore.getState().setFindings([])
    useFlowStore.getState().setFlowMap(null)
    setLoading(true)
    try {
      let req: NewSessionRequest
      if (mode === 'yaml') {
        req = { target_url: url, mode: 'yaml', yaml_path: yamlPath.trim() }
      } else if (mode === 'tokens' && tokenValue.trim()) {
        req = {
          target_url: url,
          mode: 'manual',
          manual_tokens: [{ role_name: roleName || 'user', token_type: tokenType, token_value: tokenValue.trim() }],
        }
      } else {
        req = { target_url: url, mode: 'auto' }
      }

      const r = await fetch('/api/session/new', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      })
      if (!r.ok) { setError(await r.text()); return }
      const { session_id } = await r.json() as { session_id: string }
      setSessionId(session_id)
      setTarget(url)

      const r2 = await fetch('/api/scan/start', { method: 'POST' })
      if (r2.ok) setStatus('running')
    } catch (e) { setError(String(e)) }
    finally { setLoading(false) }
  }

  return (
    <div style={{ height: '100%', display: 'flex', overflow: 'hidden', background: 'var(--bg)' }}>

      {/* ── Colonne gauche : sessions ── */}
      <div style={{
        width: 320, flexShrink: 0, borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        <div style={{
          fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)',
          letterSpacing: 2, padding: '10px 14px 8px',
          borderBottom: '1px solid var(--border)', background: '#060606', flexShrink: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span><span style={{ color: 'var(--green)' }}>[ </span>SESSIONS RÉCENTES<span style={{ color: 'var(--green)' }}> ]</span></span>
          {sessions.length > 0 && (
            <button
              onClick={handlePurgeAll}
              style={{
                background: 'transparent', border: '1px solid #1a1a1a',
                color: '#2a2a2a', fontFamily: 'var(--font-title)', fontSize: 7,
                padding: '1px 6px', cursor: 'pointer', letterSpacing: 1,
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = '#ff0066'; e.currentTarget.style.color = '#ff0066' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = '#1a1a1a'; e.currentTarget.style.color = '#2a2a2a' }}
            >
              PURGER TOUT
            </button>
          )}
        </div>

        <div style={{ flex: 1, overflowY: 'auto' }}>
          {sessionsLoading && (
            <div style={{ padding: '14px', fontSize: 9, color: '#2a4a2a', letterSpacing: 1, textAlign: 'center' }}>
              CHARGEMENT…
            </div>
          )}
          {!sessionsLoading && sessions.length === 0 && (
            <div style={{ padding: '20px 14px', fontSize: 9, color: '#2a4a2a', letterSpacing: 1 }}>
              <div style={{ marginBottom: 6 }}>Aucune session enregistrée.</div>
              <div style={{ color: '#1a3a1a' }}>Les sessions apparaîtront ici après votre première analyse.</div>
            </div>
          )}
          {sessions.map(s => {
            const col = STATUS_COLORS[s.status] ?? '#445566'
            const isResuming = resuming === s.session_id
            const shortUrl = s.target_url.replace(/^https?:\/\//, '').slice(0, 28)
            return (
              <div
                key={s.session_id}
                onClick={() => handleResume(s)}
                style={{
                  padding: '9px 14px', borderBottom: '1px solid var(--border)',
                  cursor: 'pointer', transition: 'background 0.1s',
                }}
                onMouseEnter={e => { e.currentTarget.style.background = '#0a1a12' }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: col, flexShrink: 0, display: 'inline-block' }} />
                  <span style={{ fontSize: 11, color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {shortUrl}
                  </span>
                  <span style={{ fontSize: 8, color: col, letterSpacing: 1, flexShrink: 0 }}>{s.status.toUpperCase()}</span>
                  <button
                    onClick={e => handleDelete(s, e)}
                    disabled={deleting === s.session_id}
                    title="Supprimer cette session"
                    style={{
                      background: 'transparent', border: '1px solid #1a1a1a',
                      color: '#2a2a2a', fontFamily: 'var(--font-title)', fontSize: 7,
                      padding: '1px 4px', cursor: 'pointer', flexShrink: 0,
                    }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = '#ff0066'; e.currentTarget.style.color = '#ff0066' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = '#1a1a1a'; e.currentTarget.style.color = '#2a2a2a' }}
                  >
                    {deleting === s.session_id ? '…' : '✕'}
                  </button>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: '#445566' }}>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{s.session_id.slice(0, 16)}…</span>
                  <span style={{ color: s.findings_count > 0 ? '#ff0066' : '#445566' }}>
                    {s.findings_count} finding{s.findings_count !== 1 ? 's' : ''}
                  </span>
                  <span>{relativeDate(s.updated_at)}</span>
                </div>
                {isResuming && (
                  <div style={{ fontSize: 8, color: '#00ccff', marginTop: 3, letterSpacing: 1 }}>RESTAURATION…</div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Colonne droite : nouvelle session ── */}
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', overflowY: 'auto', padding: '16px' }}>
        <div style={{ width: 360 }}>
          <div style={{ fontFamily: 'var(--font-title)', fontSize: 12, color: 'var(--green)', letterSpacing: 2, marginBottom: 18 }}>
            ── NOUVELLE SESSION ──
          </div>

          {/* URL */}
          <label style={{ fontSize: 9, color: 'var(--green-dim)', letterSpacing: 1 }}>TARGET URL</label>
          <input
            value={url} onChange={e => setUrl(e.target.value)}
            placeholder="https://api.exemple.com"
            onKeyDown={e => e.key === 'Enter' && handleLaunch()}
            style={{
              width: '100%', marginTop: 5, marginBottom: 16, boxSizing: 'border-box',
              background: '#0d0d0d', border: '1px solid var(--border-hi)',
              color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 12,
              padding: '7px 10px', outline: 'none',
            }}
          />

          {/* Mode selector */}
          <div style={{ fontSize: 9, color: 'var(--green-dim)', letterSpacing: 1, marginBottom: 10 }}>MODE D'ANALYSE</div>
          <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
            {(['discover', 'tokens', 'yaml'] as ScanMode[]).map(m => (
              <button
                key={m}
                onClick={() => setMode(m)}
                style={{
                  flex: 1, padding: '6px 4px', fontSize: 8,
                  background: mode === m ? '#031a10' : 'transparent',
                  border: `1px solid ${mode === m ? 'var(--green)' : 'var(--border)'}`,
                  color: mode === m ? 'var(--green)' : '#445566',
                  fontFamily: 'var(--font-title)', letterSpacing: 1, cursor: 'pointer',
                  transition: 'all 0.1s',
                }}
              >
                {MODE_INFO[m].label}
              </button>
            ))}
          </div>

          {/* Mode description */}
          <div style={{
            padding: '8px 10px', background: '#050e07', border: '1px solid #1a3a1a',
            fontSize: 9, color: '#445566', lineHeight: 1.6, marginBottom: 14,
          }}>
            {MODE_INFO[mode].desc}
          </div>

          {/* Mode-specific inputs */}
          {mode === 'tokens' && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 4 }}>TYPE</label>
                  <select
                    value={tokenType}
                    onChange={e => setTokenType(e.target.value as typeof tokenType)}
                    style={{
                      width: '100%', background: '#0d0d0d', border: '1px solid var(--border)',
                      color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 10,
                      padding: '5px 8px', outline: 'none',
                    }}
                  >
                    <option value="bearer">Bearer Token</option>
                    <option value="cookie">Cookie</option>
                    <option value="api_key">API Key</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 4 }}>RÔLE</label>
                  <input
                    value={roleName} onChange={e => setRoleName(e.target.value)}
                    placeholder="user"
                    style={{
                      width: '100%', boxSizing: 'border-box',
                      background: '#0d0d0d', border: '1px solid var(--border)',
                      color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 10,
                      padding: '5px 8px', outline: 'none',
                    }}
                  />
                </div>
              </div>
              <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 4 }}>VALEUR</label>
              <input
                value={tokenValue} onChange={e => setTokenValue(e.target.value)}
                placeholder={tokenType === 'bearer' ? 'eyJhbGciOi...' : tokenType === 'cookie' ? 'session=abc123' : 'sk-...'}
                style={{
                  width: '100%', boxSizing: 'border-box',
                  background: '#0d0d0d', border: '1px solid var(--border-hi)',
                  color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 10,
                  padding: '5px 8px', outline: 'none',
                }}
              />
            </div>
          )}

          {mode === 'yaml' && (
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 4 }}>CHEMIN DU FICHIER</label>
              <input
                value={yamlPath} onChange={e => setYamlPath(e.target.value)}
                placeholder="/home/user/.hdwp/contexts/mon-api.yaml"
                style={{
                  width: '100%', boxSizing: 'border-box',
                  background: '#0d0d0d', border: '1px solid var(--border-hi)',
                  color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 10,
                  padding: '5px 8px', outline: 'none',
                }}
              />
              <div style={{ fontSize: 8, color: '#2a4a2a', marginTop: 5 }}>
                Fichiers générés automatiquement dans ~/.hdwp/contexts/
              </div>
            </div>
          )}

          {error && (
            <div style={{ color: 'var(--red)', fontSize: 9, marginBottom: 10, letterSpacing: 0.5 }}>
              ⚠ {error}
            </div>
          )}

          <button
            onClick={handleLaunch}
            disabled={loading}
            style={{
              width: '100%', padding: '9px 0',
              background: 'transparent', border: '1px solid var(--green)',
              color: 'var(--green)', fontFamily: 'var(--font-title)', fontSize: 10,
              letterSpacing: 2, cursor: loading ? 'wait' : 'pointer', transition: 'all 0.12s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--green)'; e.currentTarget.style.color = '#020c0a' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--green)' }}
          >
            {loading ? '[ DÉMARRAGE… ]' : '[ LANCER L\'ANALYSE ]'}
          </button>
        </div>
      </div>
    </div>
  )
}
