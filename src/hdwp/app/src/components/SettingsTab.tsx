import { useEffect, useState } from 'react'
import { useLLMStore } from '../stores/llmStore'
import { useScanStore } from '../stores/scanStore'
import type { SessionMeta } from '../types/hdwp'

const SUB_TABS = [
  { id: 'llm', label: 'LLM' },
  { id: 'knowledge', label: 'Knowledge' },
  { id: 'sessions', label: 'Sessions' },
  { id: 'plugins', label: 'Plugins' },
]

function SubTabBar({ active, onChange }: { active: string; onChange(id: string): void }) {
  return (
    <div style={{
      display: 'flex', gap: 0, borderBottom: '1px solid var(--border)',
      background: '#010e08', flexShrink: 0,
    }}>
      {SUB_TABS.map(tab => {
        const isActive = active === tab.id
        return (
          <button key={tab.id} onClick={() => onChange(tab.id)} style={{
            padding: '5px 14px', fontSize: 9, letterSpacing: 1,
            color: isActive ? 'var(--green)' : '#2a4a2a',
            background: isActive ? '#031a10' : 'transparent',
            border: 'none', borderRight: '1px solid var(--border)',
            borderBottom: isActive ? '2px solid var(--green)' : '2px solid transparent',
            cursor: 'pointer', fontFamily: 'var(--font-title)',
          }}>
            {tab.label}
          </button>
        )
      })}
    </div>
  )
}

// ── Knowledge ─────────────────────────────────────────────────

interface KBPattern { property_type: string; mutation_type: string; target_type: string; confirmed: number; total: number; avg_confidence: number }
interface KBStats { session_count: number; patterns: KBPattern[] }
interface Divergence { base: number; adapted: number; divergence_pct: number; is_adapted: boolean }
interface LearningHealth {
  confidence_weights: Record<string, number>
  adapted_weights: Record<string, number>
  divergences: Record<string, Divergence>
  patterns: KBPattern[]
}

function ConfidenceBar({ label, value }: { label: string; value: number }) {
  const pct = Math.round(value * 100)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
      <div style={{ width: 40, fontSize: 8, color: '#445566', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</div>
      <div style={{ flex: 1, height: 6, background: '#111', border: '1px solid var(--border)', position: 'relative' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: pct > 60 ? '#00ff88' : pct > 30 ? '#ffaa00' : '#ff0066' }} />
      </div>
      <div style={{ width: 32, fontSize: 9, color: 'var(--text-hl)', textAlign: 'right' }}>{pct}%</div>
    </div>
  )
}

function KnowledgeSettings() {
  const [stats, setStats] = useState<KBStats | null>(null)
  const [health, setHealth] = useState<LearningHealth | null>(null)
  const [loading, setLoading] = useState(true)
  const [confirm, setConfirm] = useState(false)
  const [resetting, setResetting] = useState(false)

  const load = () => {
    setLoading(true)
    Promise.all([
      fetch('/api/knowledge/stats').then(r => r.ok ? r.json() : null),
      fetch('/api/knowledge/learning-health').then(r => r.ok ? r.json() : null),
    ])
      .then(([s, h]) => { setStats(s); setHealth(h) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const handleReset = async () => {
    setResetting(true)
    await fetch('/api/knowledge/reset', { method: 'POST' }).catch(() => {})
    setResetting(false)
    setConfirm(false)
    load()
  }

  if (loading) return (
    <div style={{ padding: '20px 24px', fontSize: 10, color: 'var(--green-dark)', letterSpacing: 1 }}>CHARGEMENT…</div>
  )

  return (
    <div style={{ padding: '12px 24px', maxWidth: 520 }}>
      <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 10 }}>── BASE DE CONNAISSANCES ──</div>

      <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
        <div style={{ textAlign: 'center', padding: '10px 18px', border: '1px solid var(--border)', background: '#060606' }}>
          <div style={{ fontFamily: 'var(--font-title)', fontSize: 22, color: 'var(--green)', marginBottom: 3 }}>
            {stats?.session_count ?? 0}
          </div>
          <div style={{ fontSize: 8, color: '#445566', letterSpacing: 1 }}>SESSIONS</div>
        </div>
        <div style={{ textAlign: 'center', padding: '10px 18px', border: '1px solid var(--border)', background: '#060606' }}>
          <div style={{ fontFamily: 'var(--font-title)', fontSize: 22, color: '#ffaa00', marginBottom: 3 }}>
            {stats?.patterns?.length ?? 0}
          </div>
          <div style={{ fontSize: 8, color: '#445566', letterSpacing: 1 }}>PATTERNS</div>
        </div>
      </div>

      {stats?.patterns && stats.patterns.length > 0 && (
        <>
          <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 6 }}>── STATISTIQUES PATTERNS ──</div>
          <div style={{ border: '1px solid var(--border)', overflow: 'hidden' }}>
            <div style={{ display: 'flex', padding: '4px 8px', background: '#010e08', fontSize: 8, color: '#445566', letterSpacing: 1 }}>
              <div style={{ flex: 2 }}>TYPE</div>
              <div style={{ flex: 2 }}>MUTATION</div>
              <div style={{ flex: 1, textAlign: 'right' }}>CONF.</div>
              <div style={{ flex: 1, textAlign: 'right' }}>MOY.</div>
            </div>
            {stats.patterns.map((p, i) => (
              <div key={i} style={{
                display: 'flex', padding: '5px 8px', fontSize: 9,
                background: i % 2 === 0 ? '#010e08' : 'transparent',
                borderTop: '1px solid var(--border)',
              }}>
                <div style={{ flex: 2, color: 'var(--text-hl)' }}>{p.property_type}</div>
                <div style={{ flex: 2, color: '#445566' }}>{p.mutation_type}</div>
                <div style={{ flex: 1, textAlign: 'right', color: p.confirmed > 0 ? '#ff0066' : '#445566' }}>
                  {p.confirmed}/{p.total}
                </div>
                <div style={{ flex: 1, textAlign: 'right', color: '#00ccff' }}>
                  {Math.round(p.avg_confidence * 100)}%
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {health && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 8 }}>
            {`── QUALITÉ DE L'APPRENTISSAGE ──`}
          </div>

          {(stats?.session_count ?? 0) < 5 && (
            <div style={{ fontSize: 9, color: '#ffaa00', marginBottom: 10, padding: '6px 10px', border: '1px solid #333', background: '#111' }}>
              5 sessions minimum pour adaptation ({stats?.session_count ?? 0}/5)
            </div>
          )}

          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 8, color: '#445566', letterSpacing: 1, marginBottom: 4 }}>POIDS CONFIANCE MODÈLE</div>
            <ConfidenceBar label="EP" value={health.confidence_weights.ep ?? 0.4} />
            <ConfidenceBar label="ROLE" value={health.confidence_weights.role ?? 0.4} />
            <ConfidenceBar label="BOLA" value={health.confidence_weights.bola ?? 0.2} />
          </div>

          {Object.entries(health.divergences).length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 8, color: '#445566', letterSpacing: 1, marginBottom: 4 }}>DIVERGENCES POIDS HYPOTHÈSES</div>
              {Object.entries(health.divergences).map(([key, d]) => (
                <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 9, marginBottom: 2 }}>
                  <span style={{ width: 100, color: 'var(--text-hl)' }}>{key}</span>
                  <span style={{ color: '#445566' }}>{d.base}</span>
                  <span style={{ color: '#445566' }}>&rarr;</span>
                  <span style={{ color: d.is_adapted ? '#00ccff' : '#445566' }}>{d.adapted}</span>
                  {d.is_adapted && (
                    <span style={{
                      fontSize: 7, padding: '1px 5px', letterSpacing: 1,
                      border: '1px solid #00ccff', color: '#00ccff',
                    }}>
                      ADAPTÉ
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{ marginTop: 16 }}>
        {!confirm ? (
          <button onClick={() => setConfirm(true)} style={{
            padding: '5px 14px', background: 'transparent',
            border: '1px solid #445566', color: '#445566',
            fontFamily: 'var(--font-title)', fontSize: 8, letterSpacing: 1, cursor: 'pointer',
          }}>
            [ RÉINITIALISER LA KB ]
          </button>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 9, color: '#ffaa00' }}>
            <span>Confirmer la réinitialisation ?</span>
            <button onClick={handleReset} disabled={resetting} style={{
              padding: '3px 10px', background: 'transparent', border: '1px solid #ff0066',
              color: '#ff0066', fontFamily: 'var(--font-title)', fontSize: 8, cursor: 'pointer',
            }}>
              {resetting ? '…' : 'OUI'}
            </button>
            <button onClick={() => setConfirm(false)} style={{
              padding: '3px 10px', background: 'transparent', border: '1px solid #445566',
              color: '#445566', fontFamily: 'var(--font-title)', fontSize: 8, cursor: 'pointer',
            }}>
              NON
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Sessions ──────────────────────────────────────────────────

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

function SessionsSettings({ onTabChange }: { onTabChange?: (tab: string) => void }) {
  const [sessions, setSessions] = useState<SessionMeta[]>([])
  const [loading, setLoading] = useState(true)
  const [resuming, setResuming] = useState<string | null>(null)
  const { setSessionId, setTarget, setStatus } = useScanStore()

  useEffect(() => {
    fetch('/api/sessions')
      .then(r => r.ok ? r.json() : [])
      .then(setSessions)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const handleResume = async (s: SessionMeta) => {
    setResuming(s.session_id)
    try {
      const r = await fetch(`/api/session/${s.session_id}/resume`, { method: 'POST' })
      if (!r.ok) return
      const data = await r.json() as { session_id: string; target_url: string; status: string }
      setSessionId(data.session_id)
      setTarget(data.target_url)
      setStatus(data.status === 'running' ? 'running' : data.status === 'done' ? 'done' : 'idle')
      onTabChange?.('scan')
    } catch { /* ignore */ }
    finally { setResuming(null) }
  }

  if (loading) return (
    <div style={{ padding: '20px 24px', fontSize: 10, color: 'var(--green-dark)', letterSpacing: 1 }}>CHARGEMENT…</div>
  )

  return (
    <div style={{ padding: '12px 24px', maxWidth: 660 }}>
      <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 10 }}>── HISTORIQUE DES SESSIONS ──</div>
      {sessions.length === 0 ? (
        <div style={{ fontSize: 10, color: '#445566', padding: '12px 0' }}>
          Aucune session enregistrée. Lancez une analyse depuis l'onglet Scan.
        </div>
      ) : (
        <div style={{ border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', padding: '4px 8px', background: '#010e08', fontSize: 8, color: '#445566', letterSpacing: 1 }}>
            <div style={{ flex: 3 }}>TARGET</div>
            <div style={{ flex: 1 }}>STATUT</div>
            <div style={{ flex: 1 }}>FINDINGS</div>
            <div style={{ flex: 2 }}>DATE</div>
            <div style={{ flex: 1 }} />
          </div>
          {sessions.map((s, i) => {
            const col = STATUS_COLORS[s.status] ?? '#445566'
            const shortUrl = s.target_url.replace(/^https?:\/\//, '').slice(0, 28)
            return (
              <div key={s.session_id} style={{
                display: 'flex', alignItems: 'center', padding: '6px 8px', fontSize: 9,
                background: i % 2 === 0 ? '#010e08' : 'transparent',
                borderTop: '1px solid var(--border)',
              }}>
                <div style={{ flex: 3, color: 'var(--text-hl)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{shortUrl}</div>
                <div style={{ flex: 1 }}>
                  <span style={{ color: col, fontSize: 8, letterSpacing: 0.5 }}>{s.status.toUpperCase()}</span>
                </div>
                <div style={{ flex: 1, color: s.findings_count > 0 ? '#ff0066' : '#445566' }}>
                  {s.findings_count}
                </div>
                <div style={{ flex: 2, color: '#445566' }}>{relativeDate(s.updated_at)}</div>
                <div style={{ flex: 1 }}>
                  <button
                    onClick={() => handleResume(s)}
                    disabled={resuming === s.session_id}
                    style={{
                      padding: '2px 8px', background: 'transparent',
                      border: `1px solid ${col}`, color: col,
                      fontFamily: 'var(--font-title)', fontSize: 7, cursor: 'pointer', letterSpacing: 1,
                    }}
                  >
                    {resuming === s.session_id ? '…' : 'REPRENDRE'}
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── LLM ───────────────────────────────────────────────────────

const PROVIDERS = [
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'openai', label: 'OpenAI' },
  { value: 'ollama', label: 'Ollama' },
]

const ENV_VAR_LABELS: Record<string, string> = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
}

function LLMSettings() {
  const {
    active, provider, model,
    models, modelsLoading, modelsError,
    apiKeys,
    fetchStatus, fetchModels, fetchApiKeys, saveApiKey,
  } = useLLMStore()

  const [enabled, setEnabled] = useState(active)
  const [prov, setProv] = useState(provider ?? 'anthropic')
  const [mdl, setMdl] = useState(model ?? '')
  const [baseUrl, setBaseUrl] = useState('http://localhost:11434/v1')
  const [apiKeyInput, setApiKeyInput] = useState('')
  const [savingKey, setSavingKey] = useState(false)
  const [keySaved, setKeySaved] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [manualModel, setManualModel] = useState(false)

  useEffect(() => { fetchStatus(); fetchApiKeys() }, [fetchStatus, fetchApiKeys])
  useEffect(() => { setEnabled(active); setProv(provider ?? 'anthropic'); setMdl(model ?? '') }, [active, provider, model])
  useEffect(() => { fetchModels(prov) }, [prov, fetchModels])
  useEffect(() => { if (modelsError) setManualModel(true); else setManualModel(false) }, [modelsError])

  const handleProviderChange = (newProv: string) => {
    setProv(newProv); setMdl(''); setApiKeyInput(''); setKeySaved(false); setManualModel(false)
  }

  const handleSaveKey = async () => {
    if (!apiKeyInput.trim()) return
    setSavingKey(true); setKeySaved(false)
    const ok = await saveApiKey(prov, apiKeyInput.trim())
    setSavingKey(false)
    if (ok) { setKeySaved(true); setApiKeyInput(''); setTimeout(() => setKeySaved(false), 3000) }
  }

  const handleSave = async () => {
    setSaving(true); setSaved(false)
    try {
      const r = await fetch('/api/llm/config', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, provider: prov, model: mdl, base_url: prov === 'ollama' ? baseUrl : null }),
      })
      if (r.ok) { setSaved(true); await fetchStatus(); setTimeout(() => setSaved(false), 2500) }
    } catch { /* ignore */ } finally { setSaving(false) }
  }

  const sectionLabel = (t: string) => (
    <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, margin: '16px 0 8px' }}>{`── ${t} ──`}</div>
  )

  const radio = (name: string, value: string, current: string, onChange: (v: string) => void, label: string) => (
    <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, cursor: 'pointer', marginRight: 16, color: current === value ? 'var(--green)' : 'var(--green-dark)', fontSize: 11 }}>
      <input type="radio" name={name} checked={current === value} onChange={() => onChange(value)} style={{ accentColor: 'var(--green)' }} />
      {label}
    </label>
  )

  const inputStyle: React.CSSProperties = {
    width: '100%', background: '#0d0d0d', border: '1px solid var(--border-hi)',
    color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '6px 10px', outline: 'none',
  }

  const keyStatus = apiKeys[prov]
  const needsKey = prov !== 'ollama'
  const envLabel = ENV_VAR_LABELS[prov] ?? ''

  return (
    <div style={{ padding: '12px 24px', maxWidth: 520, margin: '0 auto' }}>
      {sectionLabel('STATUT')}
      <div>
        {radio('status', 'on', enabled ? 'on' : 'off', v => setEnabled(v === 'on'), 'Activé')}
        {radio('status', 'off', enabled ? 'on' : 'off', v => setEnabled(v === 'on'), 'Désactivé')}
      </div>

      {sectionLabel('PROVIDER')}
      <div>{PROVIDERS.map(p => radio('prov', p.value, prov, handleProviderChange, p.label))}</div>

      {needsKey && (
        <>
          {sectionLabel('CLÉ API')}
          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 11, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', display: 'inline-block', background: keyStatus?.set ? 'var(--green)' : '#445566' }} />
              <span style={{ color: keyStatus?.set ? 'var(--green)' : '#445566' }}>
                {envLabel} {keyStatus?.set ? `détectée${keyStatus.masked ? ` (${keyStatus.masked})` : ''}` : 'absente'}
              </span>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input type="password" value={apiKeyInput} onChange={e => setApiKeyInput(e.target.value)}
                placeholder={`Entrer ${envLabel}`} onKeyDown={e => e.key === 'Enter' && handleSaveKey()}
                style={{ ...inputStyle, flex: 1 }} />
              <button onClick={handleSaveKey} disabled={savingKey || !apiKeyInput.trim()} style={{
                padding: '6px 12px', background: 'transparent', border: '1px solid var(--green-dark)',
                color: apiKeyInput.trim() ? 'var(--green)' : 'var(--green-dark)',
                fontFamily: 'var(--font-title)', fontSize: 8, letterSpacing: 1,
                cursor: savingKey || !apiKeyInput.trim() ? 'default' : 'pointer', whiteSpace: 'nowrap', flexShrink: 0,
              }}>
                {savingKey ? '...' : 'SAUVER'}
              </button>
            </div>
            {keySaved && <div style={{ fontSize: 10, color: 'var(--green)', marginTop: 4 }}>✓ Clé sauvegardée — modèles rechargés</div>}
          </div>
        </>
      )}

      {sectionLabel('MODÈLE')}
      {modelsLoading ? (
        <div style={{ fontSize: 10, color: 'var(--green-dim)', letterSpacing: 1, padding: '6px 0' }}>Chargement des modèles...</div>
      ) : manualModel ? (
        <>
          {modelsError && <div style={{ fontSize: 10, color: '#ffaa00', marginBottom: 6 }}>{modelsError}</div>}
          <input value={mdl} onChange={e => setMdl(e.target.value)} placeholder="Nom du modèle" style={inputStyle} />
        </>
      ) : models.length > 0 ? (
        <select value={mdl} onChange={e => setMdl(e.target.value)} style={{ ...inputStyle, appearance: 'none', cursor: 'pointer' }}>
          <option value="" style={{ background: '#0d0d0d', color: '#445566' }}>— Sélectionner un modèle —</option>
          {models.map(m => <option key={m} value={m} style={{ background: '#0d0d0d', color: 'var(--text-hl)' }}>{m}</option>)}
        </select>
      ) : (
        <div style={{ fontSize: 10, color: '#445566', padding: '6px 0' }}>
          {needsKey && !keyStatus?.set ? 'Entrez une clé API pour charger les modèles disponibles' : 'Aucun modèle disponible'}
        </div>
      )}

      {prov === 'ollama' && (
        <>{sectionLabel('BASE URL')}<input value={baseUrl} onChange={e => setBaseUrl(e.target.value)} style={inputStyle} /></>
      )}

      <div style={{ marginTop: 20, display: 'flex', alignItems: 'center', gap: 14 }}>
        <button onClick={handleSave} disabled={saving || !mdl} style={{
          padding: '8px 24px', background: 'transparent',
          border: `1px solid ${!mdl ? 'var(--green-dark)' : 'var(--green)'}`,
          color: !mdl ? 'var(--green-dark)' : 'var(--green)',
          fontFamily: 'var(--font-title)', fontSize: 10, letterSpacing: 2,
          cursor: saving || !mdl ? 'default' : 'pointer',
        }}
          onMouseEnter={e => { if (mdl) { e.currentTarget.style.background = 'var(--green)'; e.currentTarget.style.color = '#020c0a' } }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = mdl ? 'var(--green)' : 'var(--green-dark)' }}
        >
          {saving ? '[ SAUVEGARDE... ]' : '[ SAUVEGARDER ]'}
        </button>
        {saved && <span style={{ fontSize: 10, color: 'var(--green)' }}>✓ Configuration sauvegardée</span>}
      </div>
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────

export function SettingsTab({ onTabChange }: { onTabChange?: (tab: string) => void }) {
  const [subTab, setSubTab] = useState('llm')

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <SubTabBar active={subTab} onChange={setSubTab} />
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {subTab === 'llm' && <LLMSettings />}
        {subTab === 'knowledge' && <KnowledgeSettings />}
        {subTab === 'sessions' && <SessionsSettings onTabChange={onTabChange} />}
        {subTab === 'plugins' && (
          <div style={{ padding: '24px' }}>
            <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 12 }}>── PLUGINS ──</div>
            <div style={{ fontSize: 10, color: '#445566', marginBottom: 16 }}>
              La gestion des plugins (activation, création) est disponible dans l'onglet dédié.
            </div>
            <button onClick={() => onTabChange?.('plugins')} style={{
              padding: '7px 18px', background: 'transparent', border: '1px solid var(--green)',
              color: 'var(--green)', fontFamily: 'var(--font-title)', fontSize: 9, letterSpacing: 2, cursor: 'pointer',
            }}>
              [ → ALLER À PLUGINS ]
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
