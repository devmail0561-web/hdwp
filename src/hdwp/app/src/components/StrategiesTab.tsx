import { useEffect, useRef, useState } from 'react'
import { useStrategiesStore } from '../stores/strategiesStore'
import type { Strategy } from '../types/hdwp'

const PROOF_COLORS: Record<string, string> = {
  network: '#00ff88',
  contextual: '#00ccff',
  payload: '#ffaa00',
  passive_dispatch: '#445566',
}

function proofColor(pt: string) {
  return PROOF_COLORS[pt] ?? '#445566'
}

function ScaffoldModal({ onClose, onCreated, knownVulnTypes, knownProofTypes }: {
  onClose: () => void
  onCreated: (path: string) => void
  knownVulnTypes: string[]
  knownProofTypes: string[]
}) {
  const [name, setName] = useState('')
  const [id, setId] = useState('user.')
  const [vulnType, setVulnType] = useState(knownVulnTypes[0] ?? '')
  const [customVulnType, setCustomVulnType] = useState('')
  const [proofType, setProofType] = useState(knownProofTypes[0] ?? '')
  const [customProofType, setCustomProofType] = useState('')
  const [description, setDescription] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const nameRef = useRef<HTMLInputElement>(null)

  useEffect(() => { nameRef.current?.focus() }, [])

  const handleNameChange = (v: string) => {
    const slug = v.toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^_+/, '')
    setName(slug)
    setId(`user.${slug}`)
  }

  const resolvedVulnType = vulnType === '__custom__' ? customVulnType : vulnType
  const resolvedProofType = proofType === '__custom__' ? customProofType : proofType

  const handleCreate = async () => {
    if (!name) { setError('Nom requis'); return }
    if (!id.startsWith('user.') || id === 'user.') { setError("L'ID doit commencer par 'user.' suivi d'un nom"); return }
    if (!resolvedVulnType) { setError('vuln_type requis'); return }
    setError('')
    setLoading(true)
    try {
      const r = await fetch('/api/strategies/scaffold', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, id, vuln_type: resolvedVulnType, proof_type: resolvedProofType, description }),
      })
      if (!r.ok) {
        const txt = await r.text()
        setError(txt.includes('existe') ? `Stratégie '${id}' existe déjà` : txt.slice(0, 100))
        return
      }
      const { path } = await r.json() as { path: string }
      onCreated(path)
    } catch (e) { setError(String(e)) }
    finally { setLoading(false) }
  }

  const inputStyle: React.CSSProperties = {
    width: '100%', boxSizing: 'border-box',
    background: '#0d0d0d', border: '1px solid var(--border)',
    color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 10,
    padding: '5px 8px', outline: 'none',
  }
  const selectStyle: React.CSSProperties = { ...inputStyle }

  return (
    <div style={{
      position: 'absolute', inset: 0, zIndex: 20,
      background: '#020c0aee', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 400, background: 'var(--bg-panel)',
        border: '1px solid var(--border-hi)', padding: '20px 24px',
      }}>
        <div style={{ fontFamily: 'var(--font-title)', fontSize: 11, color: 'var(--green)', letterSpacing: 2, marginBottom: 16 }}>
          <span style={{ color: 'var(--green)' }}>[ </span>NOUVELLE STRATÉGIE<span style={{ color: 'var(--green)' }}> ]</span>
        </div>

        {[
          { label: 'NOM (snake_case)', val: name, set: handleNameChange, placeholder: 'sqli_time_based', ref: nameRef },
          { label: 'ID', val: id, set: setId, placeholder: 'user.sqli_time_based' },
        ].map(({ label, val, set, placeholder, ref }) => (
          <div key={label} style={{ marginBottom: 10 }}>
            <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 3 }}>{label}</label>
            <input ref={ref} value={val} onChange={e => set(e.target.value)} placeholder={placeholder} style={inputStyle} />
          </div>
        ))}

        <div style={{ marginBottom: 10 }}>
          <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 3 }}>VULN_TYPE</label>
          <select value={vulnType} onChange={e => setVulnType(e.target.value)} style={selectStyle}>
            {knownVulnTypes.map(vt => <option key={vt} value={vt}>{vt}</option>)}
            <option value="__custom__">-- personnalisé --</option>
          </select>
          {vulnType === '__custom__' && (
            <input
              value={customVulnType} onChange={e => setCustomVulnType(e.target.value)}
              placeholder="nouveau_type"
              style={{ ...inputStyle, marginTop: 4 }}
            />
          )}
        </div>

        <div style={{ marginBottom: 10 }}>
          <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 3 }}>PROOF TYPE</label>
          <select value={proofType} onChange={e => setProofType(e.target.value)} style={selectStyle}>
            {knownProofTypes.map(pt => <option key={pt} value={pt}>{pt}</option>)}
            <option value="__custom__">-- personnalisé --</option>
          </select>
          {proofType === '__custom__' && (
            <input
              value={customProofType} onChange={e => setCustomProofType(e.target.value)}
              placeholder="nouveau_proof_type"
              style={{ ...inputStyle, marginTop: 4 }}
            />
          )}
        </div>

        <div style={{ marginBottom: 14 }}>
          <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 3 }}>DESCRIPTION</label>
          <input value={description} onChange={e => setDescription(e.target.value)}
            placeholder="Cette stratégie exploite..."
            style={inputStyle}
          />
        </div>

        {error && <div style={{ color: 'var(--red)', fontSize: 9, marginBottom: 10 }}>⚠ {error}</div>}

        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={handleCreate} disabled={loading} style={{
            flex: 1, padding: '7px 0', background: 'transparent',
            border: '1px solid var(--green)', color: 'var(--green)',
            fontFamily: 'var(--font-title)', fontSize: 9, letterSpacing: 2, cursor: loading ? 'wait' : 'pointer',
          }}>
            {loading ? '…' : '[ CRÉER ]'}
          </button>
          <button onClick={onClose} style={{
            flex: 1, padding: '7px 0', background: 'transparent',
            border: '1px solid var(--border)', color: '#445566',
            fontFamily: 'var(--font-title)', fontSize: 9, letterSpacing: 2, cursor: 'pointer',
          }}>
            [ ANNULER ]
          </button>
        </div>
      </div>
    </div>
  )
}

function SuccessPanel({ path, onClose }: { path: string; onClose: () => void }) {
  return (
    <div style={{
      position: 'absolute', inset: 0, zIndex: 20,
      background: '#020c0aee', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{ width: 420, background: 'var(--bg-panel)', border: '1px solid var(--border-hi)', padding: '20px 24px' }}>
        <div style={{ fontFamily: 'var(--font-title)', fontSize: 11, color: '#00ff88', letterSpacing: 2, marginBottom: 14 }}>
          ✓ STRATÉGIE CRÉÉE
        </div>
        <div style={{ fontSize: 9, color: 'var(--green-dim)', marginBottom: 8 }}>Fichier généré :</div>
        <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-hl)', wordBreak: 'break-all', padding: '6px 8px', background: '#0a0a0a', border: '1px solid var(--border)', marginBottom: 14 }}>
          {path}
        </div>
        <div style={{ fontSize: 9, color: '#445566', marginBottom: 16 }}>
          Éditez ce fichier YAML dans votre éditeur, puis cliquez <strong style={{ color: 'var(--green-dim)' }}>RELOAD</strong> pour charger la stratégie.
        </div>
        <button onClick={onClose} style={{
          width: '100%', padding: '7px 0', background: 'transparent',
          border: '1px solid var(--green)', color: 'var(--green)',
          fontFamily: 'var(--font-title)', fontSize: 9, letterSpacing: 2, cursor: 'pointer',
        }}>
          [ FERMER ]
        </button>
      </div>
    </div>
  )
}

function StrategyDetail({ strategy, onToggle }: { strategy: Strategy; onToggle: () => void }) {
  return (
    <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 10, overflowY: 'auto', flex: 1 }}>
      <div>
        <div style={{ fontFamily: 'var(--font-title)', fontSize: 13, color: strategy.enabled ? '#00ff88' : '#445566', letterSpacing: 1, marginBottom: 3 }}>
          {strategy.name}
        </div>
        <div style={{ fontSize: 9, color: '#445566', letterSpacing: 1 }}>{strategy.id}</div>
      </div>

      <button
        onClick={onToggle}
        style={{
          alignSelf: 'flex-start', background: 'transparent',
          border: `1px solid ${strategy.enabled ? '#ff0066' : '#00ff88'}`,
          color: strategy.enabled ? '#ff0066' : '#00ff88',
          fontFamily: 'var(--font-title)', fontSize: 9, letterSpacing: 2,
          padding: '4px 12px', cursor: 'pointer',
        }}
      >
        {strategy.enabled ? '[ DÉSACTIVER ]' : '[ ACTIVER ]'}
      </button>

      {[
        { label: 'VULN_TYPE', value: strategy.vuln_type, color: '#ff4400' },
        { label: 'PROOF TYPE', value: strategy.proof_type, color: proofColor(strategy.proof_type) },
        { label: 'SOURCE', value: strategy.source === 'user' ? 'USER' : strategy.source === 'package' ? 'PACKAGE' : 'BUILTIN', color: strategy.source === 'user' ? '#ffd700' : '#445566' },
        { label: 'PHASES', value: String(strategy.phases_count), color: 'var(--text-hl)' },
      ].map(({ label, value, color }) => (
        <div key={label}>
          <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 2 }}>{label}</div>
          <div style={{ fontSize: 10, color }}>{value}</div>
        </div>
      ))}

      {strategy.description && (
        <div>
          <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 2 }}>DESCRIPTION</div>
          <div style={{ fontSize: 10, color: 'var(--green-dim)', lineHeight: 1.5 }}>{strategy.description}</div>
        </div>
      )}

      {strategy.tech_stack.length > 0 && (
        <div>
          <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 4 }}>TECH STACK</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {strategy.tech_stack.map(t => (
              <span key={t} style={{ fontSize: 8, padding: '2px 6px', border: '1px solid #00ccff', color: '#00ccff', letterSpacing: 1 }}>{t}</span>
            ))}
          </div>
        </div>
      )}

      {Object.keys(strategy.params).length > 0 && (
        <div>
          <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 4 }}>PARAMS</div>
          {Object.entries(strategy.params).map(([k, v]) => (
            <div key={k} style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: '#445566' }}>
              <span style={{ color: 'var(--green-dim)' }}>{k}</span>: {String(v)}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function StrategiesTab() {
  const { strategies, loading, fetchStrategies, toggleStrategy } = useStrategiesStore()
  const [selected, setSelected] = useState<Strategy | null>(null)
  const [showScaffold, setShowScaffold] = useState(false)
  const [createdPath, setCreatedPath] = useState<string | null>(null)
  const [reloading, setReloading] = useState(false)

  useEffect(() => { fetchStrategies() }, [fetchStrategies])

  useEffect(() => {
    if (selected) {
      const updated = strategies.find(s => s.id === selected.id)
      if (updated) setSelected(updated)
    }
  }, [strategies])

  const knownVulnTypes = [...new Set(strategies.map(s => s.vuln_type))].sort()
  const knownProofTypes = [...new Set(strategies.map(s => s.proof_type))].sort()

  const handleReload = async () => {
    setReloading(true)
    try {
      await fetch('/api/strategies/reload', { method: 'POST' })
      await fetchStrategies()
    } finally {
      setReloading(false)
    }
  }

  const handleToggle = async (strategyId: string) => {
    await toggleStrategy(strategyId)
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>
      {showScaffold && (
        <ScaffoldModal
          onClose={() => setShowScaffold(false)}
          onCreated={path => { setShowScaffold(false); setCreatedPath(path) }}
          knownVulnTypes={knownVulnTypes}
          knownProofTypes={knownProofTypes}
        />
      )}
      {createdPath && (
        <SuccessPanel path={createdPath} onClose={() => { setCreatedPath(null); fetchStrategies() }} />
      )}

      <div style={{
        fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)',
        letterSpacing: 2, padding: '7px 10px 5px',
        borderBottom: '1px solid var(--border)', background: '#060606', flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <span>
          <span style={{ color: 'var(--green)' }}>[ </span>STRATÉGIES ({strategies.length})<span style={{ color: 'var(--green)' }}> ]</span>
        </span>
        <div style={{ display: 'flex', gap: 5 }}>
          <button onClick={() => setShowScaffold(true)} style={{
            background: 'transparent', border: '1px solid var(--green)',
            color: 'var(--green)', fontFamily: 'var(--font-title)',
            fontSize: 7, padding: '2px 8px', cursor: 'pointer', letterSpacing: 1,
          }}>+ NOUVEAU</button>
          <button onClick={handleReload} disabled={reloading} style={{
            background: 'transparent', border: '1px solid var(--border)',
            color: 'var(--green-dark)', fontFamily: 'var(--font-title)',
            fontSize: 7, padding: '2px 8px', cursor: reloading ? 'wait' : 'pointer', letterSpacing: 1,
          }}>{reloading ? '…' : '↺ RELOAD'}</button>
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ width: '45%', borderRight: '1px solid var(--border)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{
            display: 'flex', padding: '5px 10px',
            borderBottom: '1px solid var(--border)', background: '#010e08', flexShrink: 0,
          }}>
            {([['STRATÉGIE', 3], ['TYPE', 1], ['STATUT', 1]] as [string, number][]).map(([label, flex]) => (
              <div key={label} style={{ flex, fontSize: 7, color: '#445566', letterSpacing: 1 }}>{label}</div>
            ))}
          </div>

          <div style={{ flex: 1, overflowY: 'auto' }}>
            {loading && strategies.length === 0 && (
              <div style={{ padding: 16, color: 'var(--green-dark)', fontSize: 10, textAlign: 'center', letterSpacing: 1 }}>
                CHARGEMENT...
              </div>
            )}
            {!loading && strategies.length === 0 && (
              <div style={{ padding: 16, color: '#445566', fontSize: 10, textAlign: 'center', letterSpacing: 1 }}>
                Aucune stratégie disponible
              </div>
            )}
            {strategies.map(s => {
              const isSelected = selected?.id === s.id
              return (
                <div
                  key={s.id}
                  onClick={() => setSelected(s)}
                  style={{
                    display: 'flex', alignItems: 'center',
                    padding: '5px 10px', cursor: 'pointer',
                    borderBottom: '1px solid var(--border)',
                    borderLeft: isSelected ? '2px solid var(--green)' : '2px solid transparent',
                    background: isSelected ? '#0a1a10' : 'transparent',
                  }}
                >
                  <div style={{ flex: 3, overflow: 'hidden' }}>
                    <div style={{ fontSize: 10, color: s.enabled ? 'var(--text-hl)' : '#445566', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {s.name}
                    </div>
                    <div style={{ fontSize: 8, color: '#445566', letterSpacing: 1 }}>{s.source === 'user' ? 'USER' : 'BUILTIN'}</div>
                  </div>
                  <div style={{ flex: 1 }}>
                    <span style={{ fontSize: 8, color: proofColor(s.proof_type), letterSpacing: 1 }}>{s.vuln_type}</span>
                  </div>
                  <div style={{ flex: 1 }}>
                    <span style={{ fontSize: 8, color: s.enabled ? '#00ff88' : '#445566', letterSpacing: 1 }}>
                      {s.enabled ? 'ON' : 'OFF'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {selected ? (
            <StrategyDetail strategy={selected} onToggle={() => handleToggle(selected.id)} />
          ) : (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#445566', fontSize: 10, letterSpacing: 1 }}>
              Sélectionnez une stratégie
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
