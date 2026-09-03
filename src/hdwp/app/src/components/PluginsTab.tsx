import { useEffect, useRef, useState } from 'react'
import { usePluginsStore } from '../stores/pluginsStore'
import type { Plugin } from '../types/hdwp'

const CATEGORIES = ['authorization', 'information_flow', 'injection', 'session_property', 'configuration', 'concurrency', 'state_transition', 'temporal', 'business_invariant']

function ScaffoldModal({ onClose, onCreated }: { onClose: () => void; onCreated: (path: string) => void }) {
  const [name, setName] = useState('')
  const [id, setId] = useState('user.')
  const [category, setCategory] = useState('authorization')
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

  const handleCreate = async () => {
    if (!name) { setError('Nom requis'); return }
    if (!id.startsWith('user.') || id === 'user.') { setError("L'ID doit commencer par 'user.' suivi d'un nom"); return }
    setError('')
    setLoading(true)
    try {
      const r = await fetch('/api/plugins/scaffold', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, id, category, description }),
      })
      if (!r.ok) {
        const txt = await r.text()
        setError(txt.includes('existe') ? `Plugin '${name}' existe déjà` : txt.slice(0, 80))
        return
      }
      const { path } = await r.json() as { path: string }
      onCreated(path)
    } catch (e) { setError(String(e)) }
    finally { setLoading(false) }
  }

  return (
    <div style={{
      position: 'absolute', inset: 0, zIndex: 20,
      background: '#020c0aee', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 380, background: 'var(--bg-panel)',
        border: '1px solid var(--border-hi)', padding: '20px 24px',
      }}>
        <div style={{ fontFamily: 'var(--font-title)', fontSize: 11, color: 'var(--green)', letterSpacing: 2, marginBottom: 16 }}>
          <span style={{ color: 'var(--green)' }}>[ </span>NOUVEAU PLUGIN<span style={{ color: 'var(--green)' }}> ]</span>
        </div>

        {[
          { label: 'NOM (snake_case)', val: name, set: handleNameChange, placeholder: 'rate_limit_bypass' },
          { label: 'ID', val: id, set: setId, placeholder: 'user.rate_limit_bypass' },
        ].map(({ label, val, set, placeholder }) => (
          <div key={label} style={{ marginBottom: 10 }}>
            <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 3 }}>{label}</label>
            <input
              ref={label.startsWith('NOM') ? nameRef : undefined}
              value={val} onChange={e => set(e.target.value)}
              placeholder={placeholder}
              style={{
                width: '100%', boxSizing: 'border-box',
                background: '#0d0d0d', border: '1px solid var(--border)',
                color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 10,
                padding: '5px 8px', outline: 'none',
              }}
            />
          </div>
        ))}

        <div style={{ marginBottom: 10 }}>
          <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 3 }}>CATÉGORIE</label>
          <select value={category} onChange={e => setCategory(e.target.value)} style={{
            width: '100%', background: '#0d0d0d', border: '1px solid var(--border)',
            color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 10,
            padding: '5px 8px', outline: 'none',
          }}>
            {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>

        <div style={{ marginBottom: 14 }}>
          <label style={{ fontSize: 8, color: 'var(--green-dim)', letterSpacing: 1, display: 'block', marginBottom: 3 }}>DESCRIPTION</label>
          <input value={description} onChange={e => setDescription(e.target.value)}
            placeholder="Ce plugin détecte..."
            style={{
              width: '100%', boxSizing: 'border-box',
              background: '#0d0d0d', border: '1px solid var(--border)',
              color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', fontSize: 10,
              padding: '5px 8px', outline: 'none',
            }}
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
      <div style={{ width: 400, background: 'var(--bg-panel)', border: '1px solid var(--border-hi)', padding: '20px 24px' }}>
        <div style={{ fontFamily: 'var(--font-title)', fontSize: 11, color: '#00ff88', letterSpacing: 2, marginBottom: 14 }}>
          ✓ PLUGIN CRÉÉ
        </div>
        <div style={{ fontSize: 9, color: 'var(--green-dim)', marginBottom: 8 }}>Fichier généré :</div>
        <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-hl)', wordBreak: 'break-all', padding: '6px 8px', background: '#0a0a0a', border: '1px solid var(--border)', marginBottom: 14 }}>
          {path}
        </div>
        <div style={{ fontSize: 9, color: '#445566', marginBottom: 16 }}>
          Éditez ce fichier dans votre éditeur, puis cliquez <strong style={{ color: 'var(--green-dim)' }}>RELOAD</strong> pour charger le plugin.
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

const CAT_COLORS: Record<string, string> = {
  authorization: '#ff0066',
  information_flow: '#ffaa00',
  injection: '#ff4400',
  session_property: '#00ccff',
  configuration: '#9966ff',
  concurrency: '#44ff88',
  state_transition: '#ffd700',
  temporal: '#00aaff',
  business_invariant: '#ff8c00',
}

function catColor(cat: string) {
  return CAT_COLORS[cat] ?? '#445566'
}

function PluginDetail({ plugin, onToggle }: { plugin: Plugin; onToggle: () => void }) {
  return (
    <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 10, overflowY: 'auto', flex: 1 }}>
      {/* Header */}
      <div>
        <div style={{ fontFamily: 'var(--font-title)', fontSize: 13, color: plugin.enabled ? '#00ff88' : '#445566', letterSpacing: 1, marginBottom: 3 }}>
          {plugin.name}
        </div>
        <div style={{ fontSize: 9, color: '#445566', letterSpacing: 1 }}>{plugin.id}</div>
      </div>

      {/* Toggle */}
      <button
        onClick={onToggle}
        style={{
          alignSelf: 'flex-start', background: 'transparent',
          border: `1px solid ${plugin.enabled ? '#ff0066' : '#00ff88'}`,
          color: plugin.enabled ? '#ff0066' : '#00ff88',
          fontFamily: 'var(--font-title)', fontSize: 9, letterSpacing: 2,
          padding: '4px 12px', cursor: 'pointer',
        }}
      >
        {plugin.enabled ? '[ DÉSACTIVER ]' : '[ ACTIVER ]'}
      </button>

      {/* Fields */}
      {[
        { label: 'VERSION', value: plugin.version, color: 'var(--text-hl)' },
        { label: 'CATÉGORIE', value: plugin.category, color: catColor(plugin.category) },
        { label: 'SOURCE', value: plugin.source === 'user' ? 'USER' : 'BUILTIN', color: plugin.source === 'user' ? '#ffd700' : '#445566' },
        { label: 'DATA ACCESS', value: plugin.data_access, color: '#9966ff' },
      ].map(({ label, value, color }) => (
        <div key={label}>
          <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 2 }}>{label}</div>
          <div style={{ fontSize: 10, color }}>{value}</div>
        </div>
      ))}

      {plugin.description && (
        <div>
          <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 2 }}>DESCRIPTION</div>
          <div style={{ fontSize: 10, color: 'var(--green-dim)', lineHeight: 1.5 }}>{plugin.description}</div>
        </div>
      )}

      {plugin.owasp_mapping.length > 0 && (
        <div>
          <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 4 }}>OWASP</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {plugin.owasp_mapping.map(o => (
              <span key={o} style={{
                fontSize: 8, padding: '2px 6px',
                border: '1px solid #ff0066', color: '#ff0066', letterSpacing: 1,
              }}>{o}</span>
            ))}
          </div>
        </div>
      )}

      {plugin.cwe_mapping.length > 0 && (
        <div>
          <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 4 }}>CWE</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {plugin.cwe_mapping.map(c => (
              <span key={c} style={{
                fontSize: 8, padding: '2px 6px',
                border: '1px solid #ffaa00', color: '#ffaa00', letterSpacing: 1,
              }}>{c}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function PluginsTab() {
  const { plugins, loading, fetchPlugins, togglePlugin } = usePluginsStore()
  const [selected, setSelected] = useState<Plugin | null>(null)
  const [showScaffold, setShowScaffold] = useState(false)
  const [createdPath, setCreatedPath] = useState<string | null>(null)
  const [reloading, setReloading] = useState(false)

  useEffect(() => { fetchPlugins() }, [fetchPlugins])

  useEffect(() => {
    if (selected) {
      const updated = plugins.find(p => p.id === selected.id)
      if (updated) setSelected(updated)
    }
  }, [plugins])

  const handleReload = async () => {
    setReloading(true)
    try {
      await fetch('/api/plugins/reload', { method: 'POST' })
      await fetchPlugins()
    } finally {
      setReloading(false)
    }
  }

  const handleCreated = (path: string) => {
    setShowScaffold(false)
    setCreatedPath(path)
  }

  const handleToggle = async (pluginId: string) => {
    await togglePlugin(pluginId)
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>
      {/* Modals */}
      {showScaffold && <ScaffoldModal onClose={() => setShowScaffold(false)} onCreated={handleCreated} />}
      {createdPath && <SuccessPanel path={createdPath} onClose={() => { setCreatedPath(null); fetchPlugins() }} />}

      {/* Header */}
      <div style={{
        fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)',
        letterSpacing: 2, padding: '7px 10px 5px',
        borderBottom: '1px solid var(--border)', background: '#060606', flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <span>
          <span style={{ color: 'var(--green)' }}>[ </span>PLUGINS ({plugins.length})<span style={{ color: 'var(--green)' }}> ]</span>
        </span>
        <div style={{ display: 'flex', gap: 5 }}>
          <button
            onClick={() => setShowScaffold(true)}
            style={{
              background: 'transparent', border: '1px solid var(--green)',
              color: 'var(--green)', fontFamily: 'var(--font-title)',
              fontSize: 7, padding: '2px 8px', cursor: 'pointer', letterSpacing: 1,
            }}
          >+ NOUVEAU</button>
          <button
            onClick={handleReload}
            disabled={reloading}
            style={{
              background: 'transparent', border: '1px solid var(--border)',
              color: 'var(--green-dark)', fontFamily: 'var(--font-title)',
              fontSize: 7, padding: '2px 8px', cursor: reloading ? 'wait' : 'pointer', letterSpacing: 1,
            }}
          >{reloading ? '…' : '↺ RELOAD'}</button>
        </div>
      </div>

      {/* Body: list + detail */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* List */}
        <div style={{ width: '45%', borderRight: '1px solid var(--border)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Col headers */}
          <div style={{
            display: 'flex', padding: '5px 10px',
            borderBottom: '1px solid var(--border)', background: '#010e08', flexShrink: 0,
          }}>
            {[['PLUGIN', 3], ['CAT.', 1], ['STATUT', 1]] .map(([label, flex]) => (
              <div key={label as string} style={{ flex: flex as number, fontSize: 7, color: '#445566', letterSpacing: 1 }}>
                {label}
              </div>
            ))}
          </div>

          {/* Rows */}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {loading && plugins.length === 0 && (
              <div style={{ padding: 16, color: 'var(--green-dark)', fontSize: 10, textAlign: 'center', letterSpacing: 1 }}>
                CHARGEMENT...
              </div>
            )}
            {!loading && plugins.length === 0 && (
              <div style={{ padding: 16, color: '#445566', fontSize: 10, textAlign: 'center', letterSpacing: 1 }}>
                Aucun plugin disponible
              </div>
            )}
            {plugins.map((p, i) => {
              const isSelected = selected?.id === p.id
              const cc = catColor(p.category)
              return (
                <div
                  key={p.id}
                  onClick={() => setSelected(p)}
                  style={{
                    display: 'flex', alignItems: 'center',
                    padding: '5px 10px', cursor: 'pointer',
                    borderBottom: '1px solid var(--border)',
                    borderLeft: isSelected ? '2px solid var(--green)' : '2px solid transparent',
                    background: isSelected ? '#031a0e' : i % 2 === 0 ? '#010e08' : 'transparent',
                    transition: 'background 0.1s',
                  }}
                  onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = '#0a1a12' }}
                  onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = i % 2 === 0 ? '#010e08' : 'transparent' }}
                >
                  {/* Name */}
                  <div style={{ flex: 3, fontSize: 9, color: p.enabled ? '#00ff88' : '#445566', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {p.name}
                  </div>
                  {/* Category dot */}
                  <div style={{ flex: 1 }}>
                    <span style={{ fontSize: 7, color: cc, letterSpacing: 0.5 }}>{p.category.slice(0, 6)}</span>
                  </div>
                  {/* Toggle */}
                  <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <button
                      onClick={e => { e.stopPropagation(); handleToggle(p.id) }}
                      style={{
                        background: p.enabled ? '#00ff8820' : 'transparent',
                        border: `1px solid ${p.enabled ? '#00ff88' : '#445566'}`,
                        color: p.enabled ? '#00ff88' : '#445566',
                        fontFamily: 'var(--font-title)', fontSize: 7,
                        padding: '1px 5px', cursor: 'pointer', letterSpacing: 1,
                        minWidth: 28,
                      }}
                    >
                      {p.enabled ? 'ON' : 'OFF'}
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Detail panel */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#010e08' }}>
          {selected ? (
            <PluginDetail
              plugin={selected}
              onToggle={() => handleToggle(selected.id)}
            />
          ) : (
            <div style={{
              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: '#2a4a2a', fontSize: 10, letterSpacing: 2,
            }}>
              ← SÉLECTIONNER UN PLUGIN
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
