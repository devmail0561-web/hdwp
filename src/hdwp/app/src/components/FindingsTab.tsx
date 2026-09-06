import { useEffect, useState } from 'react'
import { useFindingsStore } from '../stores/findingsStore'
import { useScanStore } from '../stores/scanStore'
import type { Finding } from '../types/hdwp'

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ff0066', HIGH: '#ff0066', MEDIUM: '#ffaa00', LOW: '#00ccff', INFO: '#445566',
}

function SeverityBar({ severity }: { severity: string }) {
  const color = SEV_COLORS[severity] ?? '#445566'
  const filled = severity === 'CRITICAL' ? 4 : severity === 'HIGH' ? 4 : severity === 'MEDIUM' ? 3 : severity === 'LOW' ? 2 : 1
  return (
    <span style={{ display: 'inline-flex', gap: 1 }}>
      {[0, 1, 2, 3].map(i => (
        <span key={i} style={{
          width: 6, height: 10, display: 'inline-block',
          background: i < filled ? color : '#1a1a1a',
        }} />
      ))}
    </span>
  )
}

function SectionHeader({ title }: { title: string }) {
  return (
    <div style={{
      fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)',
      letterSpacing: 2, padding: '7px 10px 5px',
      borderBottom: '1px solid var(--border)', background: '#060606',
    }}>
      <span style={{ color: 'var(--green)' }}>[ </span>{title}<span style={{ color: 'var(--green)' }}> ]</span>
    </div>
  )
}

function DetailRow({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ display: 'flex', gap: 10, padding: '3px 0', fontSize: 10 }}>
      <span style={{ color: 'var(--green-dark)', width: 80, flexShrink: 0, letterSpacing: 1, fontSize: 9 }}>{label}</span>
      <span style={{ color: color ?? 'var(--text-hl)', wordBreak: 'break-all' }}>{value}</span>
    </div>
  )
}

function FindingListItem({ finding, selected, onClick }: {
  finding: Finding; selected: boolean; onClick: () => void
}) {
  const sevColor = SEV_COLORS[finding.severity] ?? '#445566'
  return (
    <div
      onClick={onClick}
      style={{
        padding: '6px 8px', cursor: 'pointer',
        borderLeft: selected ? `3px solid ${sevColor}` : '3px solid transparent',
        background: selected ? '#0d1a0d' : 'transparent',
        borderBottom: '1px solid var(--border)',
        transition: 'background 0.1s',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
        <span style={{
          fontSize: 9, color: selected ? sevColor : '#445566', letterSpacing: 1,
          fontWeight: selected ? 'bold' : 'normal',
        }}>
          {selected ? '▶ ' : '  '}{finding.id}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10 }}>
        <SeverityBar severity={finding.severity} />
        <span style={{ color: sevColor, fontWeight: 'bold', fontSize: 9 }}>{finding.severity}</span>
        <span style={{ color: '#445566', fontSize: 9 }}>{finding.owasp_category}</span>
        <span style={{ marginLeft: 'auto', color: '#44ff88', fontSize: 9, fontWeight: 'bold' }}>
          {Math.round(finding.confidence * 100)}%
        </span>
      </div>
    </div>
  )
}

function DetailPanel({ finding }: { finding: Finding | null }) {
  if (!finding) {
    return (
      <div style={{
        flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--green-dark)', fontSize: 10, letterSpacing: 1,
      }}>
        Sélectionnez un finding
      </div>
    )
  }

  const sevColor = SEV_COLORS[finding.severity] ?? '#445566'

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <SectionHeader title="DÉTAIL" />
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 12px' }}>
        <DetailRow label="ID" value={finding.id} />
        <DetailRow label="TYPE" value={`${finding.cwe_id}`} color={sevColor} />
        <DetailRow label="SÉVÉRITÉ" value={finding.severity} color={sevColor} />
        <DetailRow label="OWASP" value={finding.owasp_category} />
        <DetailRow label="HYPOTHÈSE" value={finding.hypothesis_id} />
        <DetailRow label="PROPRIÉTÉ" value={finding.property_id} />
        <div style={{ display: 'flex', gap: 10, padding: '3px 0', fontSize: 10 }}>
          <span style={{ color: 'var(--green-dark)', width: 80, flexShrink: 0, letterSpacing: 1, fontSize: 9 }}>CONF</span>
          <span style={{ color: '#44ff88', fontFamily: 'var(--font-title)', fontSize: 14, fontWeight: 700 }}>
            {Math.round(finding.confidence * 100)}%
          </span>
        </div>
        <div style={{ height: 3, background: '#1a3a1a', borderRadius: 2, margin: '4px 0 8px' }}>
          <div style={{
            height: '100%', borderRadius: 2, background: '#44ff88',
            width: `${Math.round(finding.confidence * 100)}%`, transition: 'width 0.5s',
          }} />
        </div>

        <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, padding: '6px 0 4px' }}>
          ── ENDPOINTS AFFECTÉS ──
        </div>
        {finding.affected_endpoints.length > 0 ? (
          finding.affected_endpoints.map((ep, i) => (
            <div key={i} style={{ fontSize: 10, color: '#00ccff', padding: '2px 0', paddingLeft: 8 }}>
              {ep}
            </div>
          ))
        ) : (
          <div style={{ fontSize: 10, color: '#445566', paddingLeft: 8 }}>—</div>
        )}

        <div style={{ fontSize: 9, color: 'var(--green-dark)', letterSpacing: 1, padding: '8px 0 4px' }}>
          ── REMÉDIATION ──
        </div>
        <div style={{
          fontSize: 10, color: '#d8d8e8', lineHeight: 1.6, padding: '4px 8px',
          borderLeft: '2px solid var(--green-dark)', background: '#0a0a0a',
        }}>
          {finding.remediation_hint || 'Aucune recommandation disponible.'}
        </div>
      </div>
    </div>
  )
}

export function FindingsTab() {
  const { findings, loading, fetchFindings } = useFindingsStore()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  useEffect(() => { fetchFindings() }, [fetchFindings])

  // Re-fetch when scan completes or errors (findings accumulate during the scan)
  const { status } = useScanStore()
  useEffect(() => {
    if (status === 'done' || status === 'error') fetchFindings()
  }, [status, fetchFindings])

  const selected = findings.find(f => f.id === selectedId) ?? null

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `hdwp-findings-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Left: list */}
        <div style={{
          width: '40%', display: 'flex', flexDirection: 'column',
          borderRight: '1px solid var(--border)', overflow: 'hidden',
        }}>
          <SectionHeader title={`LISTE (${findings.length})`} />
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {loading && findings.length === 0 && (
              <div style={{ padding: 12, color: 'var(--green-dark)', fontSize: 10 }}>Chargement...</div>
            )}
            {!loading && findings.length === 0 && (
              <div style={{ padding: 12, color: 'var(--green-dark)', fontSize: 10, letterSpacing: 1 }}>
                Aucun finding confirmé
              </div>
            )}
            {findings.map(f => (
              <FindingListItem
                key={f.id}
                finding={f}
                selected={selectedId === f.id}
                onClick={() => setSelectedId(f.id)}
              />
            ))}
          </div>
        </div>

        {/* Right: detail */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <DetailPanel finding={selected} />
        </div>
      </div>

      {/* Bottom bar */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '5px 10px', borderTop: '1px solid var(--border)',
        background: 'var(--bg-input)', flexShrink: 0,
      }}>
        <button
          onClick={handleExport}
          disabled={findings.length === 0}
          style={{
            background: 'transparent', border: '1px solid var(--green-dark)',
            color: findings.length > 0 ? 'var(--green)' : 'var(--green-dark)',
            fontFamily: 'var(--font-title)', fontSize: 9, letterSpacing: 2,
            padding: '4px 14px', cursor: findings.length > 0 ? 'pointer' : 'default',
          }}
        >
          [ EXPORTER JSON ]
        </button>
        <button
          onClick={fetchFindings}
          style={{
            background: 'transparent', border: '1px solid var(--border)',
            color: 'var(--green-dim)', fontFamily: 'var(--font-title)',
            fontSize: 9, letterSpacing: 2, padding: '4px 14px', cursor: 'pointer',
          }}
        >
          [ RAFRAÎCHIR ]
        </button>
      </div>
    </div>
  )
}
