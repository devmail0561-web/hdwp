import { useFindingsStore } from '../stores/findingsStore'
import { useScanStore } from '../stores/scanStore'
import { useLLMStore } from '../stores/llmStore'

function MetricBlock({ label, value, color, pct }: {
  label: string; value: string | number; color: string; pct: number
}) {
  return (
    <div style={{ padding: '7px 8px', borderBottom: '1px solid var(--border)' }}>
      <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 3 }}>{label}</div>
      <div style={{ fontFamily: 'var(--font-title)', fontSize: 18, fontWeight: 700, color }}>{value}</div>
      <div style={{ height: 3, background: '#1a3a1a', borderRadius: 2, marginTop: 4 }}>
        <div style={{ height: '100%', borderRadius: 2, background: color, width: `${pct}%`, transition: 'width 1.2s' }} />
      </div>
    </div>
  )
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ff0066', HIGH: '#ff0066', MEDIUM: '#ffaa00', LOW: '#00ccff', INFO: '#445566',
}

export function MetricsPanel() {
  const { findingsCount, endpointCount, hypothesisCount } = useScanStore()
  const { findings } = useFindingsStore()
  const { active: llmActive, model } = useLLMStore()

  const avgConf = findings.length
    ? Math.round(findings.reduce((s, f) => s + f.confidence, 0) / findings.length * 100)
    : 0

  return (
    <div style={{
      borderLeft: '1px solid var(--border)', display: 'flex',
      flexDirection: 'column', overflow: 'hidden', background: 'var(--bg-panel)',
    }}>
      <div style={{ fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)', letterSpacing: 2, padding: '7px 10px 5px', borderBottom: '1px solid var(--border)', background: '#060606' }}>
        <span style={{ color: 'var(--green)' }}>[ </span>MÉTRIQUES<span style={{ color: 'var(--green)' }}> ]</span>
      </div>

      <MetricBlock label="CONF. MOY. FINDINGS" value={`${avgConf}%`} color="#00ff88" pct={avgConf} />
      <MetricBlock label="VIOLATIONS ORACLE" value={findingsCount} color="#ff0066" pct={Math.min(findingsCount * 10, 100)} />
      <MetricBlock label="COVERAGE ENDPOINTS" value={endpointCount} color="#00ccff" pct={Math.min(endpointCount * 5, 100)} />
      <MetricBlock label="HYPOTHÈSES" value={hypothesisCount} color="#ffaa00" pct={Math.min(hypothesisCount * 8, 100)} />

      <div style={{ fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)', letterSpacing: 2, padding: '7px 10px 5px', borderBottom: '1px solid var(--border)', background: '#060606' }}>
        <span style={{ color: 'var(--green)' }}>[ </span>DETAIL FINDINGS<span style={{ color: 'var(--green)' }}> ]</span>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '4px' }}>
        {findings.slice(0, 5).map(f => (
          <div key={f.id} style={{
            padding: '5px 6px', marginBottom: 3,
            borderLeft: `2px solid ${SEV_COLORS[f.severity] ?? '#445566'}`,
            background: (f.severity === 'HIGH' || f.severity === 'CRITICAL') ? '#0d0808'
              : f.severity === 'MEDIUM' ? '#0d0d08' : '#08080d',
            fontSize: 10,
          }}>
            <div style={{ color: '#445566', fontSize: 8, letterSpacing: 1 }}>{f.id}</div>
            <div style={{ color: SEV_COLORS[f.severity] ?? '#445566', fontWeight: 'bold' }}>{f.cwe_id}</div>
            <div style={{ color: '#445566', fontSize: 9 }}>
              {f.owasp_category}{' '}
              <span style={{ color: '#44ff88', fontWeight: 'bold' }}>conf:{Math.round(f.confidence * 100)}%</span>
            </div>
          </div>
        ))}

        <div style={{ fontSize: 9, color: 'var(--green-dark)', padding: '6px 8px 2px', letterSpacing: 1 }}>
          ── LLM ORACLE ──────────
        </div>
        <div style={{ padding: '4px 8px', fontSize: 9, color: '#445566', lineHeight: 1.7 }}>
          <div style={{ color: llmActive ? 'var(--green)' : '#445566' }}>
            {llmActive ? '● ' : '○ '}LLM {llmActive ? 'actif' : 'inactif'}
            {model && ` — ${model}`}
          </div>
          <div style={{ color: 'var(--green-dark)', marginTop: 3 }}>ADR-002 : non-décisionnel</div>
          <div style={{ color: 'var(--green-dark)' }}>seuil CONFIRMED = 0.85</div>
        </div>
      </div>
    </div>
  )
}
