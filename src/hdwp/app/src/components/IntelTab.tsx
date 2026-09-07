import { useV3Store } from '../stores/v3Store'

const MAX_DISPLAY = 20

const ESCLVL_COLOR: Record<number, string> = { 0: '#00ff88', 1: '#ffaa00', 2: '#ff0066' }
const DIFF_COLOR: Record<string, string> = { STRUCTURAL: '#ffaa00', VALUE: '#00ccff', IDENTITY: '#ff0066' }

function SectionHeader({ title }: { title: string }) {
  return (
    <div style={{ fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)', letterSpacing: 2, padding: '7px 10px 5px', borderBottom: '1px solid var(--border)', background: '#060606', marginTop: 1 }}>
      <span style={{ color: 'var(--green)' }}>[ </span>{title}<span style={{ color: 'var(--green)' }}> ]</span>
    </div>
  )
}

function Row({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ padding: '5px 10px', borderBottom: '1px solid #0d1a0d', fontSize: 10, lineHeight: 1.6 }}>
      {children}
    </div>
  )
}

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{ background: color + '22', color, border: `1px solid ${color}44`, borderRadius: 2, fontSize: 8, padding: '1px 5px', letterSpacing: 1, marginRight: 4 }}>
      {label}
    </span>
  )
}

function More({ total, shown }: { total: number; shown: number }) {
  if (total <= shown) return null
  return <div style={{ fontSize: 9, color: '#445566', padding: '4px 10px' }}>... {total - shown} more</div>
}

export function IntelTab() {
  const {
    threatScores, threatClassifications,
    invariantViolations, crossRoleDiffs,
    temporalAnomalies, wafSignatures,
    goalsReached,
  } = useV3Store()

  const threatEntries = Object.entries(threatScores)
  const shownThreats = threatEntries.slice(0, MAX_DISPLAY)
  const shownInvariants = invariantViolations.slice(0, MAX_DISPLAY)
  const shownDiffs = crossRoleDiffs.slice(0, MAX_DISPLAY)
  const shownAnomalies = temporalAnomalies.slice(0, MAX_DISPLAY)
  const shownWaf = wafSignatures.slice(0, MAX_DISPLAY)
  const shownGoals = goalsReached.slice(0, MAX_DISPLAY)

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', height: '100%', overflow: 'hidden', gap: 0 }}>
      {/* Left column */}
      <div style={{ overflowY: 'auto', borderRight: '1px solid var(--border)' }}>
        <SectionHeader title="THREATS" />
        {threatEntries.length === 0 && <Row><span style={{ color: '#445566' }}>no data</span></Row>}
        {shownThreats.map(([path, score]) => {
          const cls = threatClassifications[path] ?? ''
          const pct = Math.min(Math.round(score * 100), 100)
          return (
            <Row key={path}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                <span style={{ color: 'var(--green-dim)', fontFamily: 'var(--font-mono)', fontSize: 9, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{path}</span>
                <span style={{ color: '#ff6600', fontFamily: 'var(--font-title)', fontWeight: 700, minWidth: 32, textAlign: 'right' }}>{score.toFixed(2)}</span>
              </div>
              {cls && <Badge label={cls.toUpperCase()} color="#ff6600" />}
              <div style={{ height: 2, background: '#1a3a1a', borderRadius: 1, marginTop: 3 }}>
                <div style={{ height: '100%', borderRadius: 1, background: '#ff6600', width: `${pct}%`, transition: 'width 1s' }} />
              </div>
            </Row>
          )
        })}
        <More total={threatEntries.length} shown={shownThreats.length} />

        <SectionHeader title="INVARIANT VIOLATIONS" />
        {invariantViolations.length === 0 && <Row><span style={{ color: '#445566' }}>no data</span></Row>}
        {shownInvariants.map((v, i) => (
          <Row key={i}>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
              <Badge label={v.pattern_type} color="#ffaa00" />
              <span style={{ color: '#00ff88', fontSize: 9 }}>{Math.round(v.confidence * 100)}%</span>
            </div>
            <div style={{ color: 'var(--green-dim)', fontFamily: 'var(--font-mono)', fontSize: 9, marginTop: 2 }}>{v.endpoint_path}</div>
            <div style={{ color: '#445566', fontSize: 9 }}>{v.formal_statement}</div>
          </Row>
        ))}
        <More total={invariantViolations.length} shown={shownInvariants.length} />

        <SectionHeader title="CROSSROLE DIFFS" />
        {crossRoleDiffs.length === 0 && <Row><span style={{ color: '#445566' }}>no data</span></Row>}
        {shownDiffs.map((d, i) => (
          <Row key={i}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <Badge label={d.diff_type} color={DIFF_COLOR[d.diff_type] ?? '#445566'} />
              <span style={{ color: '#00ff88', fontSize: 9 }}>{Math.round(d.confidence * 100)}%</span>
            </div>
            <div style={{ color: 'var(--green-dim)', fontFamily: 'var(--font-mono)', fontSize: 9, marginTop: 2 }}>{d.endpoint_path}</div>
            <div style={{ color: '#445566', fontSize: 9 }}>{d.role_a} <span style={{ color: 'var(--green)' }}>vs</span> {d.role_b}</div>
          </Row>
        ))}
        <More total={crossRoleDiffs.length} shown={shownDiffs.length} />
      </div>

      {/* Right column */}
      <div style={{ overflowY: 'auto' }}>
        <SectionHeader title="TEMPORAL ANOMALIES" />
        {temporalAnomalies.length === 0 && <Row><span style={{ color: '#445566' }}>no data</span></Row>}
        {shownAnomalies.map((a, i) => (
          <Row key={i}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <Badge label={`ESC ${a.escalation_level}`} color={ESCLVL_COLOR[a.escalation_level] ?? '#445566'} />
              <span style={{ color: '#00ccff', fontSize: 9 }}>{a.timing_ms.toFixed(0)}ms</span>
              <span style={{ color: '#445566', fontSize: 9 }}>p95={a.baseline_p95.toFixed(0)}ms</span>
            </div>
            <div style={{ color: 'var(--green-dim)', fontFamily: 'var(--font-mono)', fontSize: 9, marginTop: 2 }}>{a.endpoint_path}</div>
          </Row>
        ))}
        <More total={temporalAnomalies.length} shown={shownAnomalies.length} />

        <SectionHeader title="WAF SIGNATURES" />
        {wafSignatures.length === 0 && <Row><span style={{ color: '#445566' }}>no data</span></Row>}
        {shownWaf.map((w, i) => (
          <Row key={i}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <Badge label={w.waf_type.toUpperCase()} color="#ff0066" />
            </div>
            <div style={{ color: 'var(--green-dim)', fontFamily: 'var(--font-mono)', fontSize: 9, marginTop: 2 }}>{w.endpoint}</div>
            <div style={{ color: '#445566', fontSize: 9, marginTop: 2 }}>
              {w.bypass_strategies.slice(0, 4).join(' · ')}
              {w.bypass_strategies.length > 4 && ` +${w.bypass_strategies.length - 4}`}
            </div>
          </Row>
        ))}
        <More total={wafSignatures.length} shown={shownWaf.length} />

        <SectionHeader title="GOALS REACHED" />
        {goalsReached.length === 0 && <Row><span style={{ color: '#445566' }}>no data</span></Row>}
        {shownGoals.map((g, i) => (
          <Row key={i}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <Badge label={g.goal_type.toUpperCase()} color="#00ff88" />
            </div>
            <div style={{ color: '#445566', fontSize: 9, marginTop: 2 }}>
              {g.plan_steps} steps · cost {g.total_cost.toFixed(2)}
            </div>
          </Row>
        ))}
        <More total={goalsReached.length} shown={shownGoals.length} />
      </div>
    </div>
  )
}
