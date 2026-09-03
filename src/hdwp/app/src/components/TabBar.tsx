interface Tab { id: string; label: string; variant?: 'normal' | 'warn' | 'alert' }

const TABS: Tab[] = [
  { id: 'scan', label: '⬡ SCAN' },
  { id: 'findings', label: '⬡ FINDINGS' },
  { id: 'flow', label: '⬡ FLOW', variant: 'warn' },
  { id: 'report', label: '⬡ REPORT', variant: 'warn' },
  { id: 'exploit', label: '⬡ EXPLOIT', variant: 'alert' },
  { id: 'plugins', label: '⬡ PLUGINS' },
  { id: 'settings', label: '⬡ SETTINGS' },
]

interface TabBarProps { active: string; onChange(id: string): void; locked?: boolean }

const VARIANT_COLORS: Record<string, string> = {
  warn: '#ffaa00', alert: '#ff0066', normal: '#00ff88',
}

export function TabBar({ active, onChange, locked }: TabBarProps) {
  return (
    <div style={{ display: 'flex', background: '#010e08', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
      {TABS.map(tab => {
        const isDisabled = locked && tab.id !== 'scan'
        const isActive = active === tab.id
        const color = isDisabled ? '#1a2a1a' : isActive ? (VARIANT_COLORS[tab.variant ?? 'normal']) : '#2a4a2a'
        return (
          <button
            key={tab.id}
            onClick={() => !isDisabled && onChange(tab.id)}
            title={isDisabled ? 'Démarrez une session pour accéder à cet onglet' : undefined}
            style={{
              padding: '7px 18px', fontSize: 10, color,
              background: isActive ? '#031a10' : 'transparent',
              border: 'none', borderRight: '1px solid var(--border)',
              borderBottom: isActive ? `2px solid ${color}` : '2px solid transparent',
              cursor: isDisabled ? 'not-allowed' : 'pointer', letterSpacing: 1,
              fontFamily: 'var(--font-title)',
              opacity: isDisabled ? 0.4 : 1,
            }}
          >
            {tab.label}
          </button>
        )
      })}
      <div style={{ flex: 1 }} />
      <button onClick={() => onChange('stop')} style={{
        padding: '7px 18px', fontSize: 10,
        color: active === 'stop' ? '#ff0066' : '#ff006655',
        background: 'transparent', border: 'none',
        borderLeft: '1px solid var(--border)', cursor: 'pointer',
        fontFamily: 'var(--font-title)', letterSpacing: 1,
      }}>
        ■ STOP
      </button>
    </div>
  )
}
