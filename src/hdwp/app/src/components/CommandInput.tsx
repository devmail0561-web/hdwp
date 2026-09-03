import { useState } from 'react'
import { useScanStore } from '../stores/scanStore'

export function CommandInput({ onCommand }: { onCommand: (tag: string, text: string) => void }) {
  const [value, setValue] = useState('')
  const { sessionId } = useScanStore()

  const handleKey = async (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== 'Enter' || !value.trim()) return
    const cmd = value.trim().toLowerCase()
    setValue('')

    onCommand('CMD', `hdwp@engine:~/SESSION$ ${cmd}`)

    if (cmd === 'clear') { onCommand('__CLEAR__', ''); return }

    if (cmd === 'stop') {
      await fetch('/api/scan/stop', { method: 'POST' })
      onCommand('SYS', 'Scan arrêté.')
      return
    }
    if (cmd === 'status') {
      const r = await fetch('/api/state')
      const s = await r.json() as { phase: string; endpoint_count: number; findings_count: number }
      onCommand('OUT', `Phase: ${s.phase} — Endpoints: ${s.endpoint_count} — Findings: ${s.findings_count}`)
      return
    }
    if (cmd === 'findings') {
      const r = await fetch('/api/findings')
      const findings = await r.json() as Array<{ id: string; severity: string; owasp_category: string; confidence: number }>
      if (findings.length === 0) { onCommand('OUT', 'Aucun finding confirmé.'); return }
      findings.forEach(f => onCommand('OUT', `${f.id} ${f.severity} ${f.owasp_category} conf:${Math.round(f.confidence * 100)}%`))
      return
    }
    if (cmd === 'llm') {
      const r = await fetch('/api/llm/status')
      const s = await r.json() as { active: boolean; model: string | null; provider: string | null }
      onCommand('OUT', `LLM: ${s.active ? 'actif' : 'inactif'} — ${s.provider ?? '—'} / ${s.model ?? '—'}`)
      return
    }
    if (cmd === 'help') {
      onCommand('OUT', 'Commandes: status · findings · stop · plugins · llm · clear · help')
      return
    }

    onCommand('OUT', `Commande inconnue: "${cmd}" — tapez help`)
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center',
      borderTop: '1px solid var(--border)', padding: '5px 10px',
      background: 'var(--bg-input)', gap: 6, flexShrink: 0,
    }}>
      <span style={{ color: 'var(--red)', fontWeight: 'bold' }}>▶</span>
      <span style={{ color: 'var(--green-dim)' }}>hdwp@engine</span>
      <span style={{ color: 'var(--green-dark)' }}>:</span>
      <span style={{ color: 'var(--green)' }}>~/{sessionId ?? 'SESSION'}</span>
      <span style={{ color: 'var(--green-dark)' }}>$</span>
      <input
        value={value}
        onChange={e => setValue(e.target.value)}
        onKeyDown={handleKey}
        placeholder="status · findings · stop · plugins · llm · help"
        style={{
          flex: 1, background: 'transparent', border: 'none', outline: 'none',
          color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: 11,
          caretColor: 'var(--green)',
        }}
        spellCheck={false}
      />
    </div>
  )
}
