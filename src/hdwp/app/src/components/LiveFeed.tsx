import { useRef, useEffect } from 'react'
import { useScanStore } from '../stores/scanStore'
import type { BusEvent } from '../types/hdwp'

const TAG_STYLES: Record<string, { color: string; bg: string }> = {
  'observation.raw':      { color: '#00d4ff', bg: '#00d4ff22' },
  'credentials.captured': { color: '#ffd700', bg: '#ffd70022' },
  'property.inferred':    { color: '#9966ff', bg: '#9966ff22' },
  'hypothesis.generated': { color: '#ff8c00', bg: '#ff8c0022' },
  'experiment.result':    { color: '#00aaff', bg: '#00aaff22' },
  'finding.confirmed':    { color: '#44ff88', bg: '#44ff8811' },
  'finding.refuted':      { color: '#ff0066', bg: '#ff006622' },
  'model.updated':        { color: '#9966ff', bg: '#9966ff11' },
}

const TAG_LABELS: Record<string, string> = {
  'observation.raw': 'OBS', 'credentials.captured': 'KEY',
  'property.inferred': 'PROP', 'hypothesis.generated': 'HYP',
  'experiment.result': 'EXP', 'finding.confirmed': '  V ',
  'finding.refuted': '  X ', 'model.updated': 'MDL',
}

function extractText(event: BusEvent): string {
  const p = event.payload as Record<string, unknown>
  switch (event.type) {
    case 'observation.raw': {
      const req = p?.request as Record<string, unknown> | undefined
      const method = req?.method ?? 'GET'
      const url = String(req?.url ?? '').replace(/^https?:\/\/[^/]+/, '')
      const sc = (p?.response as Record<string, unknown>)?.status_code ?? ''
      return `${method} ${url || '?'} → ${sc}`
    }
    case 'model.updated': {
      const eps = (p?.endpoints as unknown[])?.length ?? 0
      const conf = typeof p?.model_confidence === 'number' ? `${Math.round((p.model_confidence as number) * 100)}%` : ''
      return `${eps} endpoint(s) modélisé(s) ${conf}`
    }
    case 'property.inferred':
      return String(p?.formal_statement ?? p?.type ?? '').slice(0, 80)
    case 'hypothesis.generated':
      return String(p?.statement ?? '').slice(0, 80)
    case 'experiment.result':
      return `${p?.mutation_type ?? '?'} → ${p?.verdict ?? p?.status ?? '?'}`
    case 'finding.confirmed':
      return `[${p?.severity ?? '?'}] ${p?.cwe_id ?? ''} — confiance ${Math.round(((p?.confidence as number) ?? 0) * 100)}%`
    case 'finding.refuted':
      return `refuté: ${p?.hypothesis_id ?? p?.id ?? ''}`
    default:
      return String(p?.text ?? p?.id ?? event.type).slice(0, 80)
  }
}

function EventLine({ event }: { event: BusEvent }) {
  const style = TAG_STYLES[event.type] ?? { color: '#445566', bg: 'transparent' }
  const label = TAG_LABELS[event.type] ?? event.type.split('.').pop()?.slice(0, 3).toUpperCase() ?? 'SYS'
  const ts = event.ts ? new Date(event.ts).toLocaleTimeString('fr-FR') : '--:--:--'
  const text = extractText(event)

  return (
    <div style={{ marginBottom: 2, lineHeight: 1.5 }}>
      <span style={{ color: '#2a4a2a', marginRight: 5, fontSize: 10 }}>{ts}</span>
      <span style={{
        fontSize: 9, padding: '1px 4px', marginRight: 5,
        color: style.color, border: `1px solid ${style.color}44`,
        background: style.bg,
      }}>{label}</span>
      <span style={{ color: event.type === 'finding.confirmed' ? '#44ff88' : '#00cc66' }}>
        {text}
      </span>
    </div>
  )
}

export function LiveFeed() {
  const { events } = useScanStore()
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events.length])

  return (
    <div style={{ flex: 1, background: '#070707', padding: '7px 10px', overflowY: 'auto', fontSize: 11 }}>
      {events.map((e, i) => <EventLine key={i} event={e} />)}
      <div ref={bottomRef} />
    </div>
  )
}
