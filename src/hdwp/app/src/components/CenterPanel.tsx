import { useCallback } from 'react'
import { ModelCanvas } from './ModelCanvas'
import { LiveFeed } from './LiveFeed'
import { CommandInput } from './CommandInput'
import { useScanStore } from '../stores/scanStore'

export function CenterPanel() {
  const { addEvent } = useScanStore()

  const handleCommand = useCallback((tag: string, text: string) => {
    if (tag === '__CLEAR__') {
      useScanStore.setState({ events: [] })
      return
    }
    addEvent({
      type: `cmd.${tag.toLowerCase()}`,
      source: 'user',
      ts: new Date().toISOString(),
      payload: { text },
    })
  }, [addEvent])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <ModelCanvas />
      <div style={{
        fontFamily: 'var(--font-title)', fontSize: 9, color: 'var(--green-dim)',
        letterSpacing: 2, padding: '7px 10px 5px', borderBottom: '1px solid var(--border)',
        background: '#060606', flexShrink: 0,
      }}>
        <span style={{ color: 'var(--green)' }}>[ </span>
        LIVE FEED — BUS ÉVÉNEMENTS
        <span style={{ color: 'var(--green)' }}> ]</span>
      </div>
      <LiveFeed />
      <CommandInput onCommand={handleCommand} />
    </div>
  )
}
