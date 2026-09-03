import { StatusPanel } from './StatusPanel'
import { CenterPanel } from './CenterPanel'
import { MetricsPanel } from './MetricsPanel'
import { NewSessionPage } from './NewSessionPage'
import { useScanStore } from '../stores/scanStore'

export function ScanTab() {
  const { sessionId } = useScanStore()

  if (!sessionId) return <NewSessionPage />

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '210px 1fr 210px',
      height: '100%',
      overflow: 'hidden',
    }}>
      <StatusPanel />
      <CenterPanel />
      <MetricsPanel />
    </div>
  )
}
