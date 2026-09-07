import { useEffect, useRef, useState } from 'react'
import { useFlowStore } from '../stores/flowStore'
import { useScanStore } from '../stores/scanStore'
import type { DBTable, FlowEdge, FlowMap } from '../types/hdwp'

// ── Types ────────────────────────────────────────────────────────────────────

interface NodeState {
  id: string
  x: number
  y: number
  vx: number
  vy: number
  pinned: boolean
  r: number
}

interface Selected {
  type: 'node' | 'edge'
  data: NodeState | FlowEdge
}

type TriggerType = 'link' | 'form' | 'ajax' | 'fsm' | 'redirect'
const ALL_TRIGGERS: TriggerType[] = ['link', 'form', 'ajax', 'fsm', 'redirect']

const TRIGGER_COLORS: Record<TriggerType, string> = {
  link: '#00ccff',
  form: '#00ff88',
  ajax: '#cc44ff',
  fsm: '#ffaa00',
  redirect: '#aaaaaa',
}

const PAD = 50

function triggerColor(t: string): string {
  return TRIGGER_COLORS[t as TriggerType] ?? '#445566'
}

function distToSegment(px: number, py: number, ax: number, ay: number, bx: number, by: number): number {
  const dx = bx - ax, dy = by - ay
  const lenSq = dx * dx + dy * dy
  if (lenSq === 0) return Math.hypot(px - ax, py - ay)
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / lenSq))
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy))
}

// ── Sub-components ───────────────────────────────────────────────────────────

function NodeDetail({ node, flowMap }: { node: NodeState; flowMap: FlowMap | null }) {
  if (!flowMap) return null
  const isExfil = flowMap.exfiltration_risks.includes(node.id)
  const edgesIn = flowMap.edges.filter(e => e.to_endpoint === node.id)
  const edgesOut = flowMap.edges.filter(e => e.from_endpoint === node.id)
  const sectionLabel = (t: string) => (
    <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, margin: '10px 0 5px' }}>{`── ${t} ──`}</div>
  )
  return (
    <div>
      <div style={{ fontSize: 10, color: 'var(--text-hl)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginBottom: 6 }}>{node.id}</div>
      {isExfil && (
        <div style={{ padding: '4px 8px', background: '#200808', border: '1px solid #ff0022', color: '#ff0022', fontSize: 9, marginBottom: 8, letterSpacing: 0.5 }}>
          ⚠ RISQUE D'EXFILTRATION — données sensibles sans auth
        </div>
      )}
      {sectionLabel('EDGES ENTRANTS')}
      {edgesIn.length === 0 ? (
        <div style={{ fontSize: 9, color: '#2a4a2a' }}>Aucun</div>
      ) : edgesIn.map((e, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
          <span style={{ fontSize: 8, padding: '1px 5px', border: `1px solid ${triggerColor(e.trigger)}`, color: triggerColor(e.trigger) }}>{e.trigger}</span>
          <span style={{ fontSize: 9, color: '#445566', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.from_endpoint}</span>
        </div>
      ))}
      {sectionLabel('EDGES SORTANTS')}
      {edgesOut.length === 0 ? (
        <div style={{ fontSize: 9, color: '#2a4a2a' }}>Aucun</div>
      ) : edgesOut.map((e, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
          <span style={{ fontSize: 8, padding: '1px 5px', border: `1px solid ${triggerColor(e.trigger)}`, color: triggerColor(e.trigger) }}>{e.trigger}</span>
          <span style={{ fontSize: 9, color: '#445566', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.to_endpoint}</span>
        </div>
      ))}
    </div>
  )
}

function EdgeDetail({ edge }: { edge: FlowEdge }) {
  const col = triggerColor(edge.trigger)
  return (
    <div>
      <div style={{ fontSize: 9, color: 'var(--green-dark)', marginBottom: 6, letterSpacing: 1 }}>── ARÊTE ──</div>
      <div style={{ fontSize: 9, color: 'var(--text-hl)', marginBottom: 4, wordBreak: 'break-all' }}>
        {edge.from_endpoint}
        <span style={{ color: col }}> → </span>
        {edge.to_endpoint}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <span style={{ fontSize: 8, padding: '1px 6px', border: `1px solid ${col}`, color: col }}>{edge.trigger.toUpperCase()}</span>
        <span style={{ fontSize: 9, color: '#445566' }}>confiance</span>
        <div style={{ flex: 1, height: 3, background: '#1a3a1a', borderRadius: 2 }}>
          <div style={{ height: '100%', background: col, width: `${edge.confidence * 100}%`, borderRadius: 2 }} />
        </div>
        <span style={{ fontSize: 9, color: col }}>{Math.round(edge.confidence * 100)}%</span>
      </div>
      {edge.params_transferred.length > 0 && (
        <>
          <div style={{ fontSize: 8, color: 'var(--green-dark)', marginBottom: 4, letterSpacing: 1 }}>PARAMÈTRES TRANSFÉRÉS</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {edge.params_transferred.map(p => (
              <span key={p} style={{ fontSize: 8, padding: '1px 6px', border: '1px solid #445566', color: '#445566' }}>{p}</span>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function DBTablesSection({ tables }: { tables: DBTable[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const toggle = (name: string) => {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name); else next.add(name)
      return next
    })
  }
  return (
    <div style={{ marginTop: 16, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
      <div style={{ fontSize: 8, color: 'var(--green-dark)', letterSpacing: 1, marginBottom: 8 }}>── TABLES DB INFÉRÉES ──</div>
      {tables.map(t => (
        <div key={t.name} style={{ marginBottom: 4, border: '1px solid var(--border)' }}>
          <div
            onClick={() => toggle(t.name)}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', cursor: 'pointer', background: '#010e08' }}
          >
            <span style={{ fontSize: 9, color: 'var(--text-hl)', flex: 1, fontFamily: 'var(--font-mono)' }}>{t.name}</span>
            <span style={{ fontSize: 8, color: '#00ccff' }}>{Math.round(t.confidence * 100)}%</span>
            <span style={{ fontSize: 9, color: '#445566' }}>{expanded.has(t.name) ? '▲' : '▼'}</span>
          </div>
          {expanded.has(t.name) && (
            <div style={{ padding: '4px 8px 6px' }}>
              {t.columns.map(c => (
                <div key={c.name} style={{ fontSize: 8, color: c.is_pk ? '#ffd700' : '#445566', padding: '1px 0', fontFamily: 'var(--font-mono)' }}>
                  {c.is_pk ? '[PK] ' : ''}{c.name} <span style={{ color: '#2a4a2a' }}>({c.type_hint})</span>
                  {c.is_fk_to && <span style={{ color: '#00ccff' }}> → {c.is_fk_to}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ── Main component ───────────────────────────────────────────────────────────

export function FlowTab() {
  const { flowMap } = useFlowStore()
  const { sessionId, status } = useScanStore()

  // Fetch on mount, session change, and scan completion
  useEffect(() => {
    if (sessionId && status !== 'idle') useFlowStore.getState().fetchFlowMap()
  }, [sessionId, status])

  const canvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const animRef = useRef<number>(0)

  // Interaction refs
  const nodesRef = useRef<NodeState[]>([])
  const panXRef = useRef(0)
  const panYRef = useRef(0)
  const zoomRef = useRef(1.0)
  const draggingRef = useRef<NodeState | null>(null)
  const panningRef = useRef(false)
  const lastMouseRef = useRef({ x: 0, y: 0 })
  const animatedRef = useRef(false)
  const filtersRef = useRef<Set<string>>(new Set(ALL_TRIGGERS))

  // React state (for UI re-renders)
  const [animated, setAnimatedState] = useState(false)
  const [filters, setFilters] = useState<Set<string>>(new Set(ALL_TRIGGERS))
  const [selected, setSelected] = useState<Selected | null>(null)
  const [nodeCount, setNodeCount] = useState(0)

  // Keep refs in sync
  animatedRef.current = animated
  filtersRef.current = filters

  // ── Layout helpers ────────────────────────────────────────────────────────

  const buildLayout = (map: FlowMap) => {
    const canvas = canvasRef.current
    const container = containerRef.current
    // Utiliser les dimensions CSS du conteneur (disponibles immédiatement via layout)
    // plutôt que les attributs buffer du canvas (300×150 par défaut avant ResizeObserver)
    const rect = container?.getBoundingClientRect()
    const W = (rect && rect.width > 50) ? rect.width : (canvas?.width || 600)
    const H = (rect && rect.height > 50) ? rect.height : (canvas?.height || 400)
    // Synchroniser les dimensions du buffer avec le conteneur si besoin
    if (canvas && rect && rect.width > 0 && rect.height > 0) {
      if (canvas.width !== Math.floor(rect.width) || canvas.height !== Math.floor(rect.height)) {
        canvas.width = Math.floor(rect.width)
        canvas.height = Math.floor(rect.height)
      }
    }

    const endpointSet = new Set<string>()
    for (const e of map.edges) {
      endpointSet.add(e.from_endpoint)
      endpointSet.add(e.to_endpoint)
    }
    const endpoints = Array.from(endpointSet)
    if (endpoints.length === 0) { nodesRef.current = []; return }

    // Degree count
    const degree: Record<string, number> = {}
    for (const ep of endpoints) degree[ep] = 0
    for (const e of map.edges) {
      degree[e.from_endpoint] = (degree[e.from_endpoint] ?? 0) + 1
      degree[e.to_endpoint] = (degree[e.to_endpoint] ?? 0) + 1
    }

    // BFS depth assignment
    const incomingCount: Record<string, number> = {}
    for (const ep of endpoints) incomingCount[ep] = 0
    for (const e of map.edges) incomingCount[e.to_endpoint] = (incomingCount[e.to_endpoint] ?? 0) + 1
    const root = endpoints.reduce((a, b) => (incomingCount[a] ?? 0) <= (incomingCount[b] ?? 0) ? a : b)
    const depths: Record<string, number> = {}
    const queue = [root]
    depths[root] = 0
    const adj: Record<string, string[]> = {}
    for (const e of map.edges) { (adj[e.from_endpoint] = adj[e.from_endpoint] ?? []).push(e.to_endpoint) }
    while (queue.length > 0) {
      const cur = queue.shift()!
      for (const nb of (adj[cur] ?? [])) {
        if (depths[nb] === undefined) { depths[nb] = depths[cur] + 1; queue.push(nb) }
      }
    }
    for (const ep of endpoints) { if (depths[ep] === undefined) depths[ep] = 0 }

    // Group by depth
    const byDepth: Record<number, string[]> = {}
    for (const ep of endpoints) {
      const d = depths[ep];
      (byDepth[d] = byDepth[d] ?? []).push(ep)
    }
    const maxDepth = Math.max(...Object.keys(byDepth).map(Number))
    const colStep = Math.min(140, (W - PAD * 2) / Math.max(maxDepth + 1, 1))

    const nodes: NodeState[] = []
    for (const [depthStr, eps] of Object.entries(byDepth)) {
      const depth = Number(depthStr)
      const rowStep = (H - PAD * 2) / Math.max(eps.length, 1)
      eps.forEach((ep, i) => {
        nodes.push({
          id: ep,
          x: PAD + depth * colStep + colStep * 0.5,
          y: PAD + i * rowStep + rowStep * 0.5,
          vx: 0, vy: 0, pinned: false,
          r: Math.min(18, 8 + (degree[ep] ?? 0) * 1.5),
        })
      })
    }
    // Run physics warm-up so nodes spread naturally before first render
    const nodeMap: Record<string, NodeState> = {}
    for (const n of nodes) nodeMap[n.id] = n
    const springLen = 130
    for (let iter = 0; iter < 80; iter++) {
      // Repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const A = nodes[i], B = nodes[j]
          const dx = A.x - B.x, dy = A.y - B.y
          const dist = Math.max(Math.hypot(dx, dy), 1)
          const f = 2500 / (dist * dist)
          const fx = (dx / dist) * f, fy = (dy / dist) * f
          A.vx += fx; A.vy += fy
          B.vx -= fx; B.vy -= fy
        }
      }
      // Spring attraction along edges
      for (const e of map.edges) {
        const A = nodeMap[e.from_endpoint], B = nodeMap[e.to_endpoint]
        if (!A || !B) continue
        const dx = B.x - A.x, dy = B.y - A.y
        const dist = Math.max(Math.hypot(dx, dy), 1)
        const f = (dist - springLen) * 0.025
        const fx = (dx / dist) * f, fy = (dy / dist) * f
        A.vx += fx; A.vy += fy
        B.vx -= fx; B.vy -= fy
      }
      // Integrate
      for (const n of nodes) {
        n.vx *= 0.82; n.vy *= 0.82
        n.x = Math.max(PAD, Math.min(W - PAD, n.x + n.vx))
        n.y = Math.max(PAD, Math.min(H - PAD, n.y + n.vy))
      }
    }
    // Zero velocities after warm-up
    for (const n of nodes) { n.vx = 0; n.vy = 0 }

    nodesRef.current = nodes
    setNodeCount(nodes.length)
  }

  // ── Rebuild nodes when flowMap changes ────────────────────────────────────

  useEffect(() => {
    if (flowMap && flowMap.edges.length > 0) {
      buildLayout(flowMap)
    } else {
      nodesRef.current = []
      setNodeCount(0); // edgeCount removed
    }
  }, [flowMap])

  // ── Canvas size sync ─────────────────────────────────────────────────────

  useEffect(() => {
    const container = containerRef.current
    const canvas = canvasRef.current
    if (!container || !canvas) return
    const ro = new ResizeObserver(() => {
      const rect = container.getBoundingClientRect()
      canvas.width = rect.width
      canvas.height = rect.height
      if (flowMap) buildLayout(flowMap)
    })
    ro.observe(container)
    return () => ro.disconnect()
  }, [flowMap])

  // ── Animation loop ────────────────────────────────────────────────────────

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')!

    // Per-edge particles (two per edge)
    const packetMap = new Map<string, [number, number]>()

    const draw = () => {
      const W = canvas.width, H = canvas.height
      const nodes = nodesRef.current
      const nodeMap: Record<string, NodeState> = {}
      for (const n of nodes) nodeMap[n.id] = n

      const visibleEdges = (flowMap?.edges ?? []).filter(e => filtersRef.current.has(e.trigger))

      // ── Physics ──────────────────────────────────────────────────────────
      if (animatedRef.current && nodes.length > 1) {
        // Repulsion
        for (let i = 0; i < nodes.length; i++) {
          for (let j = i + 1; j < nodes.length; j++) {
            const A = nodes[i], B = nodes[j]
            const dx = A.x - B.x, dy = A.y - B.y
            const dist = Math.max(Math.hypot(dx, dy), 1)
            const f = 2500 / (dist * dist)
            const fx = (dx / dist) * f, fy = (dy / dist) * f
            if (!A.pinned) { A.vx += fx; A.vy += fy }
            if (!B.pinned) { B.vx -= fx; B.vy -= fy }
          }
        }
        // Spring
        for (const e of visibleEdges) {
          const A = nodeMap[e.from_endpoint], B = nodeMap[e.to_endpoint]
          if (!A || !B) continue
          const dx = B.x - A.x, dy = B.y - A.y
          const dist = Math.max(Math.hypot(dx, dy), 1)
          const f = (dist - 130) * 0.025
          const fx = (dx / dist) * f, fy = (dy / dist) * f
          if (!A.pinned) { A.vx += fx; A.vy += fy }
          if (!B.pinned) { B.vx -= fx; B.vy -= fy }
        }
        // Integrate
        for (const n of nodes) {
          if (!n.pinned) {
            n.vx *= 0.82; n.vy *= 0.82
            n.x = Math.max(PAD, Math.min(W - PAD, n.x + n.vx))
            n.y = Math.max(PAD, Math.min(H - PAD, n.y + n.vy))
          }
        }
      }

      // ── Render ────────────────────────────────────────────────────────────
      ctx.clearRect(0, 0, W, H)
      ctx.fillStyle = '#060606'
      ctx.fillRect(0, 0, W, H)

      // Grid
      ctx.strokeStyle = '#00ff4106'; ctx.lineWidth = 0.5
      for (let x = 0; x < W; x += 30) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke() }
      for (let y = 0; y < H; y += 30) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke() }

      ctx.save()
      ctx.translate(panXRef.current, panYRef.current)
      ctx.scale(zoomRef.current, zoomRef.current)

      // Edges
      for (let ei = 0; ei < visibleEdges.length; ei++) {
        const e = visibleEdges[ei]
        const A = nodeMap[e.from_endpoint], B = nodeMap[e.to_endpoint]
        if (!A || !B) continue

        const col = triggerColor(e.trigger)
        const opacity = Math.floor(80 + e.confidence * 100).toString(16).padStart(2, '0')

        // Line
        ctx.strokeStyle = col + opacity
        ctx.lineWidth = 1 + e.confidence * 2
        ctx.setLineDash([4, 3])
        ctx.beginPath(); ctx.moveTo(A.x, A.y); ctx.lineTo(B.x, B.y); ctx.stroke()
        ctx.setLineDash([])

        // Arrow head
        const angle = Math.atan2(B.y - A.y, B.x - A.x)
        const offset = B.r + 2
        const tx = B.x - Math.cos(angle) * offset
        const ty = B.y - Math.sin(angle) * offset
        ctx.save()
        ctx.translate(tx, ty)
        ctx.rotate(angle)
        ctx.fillStyle = col
        ctx.beginPath(); ctx.moveTo(-10, -4); ctx.lineTo(0, 0); ctx.lineTo(-10, 4); ctx.closePath()
        ctx.fill()
        ctx.restore()

        // Packets
        const pKey = `${e.from_endpoint}::${e.to_endpoint}::${ei}`
        let [t1, t2] = packetMap.get(pKey) ?? [Math.random(), Math.random() * 0.5]
        t1 = (t1 + 0.008 * (1 + e.confidence)) % 1
        t2 = (t2 + 0.006 * (1 + e.confidence)) % 1
        packetMap.set(pKey, [t1, t2])
        for (const t of [t1, t2]) {
          const px = A.x + (B.x - A.x) * t
          const py = A.y + (B.y - A.y) * t
          ctx.beginPath(); ctx.arc(px, py, 2.5, 0, Math.PI * 2)
          ctx.fillStyle = col + 'cc'; ctx.fill()
        }
      }

      // Nodes
      for (const n of nodes) {
        const isExfil = flowMap?.exfiltration_risks.includes(n.id) ?? false
        const isSelected = selected?.type === 'node' && (selected.data as NodeState).id === n.id
        const color = isExfil ? '#ff0022' : '#00ccff'

        if (isSelected) { ctx.shadowBlur = 15; ctx.shadowColor = color }

        // Glow ring
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 5, 0, Math.PI * 2)
        ctx.fillStyle = color + '18'; ctx.fill()

        // Body
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2)
        ctx.fillStyle = '#060606'; ctx.fill()
        ctx.strokeStyle = color; ctx.lineWidth = isSelected ? 2 : 1.5; ctx.stroke()

        ctx.shadowBlur = 0

        // Pinned dot
        if (n.pinned) {
          ctx.beginPath(); ctx.arc(n.x - n.r + 4, n.y - n.r + 4, 3, 0, Math.PI * 2)
          ctx.fillStyle = '#ffaa00'; ctx.fill()
        }

        // Exfil badge
        if (isExfil) {
          ctx.font = 'bold 10px Share Tech Mono'
          ctx.fillStyle = '#ff0022'
          ctx.textAlign = 'center'
          ctx.fillText('⚠', n.x + n.r - 2, n.y - n.r + 4)
        }

        // Label
        const label = n.id.length > 16 ? '…' + n.id.slice(-14) : n.id
        ctx.font = '8px Share Tech Mono'
        ctx.fillStyle = color
        ctx.textAlign = 'center'
        ctx.fillText(label, n.x, n.y + n.r + 11)
      }

      // Empty state
      if (nodes.length === 0) {
        ctx.restore()
        ctx.save()
        ctx.font = '10px Share Tech Mono'
        ctx.fillStyle = '#2a4a2a'
        ctx.textAlign = 'center'
        ctx.fillText('Aucune donnée de flux — lancez un scan pour voir les flux de données.', W / 2, H / 2)
        ctx.restore()
        animRef.current = requestAnimationFrame(draw)
        return
      }

      ctx.restore()
      animRef.current = requestAnimationFrame(draw)
    }

    animRef.current = requestAnimationFrame(draw)
    return () => cancelAnimationFrame(animRef.current)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flowMap, animated, selected])

  // ── Canvas event helpers ──────────────────────────────────────────────────

  const toCanvas = (e: React.MouseEvent) => {
    const rect = canvasRef.current!.getBoundingClientRect()
    return {
      cx: (e.clientX - rect.left - panXRef.current) / zoomRef.current,
      cy: (e.clientY - rect.top - panYRef.current) / zoomRef.current,
    }
  }

  const handleMouseDown = (e: React.MouseEvent) => {
    const { cx, cy } = toCanvas(e)
    const hit = nodesRef.current.find(n => Math.hypot(n.x - cx, n.y - cy) < n.r + 6)
    if (hit) { draggingRef.current = hit; hit.pinned = true }
    else panningRef.current = true
    lastMouseRef.current = { x: e.clientX, y: e.clientY }
  }

  const handleMouseMove = (e: React.MouseEvent) => {
    const dx = e.clientX - lastMouseRef.current.x
    const dy = e.clientY - lastMouseRef.current.y
    if (draggingRef.current) {
      draggingRef.current.x += dx / zoomRef.current
      draggingRef.current.y += dy / zoomRef.current
    } else if (panningRef.current) {
      panXRef.current += dx; panYRef.current += dy
    }
    lastMouseRef.current = { x: e.clientX, y: e.clientY }
  }

  const handleMouseUp = () => {
    draggingRef.current = null
    panningRef.current = false
  }

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault()
    const factor = 1 - e.deltaY * 0.001
    zoomRef.current = Math.max(0.2, Math.min(4, zoomRef.current * factor))
  }

  const handleDblClick = (e: React.MouseEvent) => {
    const { cx, cy } = toCanvas(e)
    const hit = nodesRef.current.find(n => Math.hypot(n.x - cx, n.y - cy) < n.r + 6)
    if (hit) hit.pinned = !hit.pinned
  }

  const handleClick = (e: React.MouseEvent) => {
    if (draggingRef.current) return
    const { cx, cy } = toCanvas(e)
    const hitNode = nodesRef.current.find(n => Math.hypot(n.x - cx, n.y - cy) < n.r + 6)
    if (hitNode) { setSelected({ type: 'node', data: hitNode }); return }
    const nodeMap: Record<string, NodeState> = {}
    for (const n of nodesRef.current) nodeMap[n.id] = n
    const visibleEdges = (flowMap?.edges ?? []).filter(e => filtersRef.current.has(e.trigger))
    for (const edge of visibleEdges) {
      const A = nodeMap[edge.from_endpoint], B = nodeMap[edge.to_endpoint]
      if (A && B && distToSegment(cx, cy, A.x, A.y, B.x, B.y) < 8) {
        setSelected({ type: 'edge', data: edge }); return
      }
    }
    setSelected(null)
  }

  // ── Control actions ───────────────────────────────────────────────────────

  const toggleFilter = (t: string) => {
    setFilters(prev => {
      const next = new Set(prev)
      if (next.has(t)) next.delete(t); else next.add(t)
      return next
    })
  }

  const resetLayout = () => {
    panXRef.current = 0; panYRef.current = 0; zoomRef.current = 1
    if (flowMap) buildLayout(flowMap)
  }

  const btnStyle = (active: boolean): React.CSSProperties => ({
    background: active ? '#031a10' : 'transparent',
    border: `1px solid ${active ? 'var(--green)' : 'var(--border)'}`,
    color: active ? 'var(--green)' : '#445566',
    fontFamily: 'var(--font-title)', fontSize: 8, letterSpacing: 1,
    padding: '2px 8px', cursor: 'pointer',
  })

  const visibleEdgeCount = (flowMap?.edges ?? []).filter(e => filters.has(e.trigger)).length

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--bg)' }}>

      {/* Control bar */}
      <div style={{
        display: 'flex', gap: 6, padding: '5px 10px', flexShrink: 0,
        borderBottom: '1px solid var(--border)', background: '#060606',
        alignItems: 'center', flexWrap: 'wrap',
      }}>
        <button onClick={() => setAnimatedState(a => !a)} style={btnStyle(animated)}>
          {animated ? '[ ■ FIGER ]' : '[ ▶ ANIMER ]'}
        </button>
        <button onClick={resetLayout} style={btnStyle(false)}>[ ↺ RESET ]</button>
        <div style={{ width: 1, height: 16, background: 'var(--border)', flexShrink: 0 }} />
        {ALL_TRIGGERS.map(t => (
          <button key={t} onClick={() => toggleFilter(t)} style={{
            ...btnStyle(filters.has(t)),
            borderColor: filters.has(t) ? triggerColor(t) : triggerColor(t) + '44',
            color: filters.has(t) ? triggerColor(t) : '#445566',
          }}>
            {t.toUpperCase()}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 9, color: '#445566' }}>
          {nodeCount} endpoints · {visibleEdgeCount} arêtes · {flowMap?.db_tables.length ?? 0} tables
        </span>
      </div>

      {/* Main area */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* Canvas */}
        <div ref={containerRef} style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
          <canvas
            ref={canvasRef}
            style={{ position: 'absolute', inset: 0, cursor: 'crosshair', display: 'block' }}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            onWheel={handleWheel}
            onDoubleClick={handleDblClick}
            onClick={handleClick}
          />
        </div>

        {/* Detail panel */}
        <div style={{ width: 300, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderLeft: '1px solid var(--border)' }}>
          <div style={{
            fontFamily: 'var(--font-title)', fontSize: 9, padding: '7px 10px 5px',
            borderBottom: '1px solid var(--border)', background: '#060606',
            color: 'var(--green-dim)', letterSpacing: 2, flexShrink: 0,
          }}>
            <span style={{ color: 'var(--green)' }}>[ </span>DÉTAIL<span style={{ color: 'var(--green)' }}> ]</span>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: '10px 12px' }}>
            {!selected && (
              <div style={{ fontSize: 9, color: '#2a4a2a', letterSpacing: 1 }}>← Cliquer un nœud ou une arête</div>
            )}
            {selected?.type === 'node' && (
              <NodeDetail node={selected.data as NodeState} flowMap={flowMap} />
            )}
            {selected?.type === 'edge' && (
              <EdgeDetail edge={selected.data as FlowEdge} />
            )}
            {flowMap && flowMap.db_tables.length > 0 && (
              <DBTablesSection tables={flowMap.db_tables} />
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
