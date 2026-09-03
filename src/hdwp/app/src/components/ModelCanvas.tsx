import { useRef, useEffect, useMemo } from 'react'
import { useScanStore } from '../stores/scanStore'
import { useFindingsStore } from '../stores/findingsStore'

const W = 540, H = 210, PAD = 25, CX = W / 2, CY = H / 2
const RADIUS = 80, MAX_NODES = 12, NODE_R = 10, CENTER_R = 16

function truncate(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

function clamp(v: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, v))
}

export function ModelCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const animRef = useRef<number>(0)
  const { target, endpoints } = useScanStore()
  const { findings } = useFindingsStore()

  const affectedPaths = useMemo(() => {
    const s = new Set<string>()
    for (const f of findings) {
      for (const ep of f.affected_endpoints) s.add(ep)
    }
    return s
  }, [findings])

  const visibleNodes = useMemo(() => {
    if (endpoints.length === 0) return []
    const withFinding = endpoints.filter(e => affectedPaths.has(e.path))
    const without = endpoints.filter(e => !affectedPaths.has(e.path))
    return [...withFinding, ...without].slice(0, MAX_NODES)
  }, [endpoints, affectedPaths])

  const overflow = endpoints.length - visibleNodes.length

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')!

    const satellites = visibleNodes.map((ep, i) => {
      const angle = (2 * Math.PI * i) / Math.max(visibleNodes.length, 1) - Math.PI / 2
      const rawX = CX + RADIUS * Math.cos(angle)
      const rawY = CY + RADIUS * Math.sin(angle)
      const hasFind = affectedPaths.has(ep.path)
      const color = hasFind ? '#ff0066' : ep.auth_required ? '#ffd700' : '#00ccff'
      return {
        x: clamp(rawX, PAD, W - PAD),
        y: clamp(rawY, PAD, H - PAD),
        label: truncate(ep.path, 15),
        color,
        vuln: hasFind,
      }
    })

    const edges = satellites.map((_, i) => [i] as [number])

    const packets = Array.from({ length: Math.min(satellites.length * 2, 8) }, () => {
      const idx = Math.floor(Math.random() * Math.max(satellites.length, 1))
      return { idx, t: Math.random(), speed: 0.005 + Math.random() * 0.008 }
    })

    let pulse = 0, scanAngle = 0

    const draw = () => {
      ctx.clearRect(0, 0, W, H)
      ctx.fillStyle = '#060606'
      ctx.fillRect(0, 0, W, H)

      // Grid
      ctx.strokeStyle = '#00ff4106'
      ctx.lineWidth = 0.5
      for (let gx = 0; gx < W; gx += 25) {
        ctx.beginPath(); ctx.moveTo(gx, 0); ctx.lineTo(gx, H); ctx.stroke()
      }
      for (let gy = 0; gy < H; gy += 25) {
        ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(W, gy); ctx.stroke()
      }

      // Radar sweep
      ctx.save()
      ctx.translate(CX, CY)
      ctx.rotate(scanAngle)
      const sg = ctx.createLinearGradient(0, 0, 120, 0)
      sg.addColorStop(0, '#00ff4133')
      sg.addColorStop(1, 'transparent')
      ctx.fillStyle = sg
      ctx.beginPath(); ctx.moveTo(0, 0); ctx.arc(0, 0, 120, -0.18, 0.18); ctx.closePath(); ctx.fill()
      ctx.restore()

      // Orbit circles
      ;[45, 85, 120].forEach(r => {
        ctx.beginPath(); ctx.arc(CX, CY, r, 0, Math.PI * 2)
        ctx.strokeStyle = '#00ff4109'; ctx.lineWidth = 0.5; ctx.stroke()
      })

      if (satellites.length === 0) {
        // Placeholder
        ctx.fillStyle = '#006633'
        ctx.font = '10px Share Tech Mono'
        ctx.textAlign = 'center'
        ctx.fillText('En attente de découverte...', CX, CY + 4)
      } else {
        // Edges (center → satellites)
        edges.forEach(([i]) => {
          const s = satellites[i]
          ctx.beginPath(); ctx.moveTo(CX, CY); ctx.lineTo(s.x, s.y)
          ctx.strokeStyle = s.vuln ? '#ff006622' : '#00ff4118'
          ctx.lineWidth = 1; ctx.setLineDash([3, 5]); ctx.stroke(); ctx.setLineDash([])
        })

        // Packets
        packets.forEach(pk => {
          if (pk.idx >= satellites.length) return
          const s = satellites[pk.idx]
          const px = CX + (s.x - CX) * pk.t
          const py = CY + (s.y - CY) * pk.t
          ctx.beginPath(); ctx.arc(px, py, 2, 0, Math.PI * 2)
          ctx.fillStyle = '#00ff4188'; ctx.fill()
          pk.t += pk.speed
          if (pk.t > 1) { pk.t = 0; pk.idx = Math.floor(Math.random() * satellites.length) }
        })

        // Satellite nodes
        satellites.forEach((s, i) => {
          const g = Math.sin(pulse + i * 0.8) * 0.25 + 0.75
          const a = Math.floor(g * 30).toString(16).padStart(2, '0')
          // Glow
          ctx.beginPath(); ctx.arc(s.x, s.y, NODE_R + 5, 0, Math.PI * 2)
          ctx.fillStyle = s.color + a; ctx.fill()
          // Body
          ctx.beginPath(); ctx.arc(s.x, s.y, NODE_R, 0, Math.PI * 2)
          ctx.fillStyle = '#060606'; ctx.fill()
          ctx.strokeStyle = s.color; ctx.lineWidth = 1.5; ctx.stroke()
          // Vuln ring
          if (s.vuln) {
            ctx.beginPath()
            ctx.arc(s.x, s.y, NODE_R + 9 + Math.sin(pulse + i) * 3, 0, Math.PI * 2)
            ctx.strokeStyle = '#ff006633'; ctx.lineWidth = 1; ctx.stroke()
          }
          // Label
          ctx.fillStyle = s.color
          ctx.font = '7px Share Tech Mono'
          ctx.textAlign = 'center'
          ctx.fillText(s.label, s.x, s.y + 2.5)
        })
      }

      // Central node (TARGET)
      const centerGlow = Math.sin(pulse) * 0.25 + 0.75
      const centerAlpha = Math.floor(centerGlow * 30).toString(16).padStart(2, '0')
      ctx.beginPath(); ctx.arc(CX, CY, CENTER_R + 7, 0, Math.PI * 2)
      ctx.fillStyle = '#00ff88' + centerAlpha; ctx.fill()
      ctx.beginPath(); ctx.arc(CX, CY, CENTER_R, 0, Math.PI * 2)
      ctx.fillStyle = '#060606'; ctx.fill()
      ctx.strokeStyle = '#00ff88'; ctx.lineWidth = 2; ctx.stroke()
      ctx.fillStyle = '#00ff88'
      ctx.font = 'bold 7px Share Tech Mono'
      ctx.textAlign = 'center'
      ctx.fillText(target ? truncate(target.replace(/^https?:\/\//, ''), 20) : 'TARGET', CX, CY + 2.5)

      // Overflow counter
      if (overflow > 0) {
        ctx.fillStyle = '#445566'
        ctx.font = '9px Share Tech Mono'
        ctx.textAlign = 'right'
        ctx.fillText(`+${overflow} autres`, W - 10, H - 8)
      }

      pulse += 0.035
      scanAngle += 0.012
      animRef.current = requestAnimationFrame(draw)
    }

    draw()
    return () => cancelAnimationFrame(animRef.current)
  }, [visibleNodes, affectedPaths, target, overflow])

  return (
    <div style={{ background: '#060606', borderBottom: '1px solid var(--border)', position: 'relative', height: 210, flexShrink: 0 }}>
      <div style={{ position: 'absolute', top: 7, left: 10, fontFamily: 'var(--font-title)', fontSize: 8, color: '#2a4a2a', letterSpacing: 2, zIndex: 3 }}>
        MODÈLE COMPORTEMENTAL — GRAPHE APPLICATIF
      </div>
      <canvas ref={canvasRef} width={W} height={H} style={{ position: 'absolute', inset: 0 }} />
    </div>
  )
}
