import { useEffect, useMemo, useRef, useState } from 'react'
import Blueprint from './Blueprint'
import { STATIONS } from './data'
import { Panel } from './content'
import { camAt, focusFor, buildMap, stationAt, PLATE_W, PLATE_H } from './camera'

const N = STATIONS.length

export default function App() {
  const camRef = useRef(null)
  const barRef = useRef(null)
  const rectRef = useRef(null)
  const edgeRef = useRef(null)
  const smooth = useRef({ x: STATIONS[0].x, y: STATIONS[0].y, z: STATIONS[0].z })
  const activeRef = useRef(0)
  const [active, setActive] = useState(0)
  const [focus, setFocus] = useState(() => focusFor(window.innerWidth, window.innerHeight))

  const map = useMemo(() => buildMap(STATIONS, 240, 104, 14), [])
  const plates = useMemo(
    () =>
      STATIONS.map((s) => {
        const [x, y] = map.at(s.x - PLATE_W / 2, s.y - PLATE_H / 2)
        const [x2, y2] = map.at(s.x + PLATE_W / 2, s.y + PLATE_H / 2)
        return { x, y, w: x2 - x, h: y2 - y }
      }),
    [map]
  )

  useEffect(() => {
    const onResize = () => setFocus(focusFor(window.innerWidth, window.innerHeight))
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  useEffect(() => {
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let raf
    const tick = () => {
      const max = document.documentElement.scrollHeight - window.innerHeight
      const p = max > 0 ? (window.scrollY / max) * (N - 1) : 0
      const t = camAt(STATIONS, p)
      const s = smooth.current
      const k = still ? 1 : 0.085
      s.x += (t.x - s.x) * k
      s.y += (t.y - s.y) * k
      s.z += (t.z - s.z) * k

      const z = s.z * focus.zoom
      if (camRef.current) {
        camRef.current.style.transform = `translate(${(focus.fx - s.x * z).toFixed(2)}px, ${(
          focus.fy -
          s.y * z
        ).toFixed(2)}px) scale(${z.toFixed(4)})`
      }

      const q = p
      // the minimap viewport is whatever the camera actually shows
      if (rectRef.current) {
        const vw = window.innerWidth
        const vh = window.innerHeight
        const [x0, y0] = map.at(s.x - focus.fx / z, s.y - focus.fy / z)
        const [x1, y1] = map.at(s.x + (vw - focus.fx) / z, s.y + (vh - focus.fy) / z)
        rectRef.current.setAttribute('x', x0.toFixed(1))
        rectRef.current.setAttribute('y', y0.toFixed(1))
        rectRef.current.setAttribute('width', Math.max(6, x1 - x0).toFixed(1))
        rectRef.current.setAttribute('height', Math.max(6, y1 - y0).toFixed(1))
      }
      if (edgeRef.current) {
        // right fade must start after the plate, never over it
        const room = window.innerWidth - (focus.fx + (PLATE_W * z) / 2) - 16
        edgeRef.current.style.width = `${Math.max(0, Math.min(260, room)).toFixed(0)}px`
      }
      if (barRef.current) barRef.current.style.transform = `scaleX(${(q / (N - 1)).toFixed(4)})`

      const idx = stationAt(p, N)
      if (idx !== activeRef.current) {
        activeRef.current = idx
        setActive(idx)
      }
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [focus, map])

  const jump = (i) => {
    const max = document.documentElement.scrollHeight - window.innerHeight
    window.scrollTo({ top: (i / (N - 1)) * max, behavior: 'smooth' })
  }

  const station = STATIONS[active]

  return (
    <div className="app">
      <h1 className="sr-only">A1 — autonomous DFIR investigator, documentation</h1>
      <div className="topbar" aria-hidden="true">
        <span className="bar-fill" ref={barRef} />
      </div>

      <Blueprint cameraRef={camRef} active={active} onNavigate={jump} />
      <div className="scrim" aria-hidden="true" />
      <div className="edge-scrim" ref={edgeRef} aria-hidden="true" />
      <div className="vignette" aria-hidden="true" />
      <header className="masthead">
        <span className="mark">A1</span>
        <span className="mark-rule" aria-hidden="true" />
        <span className="masthead-note">
          autonomous DFIR
          <br />
          system drawing
        </span>
      </header>

      <a
        className="gh"
        href="https://github.com/asaptanishq/Agentic-ai-investigator-for-endpoint-logs"
        target="_blank"
        rel="noreferrer"
      >
        github <span aria-hidden="true">↗</span>
      </a>

      <main className="stage" id="case">
        <Panel station={station} index={active} onNext={() => jump(active + 1)} />
      </main>

      <nav className="rail" aria-label="Case stations">
        {STATIONS.map((s, i) => (
          <button
            key={s.id}
            className={`rail-link${i === active ? ' is-active' : ''}`}
            onClick={() => jump(i)}
            aria-current={i === active ? 'step' : undefined}
            title={s.label}
          >
            <span className="rail-num">{s.num}</span>
            <span className="rail-label">{s.label}</span>
          </button>
        ))}
      </nav>

      <div className="minimap">
        <svg viewBox={`0 0 ${map.W} ${map.H}`} aria-hidden="true">
          {plates.map((b, i) => (
            <rect
              key={STATIONS[i].id}
              x={b.x}
              y={b.y}
              width={b.w}
              height={b.h}
              className={`mini-plate${i === active ? ' is-active' : ''}`}
              onClick={() => jump(i)}
            />
          ))}
          <rect ref={rectRef} className="mini-view" x="0" y="0" width="30" height="14" />
        </svg>
        <div className="readout">
          <span className="readout-num">{station.num}</span>
          <span className="readout-label">{station.rail}</span>
        </div>
      </div>

      <p className={`hint${active > 0 ? ' is-gone' : ''}`}>scroll to follow the chain</p>

      <div className="spacer" style={{ height: `${N * 100}vh` }} aria-hidden="true" />
    </div>
  )
}
