// Camera math and minimap projection, kept pure so scripts/check.mjs can
// exercise it without a browser.

export const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v))

export const ease = (t) => t * t * (3 - 2 * t)

export function camAt(stations, p) {
  const last = stations.length - 1
  const q = clamp(p, 0, last)
  const i = Math.min(last, Math.floor(q))
  const j = Math.min(last, i + 1)
  const t = ease(q - i)
  const a = stations[i]
  const b = stations[j]
  return {
    x: a.x + (b.x - a.x) * t,
    y: a.y + (b.y - a.y) * t,
    z: a.z + (b.z - a.z) * t,
  }
}

export function stationAt(p, count) {
  return Math.round(clamp(p, 0, count - 1))
}

export const PLATE_W = 780

export const PLATE_H = 520

// Right-hand nav rail keeps its own lane; the plate is fitted into whatever
// is left between the text panel and that rail.
export function focusFor(w, h) {
  const mobile = w < 860
  if (mobile) {
    return {
      mobile,
      fx: w * 0.5,
      fy: h * 0.27,
      zoom: clamp(0.46, 0.6, w / PLATE_W),
    }
  }
  const panelW = Math.min(540, w * 0.44)
  const panelRight = Math.max(w * 0.05, 64) + panelW
  const avail = Math.max(260, w - panelRight - 56 - 140)
  const zoom = clamp(0.5, 0.92, avail / PLATE_W)
  return {
    mobile,
    fx: panelRight + 18 + (PLATE_W * zoom) / 2,
    fy: h * 0.47,
    zoom,
  }
}

export function buildMap(stations, W = 240, H = 104, pad = 16, mx = PLATE_W / 2, my = PLATE_H / 2) {
  const xs = stations.map((s) => s.x)
  const ys = stations.map((s) => s.y)
  const minX = Math.min(...xs) - mx
  const maxX = Math.max(...xs) + mx
  const minY = Math.min(...ys) - my
  const maxY = Math.max(...ys) + my
  // the world is ~11k wide and ~1k tall: stretch each axis so the minimap
  // reads as a route instead of a horizontal thread
  const sx = (W - pad * 2) / (maxX - minX)
  const sy = (H - pad * 2) / (maxY - minY)
  const ox = (W - (maxX - minX) * sx) / 2 - minX * sx
  const oy = (H - (maxY - minY) * sy) / 2 - minY * sy
  return { W, H, sc: Math.min(sx, sy), at: (x, y) => [x * sx + ox, y * sy + oy] }
}
