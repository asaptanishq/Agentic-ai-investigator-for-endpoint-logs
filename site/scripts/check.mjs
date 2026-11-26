// Self-check for the camera + minimap math. Run with `npm run check`.
import assert from 'node:assert/strict'
import { STATIONS } from '../src/data.js'
import { camAt, stationAt, focusFor, buildMap, clamp, ease, PLATE_W, PLATE_H } from '../src/camera.js'

assert.equal(STATIONS.length, 9, 'nine stations')
assert.equal(new Set(STATIONS.map((s) => s.id)).size, 9, 'station ids unique')
assert.equal(new Set(STATIONS.map((s) => `${s.x},${s.y}`)).size, 9, 'stations do not overlap')
assert.deepEqual(STATIONS.map((s) => s.num), ['01','02','03','04','05','06','07','08','09'])

for (const s of STATIONS) {
  assert.ok(s.nodes.length >= 4, `${s.id} has entities to draw`)
  assert.ok(s.z > 0.5 && s.z < 2, `${s.id} zoom sane`)
}

// camera lands exactly on each station at integer progress
STATIONS.forEach((s, i) => {
  const c = camAt(STATIONS, i)
  assert.equal(c.x, s.x)
  assert.equal(c.y, s.y)
  assert.equal(c.z, s.z)
})

// clamps past both ends instead of extrapolating
const start = camAt(STATIONS, -3)
const end = camAt(STATIONS, 99)
assert.equal(start.x, STATIONS[0].x)
assert.equal(end.x, STATIONS[8].x)

// progress -> nearest station
assert.equal(stationAt(0, 9), 0)
assert.equal(stationAt(8, 9), 8)
assert.equal(stationAt(3.49, 9), 3)
assert.equal(stationAt(3.51, 9), 4)
assert.equal(stationAt(42, 9), 8)

// interpolation stays between neighbours
const mid = camAt(STATIONS, 0.5)
assert.ok(mid.x > STATIONS[0].x && mid.x < STATIONS[1].x)
assert.equal(ease(0), 0)
assert.equal(ease(1), 1)
assert.equal(ease(0.5), 0.5)
assert.equal(clamp(9, 0, 1), 1)

// the plate is fitted between the text panel and the nav rail
const desk = focusFor(1440, 900)
const half = (PLATE_W * desk.zoom) / 2
const panelRight = Math.max(1440 * 0.05, 64) + Math.min(540, 1440 * 0.44)
assert.ok(desk.fx - half >= panelRight, 'plate clears the panel on desktop')
assert.ok(desk.fx + half <= 1440 - 160, 'plate stays left of the nav rail')
assert.ok(desk.zoom >= 0.5 && desk.zoom <= 0.92, 'desktop zoom clamped')

const wide = focusFor(1920, 1080)
const wideHalf = (PLATE_W * wide.zoom) / 2
assert.ok(wide.fx - wideHalf >= Math.max(1920 * 0.05, 64) + Math.min(540, 1920 * 0.44), 'wide plate clears the panel')

const phone = focusFor(390, 844)
assert.ok(phone.mobile && phone.fy < 844 * 0.4, 'drawing sits above the sheet on mobile')
assert.ok(phone.zoom * PLATE_W <= 390, 'whole plate fits the phone width')
assert.ok(phone.zoom * PLATE_W >= 340, 'plate does not shrink into noise')

// every plate lands inside the minimap box, margins included
const map = buildMap(STATIONS, 240, 104, 16)
for (const s of STATIONS) {
  const [x, y] = map.at(s.x, s.y)
  assert.ok(x > 0 && x < map.W, `${s.id} minimap x in bounds`)
  assert.ok(y > 0 && y < map.H, `${s.id} minimap y in bounds`)
  const [x1, y1] = map.at(s.x - PLATE_W / 2, s.y - PLATE_H / 2)
  const [x2, y2] = map.at(s.x + PLATE_W / 2, s.y + PLATE_H / 2)
  assert.ok(x1 >= 0 && x2 <= map.W, `${s.id} plate inside minimap width`)
  assert.ok(y1 >= 0 && y2 <= map.H, `${s.id} plate inside minimap height`)
}

console.log('camera + minimap: 9 stations, all assertions passed')
