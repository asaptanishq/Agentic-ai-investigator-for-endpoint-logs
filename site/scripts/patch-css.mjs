// One-shot patcher: swaps the old constellation styles for blueprint styles.
import { readFileSync, writeFileSync } from 'node:fs'

const p = new URL('../src/styles.css', import.meta.url)
let c = readFileSync(p, 'utf8')

const cut = (a, b) => {
  const i = c.indexOf(a)
  const j = c.indexOf(b, i)
  if (i < 0 || j < 0) throw new Error(`marker missing: ${a.slice(-30)} / ${b.slice(-30)}`)
  return [i, j]
}

const world = `
/* --------------------------------------------------------------- drawing */

.drawing {
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
  z-index: 1;
  user-select: none;
}

#camera {
  transform-origin: 0 0;
  will-change: transform;
}

.bp-plate { cursor: pointer; }

.bp-sheet-frame { fill: none; stroke: rgba(222, 226, 228, 0.11); stroke-width: 1.4; }

.bp-sheet-tag {
  font-family: var(--mono);
  font-size: 13px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  fill: rgba(222, 226, 228, 0.28);
}

.bp-zone { font-family: var(--mono); font-size: 12px; fill: rgba(222, 226, 228, 0.14); }

.bp-titleblock rect,
.bp-titleblock path { fill: none; stroke: rgba(222, 226, 228, 0.14); stroke-width: 0.8; }

.bp-plate .bp-frame { fill: rgba(6, 7, 10, 0.62); stroke: rgba(222, 226, 228, 0.19); stroke-width: 1; }
.bp-plate[data-on='true'] .bp-frame { stroke: rgba(159, 185, 178, 0.42); }

.bp-corners { fill: none; stroke: rgba(159, 185, 178, 0.6); stroke-width: 1.2; }
.bp-rule { fill: none; stroke: rgba(222, 226, 228, 0.13); stroke-width: 0.8; }

.bp-plate-id {
  font-family: var(--mono);
  font-size: 10.5px;
  letter-spacing: 0.24em;
  text-transform: uppercase;
  fill: rgba(222, 226, 228, 0.28);
}

.bp-plate-title { font-family: var(--mono); font-size: 13.5px; letter-spacing: 0.16em; fill: rgba(222, 226, 228, 0.72); }
.bp-plate-sub { font-family: var(--mono); font-size: 10.5px; fill: rgba(222, 226, 228, 0.3); }

.bp-b rect { fill: rgba(222, 226, 228, 0.026); stroke: rgba(222, 226, 228, 0.25); stroke-width: 0.9; }
.bp-b--hot rect { fill: rgba(159, 185, 178, 0.07); stroke: rgba(159, 185, 178, 0.62); }
.bp-b--db rect { fill: none; stroke: rgba(159, 185, 178, 0.42); stroke-dasharray: 5 4; }
.bp-b--ok rect { stroke: rgba(134, 167, 149, 0.55); }
.bp-b--neg rect { stroke: rgba(176, 154, 168, 0.55); }
.bp-b--info rect { stroke: rgba(139, 159, 192, 0.55); }

.bp-t { font-family: var(--mono); font-size: 12px; fill: rgba(222, 226, 228, 0.86); }
.bp-t--sm { font-size: 10px; }
.bp-s { font-family: var(--mono); font-size: 9px; fill: rgba(222, 226, 228, 0.38); }
.bp-s--end { text-anchor: end; }

.bp-ar { fill: none; stroke: rgba(222, 226, 228, 0.28); stroke-width: 0.9; }
.bp-ar--dash { stroke: rgba(159, 185, 178, 0.5); stroke-dasharray: 3 4; }

.bp-al {
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  fill: rgba(159, 185, 178, 0.6);
}

.bp-arrowhead { fill: rgba(222, 226, 228, 0.4); }
.bp-arrowhead--a { fill: rgba(159, 185, 178, 0.75); }

.bp-note { font-family: var(--mono); font-size: 8.5px; fill: rgba(222, 226, 228, 0.26); }
.bp-mono { font-family: var(--mono); font-size: 10px; fill: rgba(222, 226, 228, 0.5); }
.bp-mono--sm { font-size: 9px; }

.bp-band {
  fill: rgba(222, 226, 228, 0.012);
  stroke: rgba(222, 226, 228, 0.09);
  stroke-width: 0.8;
  stroke-dasharray: 4 5;
}

.bp-band-t {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 0.24em;
  text-transform: uppercase;
  fill: rgba(222, 226, 228, 0.32);
}

.bp-sub { font-family: var(--mono); font-size: 9.5px; fill: rgba(222, 226, 228, 0.32); }
.bp-num { font-family: var(--mono); font-size: 8.5px; fill: rgba(222, 226, 228, 0.5); }

.bp-dim path { fill: none; stroke: rgba(222, 226, 228, 0.22); stroke-width: 0.7; }
.bp-dl { font-family: var(--mono); font-size: 8px; fill: rgba(222, 226, 228, 0.32); }
.bp-ld path { fill: none; stroke: rgba(159, 185, 178, 0.32); stroke-width: 0.7; }
.bp-ld circle { fill: var(--accent); opacity: 0.75; }
.bp-ll { font-family: var(--mono); font-size: 8.5px; fill: rgba(222, 226, 228, 0.46); }

.bp-link path { fill: none; stroke: rgba(159, 185, 178, 0.2); stroke-dasharray: 8 6; }
.bp-link .bp-al { fill: rgba(159, 185, 178, 0.36); letter-spacing: 0.2em; }

.bp-row rect,
.bp-row-rect { fill: none; stroke: rgba(222, 226, 228, 0.14); stroke-width: 0.8; }

.bp-ruler path { fill: none; stroke: rgba(222, 226, 228, 0.22); stroke-width: 0.8; }
.bp-ruler text { font-family: var(--mono); font-size: 8px; fill: rgba(222, 226, 228, 0.28); }

.bp-diamond { fill: rgba(159, 185, 178, 0.06); stroke: rgba(159, 185, 178, 0.45); stroke-width: 0.9; }
.bp-axis,
.bp-tick { fill: none; stroke: rgba(222, 226, 228, 0.3); stroke-width: 0.9; }
.bp-marker { fill: var(--accent); }

.bp-doc { fill: rgba(222, 226, 228, 0.016); stroke: rgba(222, 226, 228, 0.18); stroke-width: 0.9; }
.bp-doc-title { font-family: var(--mono); font-size: 11px; letter-spacing: 0.3em; fill: rgba(222, 226, 228, 0.72); }
.bp-fill { fill: none; stroke: rgba(222, 226, 228, 0.1); stroke-dasharray: 2 4; }

.bp-case rect { fill: none; stroke: rgba(222, 226, 228, 0.22); stroke-width: 0.9; }
.bp-case text { font-family: var(--mono); font-size: 9px; fill: rgba(222, 226, 228, 0.66); }
.bp-case--ok rect { stroke: rgba(134, 167, 149, 0.5); }
.bp-case--info rect { stroke: rgba(139, 159, 192, 0.5); }
.bp-case--ghost rect { stroke: rgba(222, 226, 228, 0.14); stroke-dasharray: 3 3; }

.bp-seg { stroke: #06070a; stroke-width: 1.2; }
.bp-seg--verd { fill: #9db6ae; }
.bp-seg--evid { fill: #8aa197; }
.bp-seg--grou { fill: #768c8d; }
.bp-seg--cali { fill: #6c828a; }
.bp-seg--effi { fill: #5d7078; }
.bp-seg--repo { fill: #4d5d64; }

.bp-lead { fill: none; stroke: rgba(222, 226, 228, 0.16); }
.bp-term { fill: rgba(222, 226, 228, 0.016); stroke: rgba(222, 226, 228, 0.16); }
.bp-prompt { font-family: var(--mono); font-size: 10px; fill: var(--accent); }
.bp-cmd { font-family: var(--mono); font-size: 9.5px; fill: rgba(222, 226, 228, 0.75); }

.bp-glyph { stroke: rgba(222, 226, 228, 0.3); stroke-width: 0.8; }
.bp-glyph--on { fill: var(--accent); stroke: var(--accent); }
.bp-glyph--off { fill: rgba(222, 226, 228, 0.28); }
.bp-glyph--info { stroke: var(--info); fill: none; }
.bp-glyph--neg { stroke: var(--neg); fill: none; }

.bp-legend text {
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: 0.12em;
  fill: rgba(222, 226, 228, 0.34);
}

.bp-print { display: none; }

`

let [i, j] = cut('/* ---------------------------------------------------------------- world */', '/* ---------------------------------------------------------------- chrome */')
c = c.slice(0, i) + world + c.slice(j)

const mini = `.mini-plate {
  fill: rgba(222, 226, 228, 0.03);
  stroke: rgba(222, 226, 228, 0.2);
  stroke-width: 0.7;
  cursor: pointer;
  transition: fill 0.25s ease, stroke 0.25s ease;
}

.mini-plate.is-active {
  fill: rgba(159, 185, 178, 0.14);
  stroke: rgba(159, 185, 178, 0.75);
}

.mini-view {
  fill: rgba(159, 185, 178, 0.06);
  stroke: rgba(159, 185, 178, 0.6);
  stroke-width: 0.7;
}

`
;[i, j] = cut('.mini-path {', '.readout {')
c = c.slice(0, i) + mini + c.slice(j)

const intake = `/* ---------------------------------------------------------------- intake */

.alert { padding: 0 0 0.4rem; }

.alert p {
  margin: 0;
  padding: 0.9rem 1.1rem 1rem;
  font-size: 0.86rem;
  line-height: 1.75;
  color: rgba(222, 226, 228, 0.72);
}

.tok {
  padding: 0.05rem 0.18rem;
  border-bottom: 1px solid;
  font-weight: 500;
  color: var(--ink);
}

.tok--host { border-color: rgba(159, 185, 178, 0.6); }
.tok--proc { border-color: rgba(176, 154, 168, 0.6); }
.tok--net { border-color: rgba(139, 159, 192, 0.6); }
.tok--time,
.tok--user { border-color: rgba(222, 226, 228, 0.3); }

.resolve { border-top: 1px dashed rgba(222, 226, 228, 0.1); }

.resolve-line {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  margin: 0;
  padding: 0.42rem 1.1rem;
  font-family: var(--mono);
  font-size: 0.64rem;
  line-height: 1.5;
  color: rgba(222, 226, 228, 0.62);
}

.resolve-line i { font-style: normal; color: rgba(222, 226, 228, 0.25); }
.resolve-line .ok { color: var(--ok); }
.resolve-line .warn { color: var(--neg); }

`
;[i, j] = cut('/* ---------------------------------------------------------------- intake */', '/* ---------------------------------------------------------------- triage */')
c = c.slice(0, i) + intake + c.slice(j)

const trace = `/* ---------------------------------------------------------------- loop */

.trace { border-top: 1px solid var(--line); }

.trace-head {
  display: flex;
  justify-content: space-between;
  padding: 0.6rem 1.1rem 0.25rem;
  font-family: var(--mono);
  font-size: 0.55rem;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: rgba(222, 226, 228, 0.28);
}

.trace-count { color: rgba(222, 226, 228, 0.62); letter-spacing: 0.08em; }
.trace-meter { display: flex; gap: 2px; padding: 0 1.1rem 0.7rem; }
.trace-meter i { flex: 1; height: 2px; background: rgba(222, 226, 228, 0.12); }
.trace-meter i.is-on { background: var(--accent); }

.trace-step {
  display: grid;
  grid-template-columns: 1.6rem minmax(0, 1fr);
  gap: 0.5rem;
  padding: 0.55rem 1.1rem 0.6rem;
  border-top: 1px dashed rgba(222, 226, 228, 0.08);
}

.trace-n { font-family: var(--mono); font-size: 0.6rem; color: rgba(222, 226, 228, 0.26); }

.trace-tool { display: block; font-family: var(--mono); font-size: 0.66rem; color: rgba(222, 226, 228, 0.9); }

.trace-args {
  display: block;
  margin-top: 0.15rem;
  font-family: var(--mono);
  font-size: 0.58rem;
  line-height: 1.5;
  color: rgba(222, 226, 228, 0.3);
  overflow-wrap: anywhere;
}

.trace-result { margin: 0.3rem 0 0; font-family: var(--mono); font-size: 0.6rem; line-height: 1.5; color: var(--accent); }

.trace-foot {
  margin: 0;
  padding: 0.6rem 1.1rem 0.8rem;
  border-top: 1px dashed rgba(222, 226, 228, 0.08);
  font-family: var(--mono);
  font-size: 0.55rem;
  line-height: 1.6;
  color: rgba(222, 226, 228, 0.26);
}

`
;[i, j] = cut('/* ---------------------------------------------------------------- loop */', '/* ---------------------------------------------------------------- evidence */')
c = c.slice(0, i) + trace + c.slice(j)

const spine = `/* ------------------------------------------------------------ architecture */

.spine { display: flex; flex-direction: column; border-top: 1px solid var(--line); }

.spine-row {
  display: grid;
  grid-template-columns: 1.6rem minmax(0, 1fr) auto;
  align-items: baseline;
  gap: 0.6rem;
  padding: 0.5rem 1.1rem;
  border-bottom: 1px dashed rgba(222, 226, 228, 0.07);
  position: relative;
}

.spine-row::before {
  content: '';
  position: absolute;
  left: 1.72rem;
  top: 0;
  bottom: 0;
  width: 1px;
  background: rgba(222, 226, 228, 0.1);
}

.spine-n { font-family: var(--mono); font-size: 0.55rem; color: rgba(222, 226, 228, 0.24); }
.spine-name {
  font-family: var(--mono);
  font-size: 0.68rem;
  color: rgba(222, 226, 228, 0.86);
  background: #0a0c0f;
  padding-right: 0.35rem;
}
.spine-row--hot .spine-name { color: var(--accent); }
.spine-note { font-family: var(--mono); font-size: 0.55rem; color: rgba(222, 226, 228, 0.3); text-align: right; }

`
;[i, j] = cut('/* ---------------------------------------------------------------- architecture */', '/* ---------------------------------------------------------------- audit */')
c = c.slice(0, i) + spine + c.slice(j)

const bench = `/* ---------------------------------------------------------------- benchmark */

.rubric { padding: 0.7rem 1.1rem 0.5rem; border-top: 1px solid var(--line); }

.rubric-row {
  display: grid;
  grid-template-columns: 4.6rem minmax(0, 1fr) 1.4rem;
  align-items: center;
  gap: 0.6rem;
  padding: 0.22rem 0;
  font-family: var(--mono);
  font-size: 0.58rem;
}

.rubric-label { color: rgba(222, 226, 228, 0.5); letter-spacing: 0.06em; }
.rubric-track { height: 6px; background: rgba(222, 226, 228, 0.07); }
.rubric-track i { display: block; height: 100%; background: linear-gradient(90deg, #9db6ae, #5d7078); }
.rubric-n { text-align: right; color: rgba(222, 226, 228, 0.72); }

.rubric-total {
  margin-top: 0.45rem;
  padding-top: 0.45rem;
  border-top: 1px dashed rgba(222, 226, 228, 0.08);
  font-family: var(--mono);
  font-size: 0.55rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: rgba(222, 226, 228, 0.26);
}

`
;[i, j] = cut('/* ---------------------------------------------------------------- benchmark */', '/* ---------------------------------------------------------------- run */')
c = c.slice(0, i) + bench + c.slice(j)

c = c.replace(`  .arch-scroll .arch {
    min-width: 520px;
  }
`, '')

c = c.replace(`  .sat-label,
  .edge-label {
    display: none;
  }
`, '')

c = c.replace(`  .tools th:nth-child(3),
  .tools td:nth-child(3) {
    display: none;
  }
`, '')

c = c.replace(`  .resolve-row,
  .claim,
  .cmd,
  .tools td,
  .tools th,
  .note,
  .term-row,
  .term-comment,
  .lexicon,
  .hot-foot {
    padding-left: 0.85rem;
    padding-right: 0.85rem;
  }`, `  .resolve-line,
  .claim,
  .cmd,
  .note,
  .term-row,
  .term-comment,
  .lexicon,
  .hot-foot,
  .trace-step,
  .spine-row,
  .rubric,
  .trace-head,
  .trace-foot {
    padding-left: 0.85rem;
    padding-right: 0.85rem;
  }
  .trace-meter {
    padding-left: 0.85rem;
    padding-right: 0.85rem;
  }
  .spine-row::before {
    left: 1.47rem;
  }`)

c = c.replace(`  .spine-trace,
  .pulse,
  .anchor-focus {
    animation: none !important;
  }`, `  .panel * {
    animation: none !important;
  }`)

writeFileSync(p, c)
console.log('styles.css patched:', c.length, 'bytes')
