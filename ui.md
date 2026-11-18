# A1 Investigator — UI design record

Status: rewritten 2026-11-18 (workstream B). Supersedes both earlier drafts — see *Why the previous drafts failed*.
Dark only; single purpose: an analyst triaging endpoint telemetry → verdict + evidence graph.

## Why the previous drafts failed

1. The 2026-11-17 draft described a full-screen evidence overlay and "the conversation is the workspace". The markup
   that shipped had a **collapsed third column** instead, so the graph was invisible by default and 35% of the screen
   was empty. The design record and the product did not describe the same thing.
2. Information architecture was chat-first: a giant centred "Start an investigation" hero, a 200px-tall empty
   sidebar, ten scenario rows, and a floating composer on top of the list. That is the generic AI-dashboard shape
   the user objected to. Palette work (true black, hairlines) did not fix an IA problem.
3. Controls were decorative: the scenario "All / Active DB / Attacks / Benign / Gaps" filter only matched the
   literal string `"alert"`, so Benign/Gaps did nothing; a `Sample` dropdown injected hard-coded fake events;
   `cancelled` SSE events were unhandled so the UI stayed in "generating" forever; dataset switch failures used
   `alert()`; `/api/events` returns HTTP 200 with an `error` field and the UI ignored it.

## Direction — "case board"

*Three fixed surfaces, one case. The rail is the case index, the bench is the record of reasoning, the map is the
evidence board. Nothing is a card; hierarchy comes from hairline rules, background steps and type, never from
gradients, glow, glass, pills or hero type.*

| Decision | Choice | Why |
| --- | --- | --- |
| Layout | Three panes side by side at ≥1180px: rail 264px · bench (flex) · case map `min(52vw, 760px)` | Triage reads left-to-right: what case → what was asked → what the evidence says. The map is visible while the investigation streams, which is the whole point of an evidence graph. |
| Map default | Open on desktop, overlay drawer ≤1180px, closes with Esc/Ctrl+M | Previously hidden; now the centrepiece. On narrow screens it must not kill the bench, so it slides over. |
| Bench | Left-aligned record: user line, then a five-step run (prepare/plan/collect/pack/verdict) with hypotheses, evidence pack and verdict | Progress is the honest thing to show: the backend really emits those stages. No fake typing indicator. |
| Welcome | Compact case briefing inside the bench, not a hero: dataset facts (events, hosts, span), starting points as a dense list | Turns the empty state into triage context from real `/api/events` counts. |
| Accent | One signal colour (amber `#e0a33c`) reserved for *running* state; verdict colours only on verdict surface | Colour means state, never decoration. |
| Entity colour | Low-chroma hues per real entity type, used **only** in the map, legend and inspector | The map is the only place hue carries meaning. |
| Type | Inter for prose/UI, JetBrains Mono for ids, timestamps, counts, process paths | Investigators scan machine strings; mono keeps columns aligned. |
| Density | 13px body, 12px controls, 11px labels, 1.55 prose, 26px table rows, 8px spacing grid | Dense but not cramped: an analyst reads dozens of events per screen. |
| Motion | 120ms ease-out on opacity/transform only; no layout animation, no glow, no gradients | Nothing should move while evidence is being read. |

Explicitly rejected: dashboard cards, gradient/glow decoration, glassmorphism, pill soup, fake metrics, giant hero
headings, arbitrary animation, placeholder/demo data presented as real.

## Tokens

| Token | Value | Use |
| --- | --- | --- |
| `--ink-0` | `#08090a` | app ground (bench) |
| `--ink-1` | `#0b0c0e` | rail / map ground |
| `--ink-2` | `#101215` | raised rows, inputs, table head |
| `--ink-3` | `#16191d` | hover, active segment, user line |
| `--line` | `#1e2126` | pane dividers |
| `--line-2` | `#2a2e34` | control borders |
| `--text` | `#e6e9ec` | primary |
| `--text-2` | `#a0a7b0` | secondary |
| `--text-3` | `#6c747d` | metadata |
| `--text-4` | `#4a5058` | disabled / rule labels |
| `--signal` | `#e0a33c` | running state, focus ring |
| `--ok` / `--bad` / `--info` | `#4fa87a` / `#d9534f` / `#5b9df0` | verdict + error + link |
| Entity hues | host `#8b98a5`, user `#e08bc0`, process `#5b9df0`, file `#4fb6a6`, registry `#b6a04e`, ip `#57c7d4`, domain `#7fd1ac`, alert `#e5664f` | map only |

Type scale: 11 (label, mono, uppercase 0.06em) · 12 (controls, rows) · 13 (body) · 15 (section) · 19 (case title) ·
24 (welcome). Spacing: 4/8/12/16/24/32. Radii: 3px controls, 4px panels/rows; no pills except count badges.

## Entity and relationship vocabulary

The map is built from `src/a1/evidence_graph.py` `EntityType` / `RelationshipType` and normalises the raw telemetry
shapes that actually exist in the bundled datasets (flat ECS dotted keys, nested ECS, Suricata, Wazuh). It never
invents a node kind. Types rendered: host, user, process, file, registry_artifact, ip_address, domain, alert.
Relationships: observed_on, spawned, authenticated_to, connected_to, resolved, created/modified/accessed (file and
registry actions), associated_with (alert → anchor). Edges are drawn with an arrowhead at the target and a label at
zoom ≥ 0.62.

## Layout

```
┌ rail 264 ┬──────── bench ────────┬── case map (52vw, max 760) ──┐
│ dataset  │ topbar: case · stamp  │ Map | Events | Report   status│
│ surface  │                       │ toolbar: search zoom fit reset│
│ case log │ record of the run     │ canvas            │ inspector│
│          │ composer              │ legend from real types present│
└──────────┴───────────────────────┴──────────────────────────────┘
```

Rail: brand, New investigation, dataset select + indexed hint, entity surface (real counts per type, click filters
the map), case log (localStorage `a1_case_log_v2`, restore/delete/clear), status + shortcuts.
Topbar: rail toggle, case name + facts, verdict stamp, case-map toggle with node count, model pill → menu.
Welcome: kicker, one-line title, one-paragraph explainer, four dataset facts, starting points with a working filter
(All / This dataset / Attack / Benign / Ambiguous).
Composer: textarea, meta line (model · dataset · hint), send square that becomes a stop square while running.

## Behaviour contract (every control)

| Control | Behaviour |
| --- | --- |
| Dataset select | `POST /api/databases/set`, reloads `/api/events`, rebuilds the map, disabled while generating, reverts + toast on failure |
| Starting point | Switches dataset first if needed, fills the prompt, submits once |
| Send / stop | Enter submits; while generating the same button is Stop → `POST /api/cancel` + aborts the stream; no double submit |
| Model pill | Popover with provider tabs from `/api/models`, filter, custom id; `POST /api/models/set`; closed by Esc/outside click |
| Case map toggle | Opens/closes the map pane; Ctrl+M; state persisted |
| Map toolbar | Search (highlights + dims), zoom ±, Fit, Reset (search/filters/scope/selection) |
| Legend | Generated from types present; each chip toggles that type |
| Node | Click selects, inspector shows attributes, relations (navigable), source events (jump to the filtered events tab); drag moves, dblclick focuses, background drag pans, wheel zooms, keyboard arrows/±/0 work when canvas is focused |
| Inspector | Focus, isolate neighbourhood, copy node id, close |
| Evidence pack | "Scope map to evidence" isolates the nodes touched by the kept event ids; "Show in events" |
| Events tab | Search over host/action/process/summary/id, count, Copy CSV |
| Report tab | Rendered markdown (sanitised), verdict tag, copy markdown |
| Case log | Restore a saved run (verdict + report), delete one, clear all with confirm |
| Shortcuts | `?` popover; Esc closes menu/inspector/map/drawer in that order |

Unavailable actions get a real disabled state or an explicit toast — never a fake success.

## Files

- `src/a1/web/static/index.html` — shell (ids stable for JS and for `tests/test_web.py`).
- `src/a1/web/static/style.css` — all classes emitted by `app.js` and `forensic-graph.js`.
- `src/a1/web/static/app.js` — controller: API, SSE, map wiring, views, history.
- `src/a1/web/static/forensic-graph.js` — `TelemetryGraph.build` normaliser/builder + `ForensicGraph` canvas renderer.

## Backend changes

None. Every contract traced during the audit (`/api/status`, `/api/models`, `/api/databases`, `/api/events`,
`/api/investigate`, `/api/chat`, `/api/cancel`) matched what the UI needs; `/api/events` returning HTTP 200 with an
`error` field is handled in the client by throwing and rendering the failure state, so no server edit was required.
