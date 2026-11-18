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

*Two fixed surfaces and an evidence drawer. The topbar is the case switchboard, the bench is the record of
reasoning, the drawer is the evidence board. Nothing is a card; hierarchy comes from hairline rules, background steps and type, never from
gradients, glow, glass, pills or hero type.*

| Decision | Choice | Why |
| --- | --- | --- |
| Layout | Topbar · bench (flex) · evidence drawer (default closed, drag-resizable 380–900px) | Triage reads top-to-bottom: which dataset → what was asked → what the evidence says. The drawer opens beside the record only when the analyst needs it, so the bench keeps full width while a run streams. |
| Dataset / case log | Both live in the `#caseMenu` popover opened from the dataset button in the topbar | Replaces the old 264px rail, which spent a third of the screen on navigation. The popover keeps dataset selection, history restore/delete/clear and workspace status one click away. |
| Evidence drawer | Tabs Map / Events / Report; Map offers Tree and Links modes, a filter, type legend and Collapse; Ctrl+E or the Evidence button opens it, Esc closes it | One surface for every piece of evidence, sized by the analyst. Tree mode is the hierarchical entity/artifact view; Links mode is the process-relationship view. |
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
registry actions), associated_with (alert → anchor). Tree and Links render the same graph; Tree groups by entity and
artifact, Links groups by process ancestry.

## Layout

```
┌ topbar: brand · new case · dataset/case menu · facts ─ verdict · evidence · model · shortcuts ┐
├──────────────────── bench (flex) ──────────────────────┴─ evidence drawer (resizable) ─┤
│ welcome: dataset facts, starting points                      │ Map | Events | Report          │
│ record of the run: user line, stages, hypotheses, pack      │ Map: Tree | Links · filter     │
│ composer                                                     │ legend · inspector             │
└──────────────────────────────────────────────────────────────┴────────────────────────────────┘
```

The topbar replaces the old rail. Brand, New investigation, the dataset button (opens `#caseMenu`: datasets list + case log + local workspace status), dataset facts, verdict stamp, Evidence button with count, model pill → menu, shortcuts. The evidence drawer is an `<aside>` toggled by the Evidence button or Ctrl+E; it can be resized by dragging its grip (380–900px) and closed with Esc. It is closed by default so the bench owns the screen until evidence is requested.

Main bench: welcome (case kicker, dataset title, facts, starting points with All / This dataset / Attack / Benign / Ambiguous filter), streamed turns, and the composer (textarea, model · dataset meta, send button that becomes stop while running).

## Behaviour contract (every control)

| Control | Behaviour |
| --- | --- |
| Dataset button | Opens `#caseMenu` with the real `/api/databases` list, indexed hint, case log (`localStorage`) and workspace status; Esc/outside click closes |
| Dataset select | `POST /api/databases/set`, reloads `/api/events`, rebuilds the map, disabled while generating, reverts + toast on failure |
| Upload database | "upload .db" in the case menu sends the raw file to `/api/databases/upload` (SQLite header + integrity checked, 256 MB cap), refreshes the catalog and switches to the new dataset |
| Starting point | Switches dataset first if needed, fills the prompt, submits once |
| Send / stop | Enter submits; while generating the same button is Stop → `POST /api/cancel` + aborts the stream; no double submit |
| Model pill | Popover with provider tabs from `/api/models`, filter, custom id; `POST /api/models/set`; closed by Esc/outside click |
| Evidence button | Opens/closes the evidence drawer; Ctrl+E; badge counts evidence items |
| Map / Tree | Hierarchical entities → artifacts → source events; filter dims non-matches; Collapse closes groups; legend toggles types |
| Map / Links | Process-relationship layout for the current graph; same filter/legend/selection semantics |
| Node | Click selects, inspector shows attributes, relations (navigable), source events (jump to the filtered events tab) |
| Inspector | Focus, isolate neighbourhood, copy node id, close |
| Evidence pack | "Scope map to evidence" isolates the nodes touched by the kept event ids; "Show in events" |
| Events tab | Search over host/action/process/summary/id, count, Copy CSV |
| Report tab | Rendered markdown (sanitised), verdict tag, copy markdown |
| Case log | Restore a saved run (verdict + report), delete one, clear all with confirm |
| Shortcuts | `?` popover; Esc closes menu/inspector/drawer in that order |

Unavailable actions get a real disabled state or an explicit toast — never a fake success.

## Files

- `src/a1/web/static/index.html` — shell (ids stable for JS and for `tests/test_web.py`).
- `src/a1/web/static/style.css` — all classes emitted by `app.js`, `forensic-graph.js`, `evidence-tree.js` and `process-links.js`.
- `src/a1/web/static/app.js` — controller: API, SSE, drawer/tabs, map wiring, views, history.
- `src/a1/web/static/forensic-graph.js` — `TelemetryGraph.build` normaliser + entity/relationship type metadata used by Tree and Links (legacy canvas renderer retained).
- `src/a1/web/static/evidence-tree.js` — hierarchical entity/artifact/source-event tree renderer used by Map → Tree.
- `src/a1/web/static/process-links.js` — process ancestry/relationship layout used by Map → Links.
- `src/a1/web/static/vendor/` — vendored marked/purify assets served locally (no CDN).

## Backend changes

None. Every contract traced during the audit (`/api/status`, `/api/models`, `/api/databases`, `/api/events`,
`/api/investigate`, `/api/chat`, `/api/cancel`) matched what the UI needs; `/api/events` returning HTTP 200 with an
`error` field is handled in the client by throwing and rendering the failure state, so no server edit was required.
