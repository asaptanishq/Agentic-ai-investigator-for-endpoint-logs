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

*Two fixed surfaces and an evidence overlay. The topbar is the case switchboard, the bench is the record of
reasoning, the overlay is the evidence board. Nothing is a card; hierarchy comes from hairline rules, background steps and type, never from
gradients, glow, glass, pills or hero type.*

| Decision | Choice | Why |
| --- | --- | --- |
| Layout | Topbar · bench (flex) · centered evidence overlay (default closed, max 1200×860, opens with a short scale/fade) | Triage reads top-to-bottom: which dataset → what was asked → what the evidence says. The overlay opens over the record only when the analyst needs it, so the bench keeps full width while a run streams. |
| Dataset / case log | Both live in the `#caseMenu` popover opened from the dataset button in the topbar | Replaces the old 264px rail, which spent a third of the screen on navigation. The popover keeps dataset selection, inactive-dataset deletion, history restore/delete/clear and workspace status one click away. |
| Evidence overlay | Tabs Map / Events / Report; Map offers Graph, Tree and Links modes, a filter, type legend and Collapse; Ctrl+E or the Evidence button opens it, Esc or a backdrop click closes it | One surface for every piece of evidence, centered over the bench instead of shrinking it. Graph is the whole interconnected entity/relationship picture, laid out with host blocks plus force relaxation; Tree is the hierarchical entity/artifact view; Links is the process-relationship view. Upload lives beside the composer, not in the case menu. |
| Bench | Left-aligned record: user line, then a five-step run (prepare/plan/collect/pack/verdict) with hypotheses, evidence pack and verdict | Progress is the honest thing to show: the backend really emits those stages. No fake typing indicator. |
| Welcome | Compact case briefing inside the bench, not a hero: dataset facts (events, hosts, span), starting points as a dense list | Turns the empty state into triage context from real `/api/events` counts. |
| Accent | One signal colour (amber `#e0a33c`) reserved for *running* state; verdict colours only on verdict surface | Colour means state, never decoration. |
| Entity colour | Low-chroma hues per real entity type, used **only** in the map, legend and inspector | The map is the only place hue carries meaning. |
| Type | Inter for prose/UI, JetBrains Mono for ids, timestamps, counts, process paths | Investigators scan machine strings; mono keeps columns aligned. |
| Density | 13px body, 12px controls, 11px labels, 1.55 prose, 26px table rows, 8px spacing grid | Dense but not cramped: an analyst reads dozens of events per screen. |
| Motion | 120ms ease-out for controls; 160–220ms cubic-bezier opacity/transform for the evidence overlay; no layout animation, no glow, no gradients | The overlay should feel like it arrives, not like the page reflows. Nothing moves while evidence is being read. |

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
registry actions), associated_with (alert → anchor). Graph, Tree and Links render the same graph; Graph lays out every
node and relationship with connected hosts as blocks, Tree groups by entity and artifact, Links groups by process
ancestry. Graph is the default map mode.

## Layout

```
┌ topbar: brand · new case · dataset/case menu · facts ─ verdict · evidence · model · shortcuts ┐
├──────────────────────────── bench (flex) ─────────────────────────────┤
│ welcome: dataset facts, starting points                                │
│ record of the run: user line, stages, hypotheses, pack                 │
│ composer (+ upload .db / logs · model · dataset)        send/stop       │
└────────────────────────────────────────────────────────────────────────┘
        ┌──────────── evidence overlay (centered, max 1200×860) ────────────┐
        │ Map | Events | Report                                             │
        │ Map: Graph | Tree | Links · filter · legend · inspector           │
        └───────────────────────────────────────────────────────────────────┘
```

The topbar replaces the old rail. Brand, New investigation, the dataset button (opens `#caseMenu`: datasets list + case log + local workspace status), dataset facts, verdict stamp, Evidence button with count, model pill → menu, shortcuts. The evidence overlay is a fixed, centered `<aside role="dialog" aria-modal="true">` toggled by the Evidence button or Ctrl+E; it opens with a short scale/fade over a dimmed backdrop and closes with Esc, the close button or a backdrop click. It is closed by default so the bench owns the screen until evidence is requested, and it has no resize grip — its size is capped by the viewport.

Main bench: welcome (case kicker, dataset title, facts, starting points with All / This dataset / Attack / Benign / Ambiguous filter), streamed turns, and the composer (textarea, model · dataset meta, upload control, send button that becomes stop while running).

The map has three modes. **Graph** is the default: every entity and relationship is drawn as one interconnected canvas, hosts are laid out as blocks with deterministic edge-spring/node-repulsion relaxation, and the analyst can pan, zoom and fit. Tree and Links remain available for hierarchical and process-ancestry reading. Risk colour is deliberately withheld until an investigation has produced evidence: before a run the graph is neutral, and only after evidence is packed does it mark malicious/suspicious nodes and their attack paths. The legend grows "malicious traces" / "suspicious traces" chips only when risk nodes exist.

## Behaviour contract (every control)

| Control | Behaviour |
| --- | --- |
| Dataset button | Opens `#caseMenu` with the real `/api/databases` list, indexed hint, case log (`localStorage`) and workspace status; Esc/outside click closes |
| Dataset select | `POST /api/databases/set`, reloads `/api/events`, rebuilds the map, disabled while generating, reverts + toast on failure |
| Delete dataset | Inactive dataset rows expose a `×` action with confirmation; the active dataset is protected and must be switched first (`DELETE /api/databases?path=…`) |
| Upload database | "+ upload .db / logs" beside the composer sends the raw file to `/api/databases/upload` (SQLite header + integrity checked, 256 MB cap; `.json/.jsonl/.ndjson/.log/.txt` are auto-detected as Wazuh/Suricata/AMiner/generic logs, converted into a `.db`, then selected), refreshes the catalog and switches to the new dataset |
| Starting point | Switches dataset first if needed, fills the prompt, submits once |
| Send / stop | Enter submits; while generating the same button is Stop → `POST /api/cancel` + aborts the stream; no double submit |
| Model pill | Popover with provider tabs from `/api/models`, filter, custom id, and a provider API-key field persisted to `.env`; `POST /api/models/set`, `POST /api/models/api-key`; closed by Esc/outside click |
| Evidence button | Opens/closes the centered evidence overlay; Ctrl+E; Esc/backdrop/close button closes; badge counts evidence items |
| Map / Graph | Default view: all entities and relationships on one pan/zoom canvas, hosts as blocks; filter dims non-matches; legend toggles types; risk borders/paths appear only after an investigation |
| Map / Tree | Hierarchical entities → artifacts → source events; filter dims non-matches; Collapse closes groups; legend toggles types |
| Map / Links | Process-relationship layout for the current graph; same filter/legend/selection semantics |
| Node | Click selects, inspector shows attributes, relations (navigable), source events (jump to the filtered events tab) |
| Inspector | Focus, isolate neighbourhood, copy node id, close |
| Evidence pack | "Scope map to evidence" isolates the nodes touched by the kept event ids; "Show in events" |
| Events tab | Search over host/action/process/summary/id, count, Copy CSV |
| Report tab | Rendered markdown (sanitised), verdict tag, copy markdown |
| Case log | Restore a saved run (verdict + report), delete one, clear all with confirm |
| Shortcuts | `?` popover; Esc closes menu/inspector/overlay in that order |

Unavailable actions get a real disabled state or an explicit toast — never a fake success.

## Files

- `src/a1/web/static/index.html` — shell (ids stable for JS and for `tests/test_web.py`).
- `src/a1/web/static/style.css` — all classes emitted by `app.js`, `forensic-graph.js`, `evidence-tree.js` and `process-links.js`.
- `src/a1/web/static/app.js` — controller: API, SSE, overlay/tabs, map wiring, views, history.
- `src/a1/web/static/forensic-graph.js` — `TelemetryGraph.build` normaliser + entity/relationship type metadata; `ForensicGraph` canvas renderer used by Map → Graph, with host-block layout, force relaxation for congested blocks, pan/zoom/fit, selection, type/search filters and post-investigation risk styling.
- `src/a1/web/static/evidence-tree.js` — hierarchical entity/artifact/source-event tree renderer used by Map → Tree.
- `src/a1/web/static/process-links.js` — process ancestry/relationship layout used by Map → Links.
- `src/a1/web/static/vendor/` — vendored marked/purify assets served locally (no CDN).

## Backend changes

None. Every contract traced during the audit (`/api/status`, `/api/models`, `/api/databases`, `/api/events`,
`/api/events/lookup`, `/api/investigate`, `/api/chat`, `/api/cancel`) matched what the UI needs; `/api/events` returning HTTP 200 with an
`error` field is handled in the client by throwing and rendering the failure state, so no server edit was required.
