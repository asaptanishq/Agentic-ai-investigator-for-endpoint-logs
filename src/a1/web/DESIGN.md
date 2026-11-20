# A1 case desk — interface design

## Job

An analyst opens a case, asks A1 one question, watches evidence accumulate, and leaves with a verdict they can defend. The screen should feel like a case desk shared with a careful colleague: the file is present, the work is visible, and nothing gets lost between sessions.

## Subject world

Case files, evidence tags, exhibit numbers, ruled paper, field notes, stamps, an evidence board. The source database is read-only; A1 is the examiner working beside you, not a chatbot in a box.

## Shell

- **Case rail** — the open case plate (dataset, event/host/time span, verdict stamp), the saved case log, and the examiner (model/provider, key, connection).
- **Deskbar** — the live desk status: `a1 at the desk`, `collecting evidence`, `verdict filed`.
- **Case log** — the investigation thread, numbered turns, five-step strip: brief, hypothesize, collect, exhibit, verdict.
- **Composer** — the question, current case and model, `+ data` to open a new case file.
- **Evidence room** — a right-hand surface with Board, Events, Report. Resizable, remembered between sessions.

## Tokens

| Token | Value | Job |
|---|---|---|
| `--desk` | `#121314` | graphite desk ground |
| `--desk-2` | `#171819` | raised paper / rail |
| `--desk-3` | `#0c0d0d` | shadowed inset |
| `--ink` | `#e8e4d9` | bone-white primary text |
| `--ink-2` | `#a5a59c` | secondary prose |
| `--ink-3` | `#85877f` | labels, metadata (AA on desk) |
| `--tag` | `#d4b273` | manila evidence tag / active state |
| `--red` | `#dc715f` | malicious verdict, failures |
| `--green` | `#7fc0a0` | benign verdict, ready |
| `--blue` | `#8fb0d4` | ambiguous verdict |
| `--line` | `#25272a` | hairline |
| `--line-2` | `#36393c` | stronger rule / hover |

Semantic colors are only used for state, never decoration. Components use tokens, not hex.

## Type

- **Bricolage Grotesque** (self-hosted, `static/fonts/bricolage-grotesque.woff2`) — case identity, empty headline, verdict stamp, report title. One family, variable weight; no second display face.
- **System sans** — prose, turns, report body.
- **System mono** — labels, IDs, metadata, tables, status. Uppercase at 8.5–10px with 0.06–0.2em tracking.

Scale: 8.5 / 10 / 11 / 12 / 14 / 16 / 20 / 26 / 32–46px. Display sizes use tight tracking; labels use wide tracking. Body line-height 1.65.

## Form

- Radius: 0 on plates, menus, tables and the desk; 2px maximum on the composer or a tag. Pills are not part of the language.
- Borders: 1px hairlines. No drop shadows except the drawer edge and menus.
- Spacing: 4 / 7 / 10 / 14 / 18 / 26 / 36 / 52px.
- Signature: the **punched evidence plate** (cut corner + eyelet hole) for the case identity and verdict; numbered exhibits `E01…`; the stamped verdict with confidence. These appear only where they carry meaning.

## States

Every surface has: empty (real instruction, not a placeholder), loading (sweep on the active step, pulsing desk dot), error (human sentence, desk unchanged), disabled (dimmed, no pointer), hover, focus-visible (1px tag outline, 2px offset). Turns have brief/hypothesize/collect/exhibit/verdict states; runs can end done, failed, or stopped.

## Copy

Lower-case desk language, factual and quiet. No urgency, no hype, no invented proof. Verdicts are stated with the boundary and confidence, and lead to a next action: read the report or ask a follow-up.

## Accessibility

AA contrast on desk surfaces (`--ink-3` ≥ 4.5:1), visible focus, real labels, keyboard reachable exhibits, reduced-motion support, and responsive layout at 1440, 1120, 960, 700, 460 and 390. Every control keeps a ≥ 24px target; primary actions (send, tabs, menus) are larger. The drawer closes with Escape and the rail with its backdrop.
