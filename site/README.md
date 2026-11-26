# A1 docs site

Documentation for A1, drawn as one technical sheet: nine details on a single
drawing, and a camera that slides along them while you scroll — alert, plan, loop,
graph, citations, verdict, scoring, usage.

```
npm install
npm run dev      # http://localhost:5173
npm run build
npm run check    # camera / plate-fit assertions, no browser needed
```

## How it is put together

- `src/data.js` — the nine stations: sheet coordinates and labels. Every plate is
  the same size, so the camera never has to reframe.
- `src/Blueprint.jsx` — one SVG sheet: grid, dashed chain between details, and nine
  `Plate` groups drawn with a handful of primitives (box, arrow, diamond, axis).
  The active plate brightens through `data-on`; clicking a plate jumps to it.
- `src/App.jsx` — scroll position becomes camera progress. The camera is one DOM
  transform updated in a rAF loop with damping, so there is no React render per
  frame. The rail, minimap window and progress bar read from the same loop.
- `src/content.jsx` — the copy and the readable specimens (architecture list,
  hypothesis board, tool trace, entity chain, validation lanes, verdict plate,
  rubric bars, terminal).
- `src/camera.js` — pure math, also exercised by `npm run check`.

Scrolling is the only navigation: `N * 100vh` of track, one viewport per station.
`prefers-reduced-motion` snaps the camera instead of easing it.

## Type and colour

- Display: Bricolage Grotesque (variable, self-hosted, `public/fonts/`).
- Text: Fraunces (variable serif, self-hosted, roman + italic) — body copy and
  the plate footer titles. `<em>` is the accent; `<b>` marks the number or claim
  that matters.
- Repo: top-right of every screen, and a link at the end of `RunSpecimen` in
  `src/content.jsx` → https://github.com/asaptanishq/Agentic-ai-investigator-for-endpoint-logs
- Labels: system mono, uppercase, wide tracking.
- Palette: near-black paper, bone ink, one muted sea-green accent, three status
  tints. No purple gradients, no glassmorphism, no cards inside cards.
