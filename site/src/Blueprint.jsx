import { memo } from 'react';
import { STATIONS } from './data.js';
import { PLATE_W, PLATE_H } from './camera.js';

/* One sheet, nine details. Every plate is drawn at the same size so the
   camera can slide between them without anything reflowing on the way. */

const B = ({ x, y, w, h = 48, t, s, tone, center = false }) => {
  const bx = +x, by = +y, bw = +w, bh = +h;
  return (
    <g>
      <rect className={`bp-b${tone ? ` bp-b--${tone}` : ''}`} x={bx} y={by} width={bw} height={bh} />
      <text
        className="bp-t"
        x={center ? bx + bw / 2 : bx + 14}
        y={by + bh / 2 + (s ? -3 : 5)}
        textAnchor={center ? 'middle' : 'start'}
      >
        {t}
      </text>
      {s && (
        <text className="bp-s" x={center ? bx + bw / 2 : bx + 14} y={by + bh / 2 + 15} textAnchor={center ? 'middle' : 'start'}>
          {s}
        </text>
      )}
    </g>
  );
};

const Ar = ({ d, label, lx, ly, dash = false }) => (
  <g>
    <path className={`bp-ar${dash ? ' bp-ar--dash' : ''}`} d={d} markerEnd="url(#bp-a)" />
    {label && (
      <text className="bp-al" x={lx} y={ly}>
        {label}
      </text>
    )}
  </g>
);

const band = (t, x, y) => (
  <text className="bp-band-t" x={x} y={y}>
    {t}
  </text>
);

const STATS = [
  ['8', 'forensic tools'],
  ['12', 'steps, max'],
  ['14', 'entity types'],
  ['13', 'relations per edge'],
];

const COVER = (
  <g>
    {band('the intake', 20, 52)}
    <rect className="bp-b bp-b--hot" x="20" y="62" width="330" height="96" />
    <text className="bp-mono" x="36" y="86">
      ALERT · WS-OPS-01 · 2026-09-10T02:14Z
    </text>
    <text className="bp-t" x="36" y="114">
      Suspicious PowerShell execution
    </text>
    <text className="bp-s" x="36" y="136">
      one host · four entities pulled from the text
    </text>

    {STATS.map(([n, l], i) => (
      <g key={l}>
        <text className="bp-big" x={386 + (i % 2) * 190} y={108 + Math.floor(i / 2) * 76}>
          {n}
        </text>
        <text className="bp-band-t" x={386 + (i % 2) * 190} y={128 + Math.floor(i / 2) * 76}>
          {l}
        </text>
      </g>
    ))}

    {band('what the alert becomes', 20, 214)}
    <B x="20" y="226" w="224" h="56" t="alert text" s="host, process, time, user" />
    <Ar d="M244 254 H296" />
    <B x="300" y="226" w="224" h="56" t="read-only queries" s="eight tools, local sqlite" />
    <Ar d="M524 254 H576" />
    <B x="580" y="226" w="180" h="56" t="cited verdict" s="malicious · 0.91" tone="ok" />

    <text className="bp-mono" x="20" y="398">
      read only · no writes · no network · no judge model
    </text>
  </g>
);

const CHAIN = [
  ['alert_prep', 'deterministic'],
  ['triage', 'plan'],
  ['investigator', 'loop'],
  ['evidence_packing', 'pack'],
  ['correlate', 'edges'],
  ['validate', 'citations'],
  ['report', 'verdict'],
];

const ARCH = (
  <g>
    {band('entrypoints', 20, 52)}
    <B x="20" y="62" w="140" h="42" t="a1" s="cli" />
    <B x="20" y="112" w="140" h="42" t="a1 web" s="sse" />
    <B x="20" y="162" w="140" h="42" t="harness" s="scoring" />
    <text className="bp-s" x="20" y="228">
      one langgraph,
    </text>
    <text className="bp-s" x="20" y="246">
      four doors.
    </text>

    {band('the graph', 240, 52)}
    {CHAIN.map(([n, tag], i) => {
      const y = 62 + i * 52;
      return (
        <g key={n}>
          <rect className={`bp-b${n === 'investigator' ? ' bp-b--hot' : ''}`} x="240" y={y} width="300" height="42" />
          <text className="bp-t" x="256" y={y + 26}>
            {n}
          </text>
          <text className="bp-mono" x="524" y={y + 26} textAnchor="end">
            {tag}
          </text>
          {i < CHAIN.length - 1 && <Ar d={`M390 ${y + 42} V ${y + 52}`} />}
        </g>
      );
    })}
    <text className="bp-mono" x="240" y="440">
      shared InvestigationState · sqlite checkpoints
    </text>

    {band('state', 580, 52)}
    <B x="580" y="62" w="180" h="86" t="sqlite" s="read-only · selects only" tone="db" />
    <B x="580" y="168" w="180" h="86" t="evidence graph" s="14 entities · 13 relations" tone="info" />
    <B x="580" y="274" w="180" h="86" t="validator" s="re-queries the db" tone="ok" />

    <text className="bp-mono" x="20" y="440">
      alert_prep never calls a model
    </text>
  </g>
);

const HYPS = [
  ['H1', 'Credential dumping on WS-OPS-01', 'ACTIVE', 'bp-info'],
  ['H2', 'Scheduled task persistence', 'WEAKLY_SUPPORTED', 'bp-ok'],
  ['H3', 'Benign administrator script', 'CONTRADICTED', 'bp-neg'],
];

const TRIAGE = (
  <g>
    {band('the plan', 20, 52)}
    <B x="20" y="62" w="340" h="58" t="TriagePlan" s="entities · host id · utc window" />
    <text className="bp-s" x="380" y="88">
      two to four hypotheses,
    </text>
    <text className="bp-s" x="380" y="106">
      no telemetry touched.
    </text>

    {HYPS.map(([id, t, st, cls], i) => {
      const y = 158 + i * 74;
      return (
        <g key={id}>
          <rect className="bp-b" x="20" y={y} width="470" height="56" />
          <text className="bp-mono" x="36" y={y + 24}>
            {id}
          </text>
          <text className="bp-t" x="70" y={y + 24}>
            {t}
          </text>
          <text className={`bp-mono ${cls}`} x="470" y={y + 40} textAnchor="end">
            {st}
          </text>
        </g>
      );
    })}

    <B x="520" y="158" w="240" h="130" t="discovered mid-run" s="persistence · creds · lateral · staging" />
    <text className="bp-mono" x="520" y="316">
      cap 8 active · keyword dedupe
    </text>

    <text className="bp-mono" x="20" y="404">
      the plan is what the investigator is allowed to chase
    </text>
  </g>
);

const TOOLS = [
  'get_database_schema',
  'query_telemetry',
  'search_timeline',
  'find_process_relationships',
  'trace_process_tree',
  'find_process_associations',
  'get_entity_context',
  'pivot_on_indicator',
];

const LOOP = (
  <g>
    {band('step budget', 20, 52)}
    <B x="20" y="62" w="140" h="40" t="04 / 12" />
    <text className="bp-s" x="20" y="126">
      react loop,
    </text>
    <text className="bp-s" x="20" y="144">
      planner in the middle.
    </text>

    <B x="210" y="62" w="300" h="52" t="investigator" s="picks one tool per step" tone="hot" />
    <Ar d="M510 88 H524" />

    <rect className="bp-b" x="530" y="52" width="230" height="300" />
    {TOOLS.map((n, i) => (
      <g key={n}>
        <text className="bp-num" x="542" y={76 + i * 36}>
          {String(i + 1).padStart(2, '0')}
        </text>
        <text className="bp-mono" x="566" y={76 + i * 36}>
          {n}
        </text>
      </g>
    ))}
    <text className="bp-band-t" x="530" y="372">
      read only
    </text>

    <path className="bp-diamond" d="M360 150 L432 196 L360 242 L288 196 Z" />
    <text className="bp-mono" x="360" y="200" textAnchor="middle">
      should_continue
    </text>
    <Ar d="M360 114 V150" />

    <B x="210" y="322" w="300" h="52" t="evidence pack" s="only cited rows go forward" />
    <Ar d="M360 242 V322" label="stop" lx="372" ly="282" />
    <path className="bp-ar bp-ar--dash" d="M288 196 H180 V88 H210" markerEnd="url(#bp-a)" />
    <text className="bp-al" x="188" y="150">
      next
    </text>
    <text className="bp-al" x="188" y="248">
      nudge after two repeats
    </text>

    <text className="bp-mono" x="20" y="404">
      two repeat nudges, then the loop is cut
    </text>
  </g>
);

const NODES = [
  ['WS-OPS-01', 'host'],
  ['powershell.exe', 'process'],
  ['lsass.exe', 'process'],
  ['dump.dmp', 'file'],
  ['10.20.4.18:443', 'ip_address'],
];

const EVIDENCE = (
  <g>
    {band('the graph', 20, 52)}
    {NODES.map(([n, k], i) => {
      const x = 20 + i * 150;
      return (
        <g key={n}>
          <rect className="bp-b" x={x} y="62" width="132" height="64" />
          <text className="bp-t--sm bp-t" x={x + 12} y="88">
            {n}
          </text>
          <text className="bp-mono" x={x + 12} y="108">
            {k}
          </text>
        </g>
      );
    })}
    {[0, 1, 2, 3].map((i) => (
      <Ar key={i} d={`M${152 + i * 150} 94 H${170 + i * 150}`} />
    ))}
    <text className="bp-mono" x="20" y="150">
      observed_on · spawned · created · connected_to — one relation per arrow
    </text>

    <B x="20" y="186" w="470" h="96" t="every edge keeps its receipt" s="source_event_id · evt-0042" tone="info" />
    <rect className="bp-b" x="520" y="186" width="240" height="96" />
    <text className="bp-t" x="534" y="212">
      states
    </text>
    <text className="bp-mono" x="534" y="242">
      observed · inferred
    </text>
    <text className="bp-mono" x="534" y="264">
      unverified · contradicted
    </text>

    <text className="bp-s" x="20" y="330">
      fourteen entity types, thirteen relationship types, one place to look.
    </text>
    <text className="bp-mono" x="20" y="404">
      the tools return rows · the graph is built from them
    </text>
  </g>
);

const CLAIMS = [
  ['evt-0042', 'lsass.exe written by powershell.exe'],
  ['evt-0911', 'outbound tls to 10.20.4.18:443'],
  ['SRV-FILE-02', 'hostname claimed by the model'],
];

const AUDIT = (
  <g>
    {band('citations', 20, 52)}
    {CLAIMS.map(([id, t], i) => {
      const y = 62 + i * 70;
      return (
        <g key={id}>
          <rect className="bp-b" x="20" y={y} width="330" height="56" />
          <text className="bp-mono" x="34" y={y + 22}>
            {id}
          </text>
          <text className="bp-s" x="34" y={y + 42}>
            {t}
          </text>
        </g>
      );
    })}

    <Ar d="M350 132 H392" />
    <B x="396" y="104" w="140" h="60" t="validator" s="sql, every time" tone="db" />

    {band('the answer', 580, 52)}
    <B x="580" y="62" w="180" h="64" t="45 valid" tone="ok" />
    <B x="580" y="136" w="180" h="64" t="1 invalid" tone="neg" />
    <B x="580" y="210" w="180" h="64" t="2 unverified" />

    <text className="bp-s" x="580" y="306">
      an exception is never
    </text>
    <text className="bp-s" x="580" y="324">
      a pass.
    </text>

    <text className="bp-mono" x="20" y="404">
      ids are re-read from sqlite · a missing row is not a citation
    </text>
  </g>
);

const FIELDS = [
  'verdict',
  'verdict_boundary',
  'confidence',
  'executive_summary',
  'investigation_reasoning',
  'attack_chain',
  'evidence_basis',
  'benign_explanations_considered',
  'evidence_gaps',
  'recommended_next_steps',
];

const BOUN = ['confirmed', 'unconfirmed', 'benign', 'inconclusive', 'gap'];

const VERDICT = (
  <g>
    {band('the report', 20, 52)}
    <rect className="bp-b" x="20" y="62" width="330" height="300" />
    <text className="bp-mono" x="36" y="86">
      IncidentVerdict
    </text>
    {FIELDS.map((f, i) => (
      <text className={`bp-s${i === 0 ? ' bp-ink' : ''}`} key={f} x="36" y={112 + i * 24}>
        {f}
      </text>
    ))}

    {band('verdict boundary', 400, 52)}
    <path className="bp-axis" d="M400 96 H740" />
    {BOUN.map((b, i) => {
      const x = 400 + i * 85;
      return (
        <g key={b}>
          <path className="bp-tick" d={`M${x} 96 V104`} />
          <text className="bp-al" x={x} y="120" textAnchor="middle">
            {b}
          </text>
        </g>
      );
    })}
    <path className="bp-marker" d="M400 88 L406 78 L394 78 Z" />
    <text className="bp-al" x="400" y="70">
      here
    </text>

    {band('confidence', 400, 210)}
    <path className="bp-axis" d="M400 254 H740" />
    {[0, 0.25, 0.5, 0.75, 1].map((v, i) => (
      <text className="bp-mono" key={v} x={400 + i * 85} y="274" textAnchor="middle">
        {v}
      </text>
    ))}
    <path className="bp-marker" d="M710 262 L716 252 L704 252 Z" />
    <text className="bp-mono" x="710" y="240" textAnchor="middle">
      0.91
    </text>

    <text className="bp-mono" x="20" y="404">
      two fields on purpose: what it believes, and how far the evidence reaches
    </text>
  </g>
);

const RUBRIC = [
  ['verdict', 20],
  ['evidence', 25],
  ['grounding', 20],
  ['calibration', 10],
  ['efficiency', 10],
  ['report', 15],
];

const BENCH = (
  <g>
    {band('rubric · weighted', 20, 52)}
    {(() => {
      let x = 20;
      return RUBRIC.map(([label, w], i) => {
        const width = (w / 100) * 740;
        const seg = (
          <g key={label}>
            <rect className={`bp-seg bp-seg--${i}`} x={x} y="64" width={width} height="30" />
            <text className="bp-mono" x={x + 8} y="84">
              {w}
            </text>
            <text className="bp-s" x={x} y="118">
              {label}
            </text>
          </g>
        );
        x += width;
        return seg;
      });
    })()}

    <text className="bp-s" x="20" y="180">
      every point comes from a sqlite query, not from a model reading the report.
    </text>

    {band('how a score exists', 20, 250)}
    <B x="20" y="260" w="230" h="56" t="harness" s="replays one incident" />
    <Ar d="M250 288 H292" />
    <B x="296" y="260" w="230" h="56" t="sqlite checks" s="ground truth rows" />
    <Ar d="M526 288 H568" />
    <B x="572" y="260" w="188" h="56" t="results.json" s="bootstrap 95% CI" tone="ok" />

    <text className="bp-mono" x="20" y="404">
      no judge model · deterministic · a single run is a snapshot
    </text>
  </g>
);

const RUN = (
  <g>
    {band('terminal', 20, 52)}
    <rect className="bp-b" x="20" y="62" width="440" height="252" />
    {[
      ['uv sync', 'install'],
      ['a1 web', 'localhost:8000 · uploads ≤ 256mb'],
      ['a1 "PowerShell on WS-OPS-01" --db case.db', 'one case'],
      ['a1 ingest eve.jsonl -o suricata.db', 'wazuh · suricata · generic'],
      ['pytest', 'unit first, telemetry ones skip'],
    ].map(([cmd, out], i) => (
      <g key={cmd}>
        <text className="bp-prompt" x="36" y={94 + i * 48}>
          <tspan fill="rgba(222,226,228,.35)">$ </tspan>
          {cmd}
        </text>
        <text className="bp-cmd-out" x="36" y={112 + i * 48}>
          {out}
        </text>
      </g>
    ))}

    {band('entrypoints', 500, 52)}
    {['a1', 'a1 web', 'a1 ingest', 'pytest'].map((e, i) => (
      <text className="bp-mono" key={e} x="500" y={78 + i * 34}>
        {e}
      </text>
    ))}
    {band('providers', 500, 250)}
    {['opencode', 'ollama', 'openai'].map((p, i) => (
      <g key={p}>
        <rect className="bp-b" x={500 + i * 88} y="262" width="82" height="34" />
        <text className="bp-mono" x={541 + i * 88} y="283" textAnchor="middle">
          {p}
        </text>
      </g>
    ))}
    <text className="bp-mono" x="500" y="330">
      python 3.12 or newer
    </text>

    <text className="bp-mono" x="20" y="404">
      local, provider-agnostic, readable
    </text>
  </g>
);

const BODIES = { cover: COVER, arch: ARCH, triage: TRIAGE, loop: LOOP, evidence: EVIDENCE, audit: AUDIT, verdict: VERDICT, benchmark: BENCH, run: RUN };

const META = {
  cover: 'Read it before you trust it',
  arch: 'One graph, seven nodes',
  triage: 'Decide before you look',
  loop: 'Twelve steps, eight tools',
  evidence: 'Nothing is prose',
  audit: 'Trust is a query',
  verdict: 'Two answers, not one',
  benchmark: 'Nothing self-reported',
  run: 'Read it, run it, argue with it',
};

const Plate = memo(function Plate({ s, i, active, onNavigate }) {
  const title = META[s.id] || s.label;
  return (
    <g
      className="bp-plate"
      data-on={i === active}
      transform={`translate(${s.x - PLATE_W / 2} ${s.y - PLATE_H / 2})`}
      onClick={() => onNavigate(i)}
      role="button"
      aria-label={`detail ${s.num}, ${title}`}
    >
      <rect className="bp-frame" x="0.5" y="0.5" width={PLATE_W - 1} height={PLATE_H - 1} />
      <path className="bp-corner" d="M0 14 V0 H14" />
      <path className="bp-corner" d={`M${PLATE_W - 14} 0 H${PLATE_W} V14`} />
      <text className="bp-head" x="20" y="30">
        DETAIL {s.num}
      </text>
      {BODIES[s.id]}
      <path className="bp-rule" d={`M0 ${PLATE_H - 62} H${PLATE_W}`} />
      <text className="bp-foot-t" x="20" y={PLATE_H - 26}>
        {title}
      </text>
    </g>
  );
});

const Flow = () => (
  <g>
    {STATIONS.slice(0, -1).map((s, i) => {
      const n = STATIONS[i + 1];
      return (
        <path
          key={s.id}
          className="bp-flow"
          d={`M${s.x + PLATE_W / 2} ${s.y} C ${s.x + PLATE_W / 2 + 120} ${s.y}, ${n.x - PLATE_W / 2 - 120} ${n.y}, ${n.x - PLATE_W / 2} ${n.y}`}
          fill="none"
        />
      );
    })}
  </g>
);

export default function Blueprint({ cameraRef, active, onNavigate }) {
  return (
    <svg className="drawing" aria-label="A1 system drawing">
      <defs>
        <pattern id="bp-grid" width="26" height="26" patternUnits="userSpaceOnUse">
          <path d="M26 0 H0 V26" fill="none" stroke="rgba(222,226,228,.045)" strokeWidth="1" />
        </pattern>
        <pattern id="bp-grid-2" width="208" height="208" patternUnits="userSpaceOnUse">
          <path d="M208 0 H0 V208" fill="none" stroke="rgba(222,226,228,.06)" strokeWidth="1" />
        </pattern>
        <marker id="bp-a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0 0.6 L8 4 L0 7.4" fill="none" stroke="rgba(222,226,228,.45)" strokeWidth="0.9" />
        </marker>
      </defs>
      <rect x="-4000" y="-3000" width="20000" height="8000" fill="url(#bp-grid)" />
      <rect x="-4000" y="-3000" width="20000" height="8000" fill="url(#bp-grid-2)" />
      <g ref={cameraRef} id="camera">
        <Flow />
        {STATIONS.map((s, i) => (
          <Plate key={s.id} s={s} i={i} active={active} onNavigate={onNavigate} />
        ))}
      </g>
    </svg>
  );
}
