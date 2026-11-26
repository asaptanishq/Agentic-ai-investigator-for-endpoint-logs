import { STATIONS } from './data'

const HYPOTHESES = [
  ['H1', 'LSASS memory was dumped for credential theft', 'supported'],
  ['H2', 'A scheduled task re-establishes access', 'weakly'],
  ['H3', 'The activity is the sanctioned backup job', 'contradicted'],
  ['H4', 'The host moved laterally to SRV-FILE-02', 'unresolved'],
  ['H5', 'Persistence hides behind UpdaterSvc', 'active', 'discovered mid-run'],
]

const WEIGHTS = [
  ['verdict + boundary', 20, 'w1'],
  ['ground-truth evidence', 25, 'w2'],
  ['grounding', 20, 'w3'],
  ['calibration', 10, 'w4'],
  ['efficiency', 10, 'w5'],
  ['report quality', 15, 'w6'],
]

/* ------------------------------------------------------------ architecture */

function Spine() {
  const rows = [
    ['01', 'alert_prep', 'deterministic · no model'],
    ['02', 'triage', '2–4 hypotheses'],
    ['03', 'investigator', 'ReAct + planner', 'hot'],
    ['04', 'evidence packing', 'compact pack'],
    ['05', 'correlate', 'confirm / refute'],
    ['06', 'validate', 're-query every citation'],
    ['07', 'report', 'verdict + boundary', 'hot'],
  ]
  return (
    <div className="spine">
      {rows.map(([n, name, note, tone]) => (
        <div className={`spine-row${tone ? ' spine-row--hot' : ''}`} key={name}>
          <span className="spine-n">{n}</span>
          <span className="spine-name">{name}</span>
          <span className="spine-note">{note}</span>
        </div>
      ))}
    </div>
  )
}

function EdgeSpecimen() {
  return (
    <div className="edges">
      <p className="edge-line">
        <span className="edge-n">powershell.exe</span>
        <span className="edge-rel">spawned</span>
        <span className="edge-n">lsass.exe</span>
      </p>
      <p className="edge-meta">
        edge.source_event_id = <b>evt-0042</b>
      </p>
      <p className="edge-meta">
        <b>14</b> entity types · <b>13</b> relationship types · <b>4</b> evidence states
      </p>
    </div>
  )
}

function AlertSpecimen() {
  return (
    <div className="alert">
      <p>
        “On <mark className="tok tok--host">WS-OPS-01</mark>,{' '}
        <mark className="tok tok--proc">powershell.exe</mark> was spawned by{' '}
        <mark className="tok tok--proc">wscript.exe</mark> and connected to{' '}
        <mark className="tok tok--net">10.20.4.18:443</mark> at{' '}
        <mark className="tok tok--time">2026-09-10T07:42Z</mark>. User:{' '}
        <mark className="tok tok--user">CORP\jdoe</mark>.”
      </p>
      <div className="resolve">
        <p className="resolve-line">
          <span className="ok">✓</span> WS-OPS-01 <i>→</i> hosts · host_id 3
        </p>
        <p className="resolve-line">
          <span className="ok">✓</span> powershell.exe <i>→</i> processes · 214 rows in window
        </p>
        <p className="resolve-line">
          <span className="ok">✓</span> 10.20.4.18 <i>→</i> connections · 61 rows
        </p>
        <p className="resolve-line">
          <span className="warn">✕</span> wscript.exe <i>→</i> absent on host · kept as a lead
        </p>
      </div>
    </div>
  )
}

function HypothesisSpecimen() {
  return (
    <div className="hyps">
      {HYPOTHESES.map(([id, text, status, tag]) => (
        <div className="hyp" key={id}>
          <span className="hyp-id">{id}</span>
          <span className="hyp-text">
            {text}
            {tag && <em className="hyp-tag">{tag}</em>}
          </span>
          <span className={`hyp-status hyp-status--${status}`}>{status.replace('_', ' ')}</span>
        </div>
      ))}
      <div className="hyp-foot">status moves only when evidence moves · nothing deleted, only resolved</div>
    </div>
  )
}

function Trace() {
  const steps = [
    ['01', 'query_telemetry', "SELECT … FROM processes WHERE host_id = 3", '14 rows · 07:41:58'],
    ['02', 'find_process_relationships', "host='WS-OPS-01' child='lsass.exe'", '1 pair · wscript.exe → powershell.exe'],
    ['03', 'trace_process_tree', 'process_entity_id=pe-8841 direction=both', '6 nodes · 1 dumped file'],
    ['04', 'pivot_on_indicator', "type='sha256' value='9f2c…'", 'no match on other hosts · lead closed'],
  ]
  return (
    <div className="trace">
      <div className="trace-head">
        <span>step budget</span>
        <span className="trace-count">04 / 12</span>
      </div>
      <div className="trace-meter">
        {Array.from({ length: 12 }, (_, i) => (
          <i key={i} className={i < 4 ? 'is-on' : ''} />
        ))}
      </div>
      {steps.map(([n, tool, args, result]) => (
        <div className="trace-step" key={n}>
          <span className="trace-n">{n}</span>
          <div>
            <code className="trace-tool">{tool}</code>
            <code className="trace-args">{args}</code>
            <p className="trace-result">{result}</p>
          </div>
        </div>
      ))}
      <p className="trace-foot">every call is a query · the loop stops at 12 or when evidence is sufficient</p>
    </div>
  )
}

function AuditSpecimen() {
  return (
    <div className="audit">
      <div className="lanes">
        {[
          ['45', 'valid', 'reproduced'],
          ['1', 'invalid', 'row absent'],
          ['2', 'unverified', 'no access'],
        ].map(([n, label, note]) => (
          <div className={`lane lane--${label}`} key={label}>
            <span className="lane-n">{n}</span>
            <span className="lane-label">{label}</span>
            <span className="lane-note">{note}</span>
          </div>
        ))}
      </div>
      <div className="claims">
        <p className="claim">
          <span className="claim-mark claim-mark--valid">✓</span>
          <code>evt-0042</code> read access to lsass.exe · re-queried, pid and timestamps match
        </p>
        <p className="claim">
          <span className="claim-mark claim-mark--invalid">✕</span>
          <code>evt-0911</code> dump written at 07:44 · no such row · demoted to inference
        </p>
        <p className="claim">
          <span className="claim-mark claim-mark--unverified">?</span>
          <code>SRV-FILE-02</code> next hop · row lives in another database · reported as a gap
        </p>
      </div>
    </div>
  )
}

function VerdictSpecimen() {
  return (
    <div className="plate">
      <div className="plate-main">
        <div>
          <span className="plate-key">verdict</span>
          <span className="plate-val plate-val--hot">malicious</span>
        </div>
        <div>
          <span className="plate-key">boundary</span>
          <span className="plate-val plate-val--hot">confirmed_malicious</span>
        </div>
      </div>
      <div className="plate-grid">
        {[
          ['confidence', '0.91'],
          ['attack chain', '5 stages'],
          ['evidence gaps', '2 listed'],
        ].map(([k, v]) => (
          <div className="plate-cell" key={k}>
            <span className="plate-key">{k}</span>
            <span className="plate-val">{v}</span>
          </div>
        ))}
      </div>
      <p className="plate-foot">
        confirmed_malicious · unconfirmed_malicious · benign · inconclusive · telemetry_gap_inconclusive
      </p>
    </div>
  )
}

function BenchmarkSpecimen() {
  return (
    <div className="bench">
      <div className="rubric">
        {WEIGHTS.map(([label, w]) => (
          <div className="rubric-row" key={label}>
            <span className="rubric-label">{label}</span>
            <span className="rubric-track">
              <i style={{ width: `${(w / 25) * 100}%` }} />
            </span>
            <span className="rubric-n">{w}</span>
          </div>
        ))}
        <div className="rubric-total">
          <span>deterministic checks · no judge model</span>
        </div>
      </div>
      <div className="cmd">
        <span className="cmd-prompt">$</span> python -m a1.benchmark --split all --out results.json
      </div>
      <p className="note">bootstrap 95% intervals · a single run is a snapshot</p>
    </div>
  )
}

function RunSpecimen() {
  const lines = [
    ['uv sync', 'install'],
    ['a1 web', '127.0.0.1:8000 · uploads to 256 mb'],
    ['a1 "Investigate PowerShell on WS-OPS-01" --db case.db', 'one incident'],
    ['a1 ingest eve.jsonl -o suricata.db', 'wazuh · suricata · generic'],
    ['pytest', 'unit tests first, telemetry ones skip'],
  ]
  return (
    <div className="term">
      {lines.map(([cmd, note]) => (
        <p className="term-row" key={cmd}>
          <span className="cmd-prompt">$</span>
          <code className="term-cmd">{cmd}</code>
          <span className="term-note">{note}</span>
        </p>
      ))}
      <div className="providers">
        <span className="lex-key">provider</span>
        <span className="chip">opencode</span>
        <span className="chip">ollama</span>
        <span className="chip">openai</span>
        <span className="prov-note">one .env</span>
      </div>
      <a
        className="repo"
        href="https://github.com/asaptanishq/Agentic-ai-investigator-for-endpoint-logs"
        target="_blank"
        rel="noreferrer"
      >
        github.com/asaptanishq/Agentic-ai-investigator-for-endpoint-logs ↗
      </a>
    </div>
  )
}

const CONTENT = {
  cover: {
    title: 'One alert in. A defensible verdict out.',
    body: [
      <>
        A1 is an autonomous DFIR investigator: it reads an alert, queries telemetry with <em>its own tools</em>, grounds every claim in a row, and returns a verdict <b>it can defend</b>.
      </>,
    ],
  },
  arch: {
    title: 'One state, one read-only door.',
    body: [
      <>
        Four entrypoints, <em>one LangGraph state</em>, seven nodes, eight tools — and a database
        handle that <b>only reads</b>.
      </>,
    ],
    specimen: <Spine />,
  },
  triage: {
    title: 'A hypothesis is a question with a kill condition.',
    body: [
      <>
        Two to four competing explanations, <em>including the boring one</em>, each checkable and
        each allowed to die.
      </>,
    ],
    specimen: <HypothesisSpecimen />,
  },
  loop: {
    title: 'Twelve steps. Eight read-only tools. No wandering.',
    body: [
      <>
        A ReAct loop with a planner: pick a tool, read what comes back, advance — or <em>get nudged back</em> to the question.
      </>,
    ],
    specimen: <Trace />,
  },
  evidence: {
    title: 'Nothing is prose. Everything is a node.',
    body: [
      <>
        Every entity and relationship the tools return lands in one graph, and every edge keeps <em>the event id that proves it</em>.
      </>,
    ],
    specimen: <EdgeSpecimen />,
  },
  audit: {
    title: 'A claim is only as good as the row behind it.',
    body: [
      <>
        Before the verdict, a validator <b>re-queries SQLite</b> for every citation. What it cannot
        reproduce is demoted, or reported as a gap.
      </>,
    ],
    specimen: <AuditSpecimen />,
  },
  verdict: {
    title: 'Malicious is easy. Confirmed is the work.',
    body: [
      <>
        Two fields on purpose: what A1 believes, and <em>how far the evidence actually reaches</em>.
      </>,
    ],
    specimen: <VerdictSpecimen />,
  },
  benchmark: {
    title: 'Nothing self-reported.',
    body: [
      <>
        Scoring is deterministic: the harness re-reads the database for every citation, checks the
        rubric, and writes results.json. <b>No judge model</b> anywhere.
      </>,
    ],
    specimen: <BenchmarkSpecimen />,
  },
  run: {
    title: 'Read it, run it, argue with it.',
    body: [
      <>
        Local and provider-agnostic. Bring a forensic SQLite database, or ingest raw <em>Wazuh or Suricata</em> logs — the web UI takes files up to <b>256 MB</b>.
      </>,
    ],
    specimen: <RunSpecimen />,
  },
}

export function Panel({ station, index, onNext }) {
  const c = CONTENT[station.id]
  return (
    <article className="panel" key={station.id}>
      <div className="panel-scroll">
        <h2 className="panel-title">{c.title}</h2>
        {c.body.map((p, i) => (
          <p className="panel-body" key={i}>
            {p}
          </p>
        ))}
        {c.specimen && <div className="specimen">{c.specimen}</div>}
      </div>
      <div className="panel-foot">
        {index < STATIONS.length - 1 ? (
          <button className="next" onClick={onNext}>
            {STATIONS[index + 1].label}
            <span aria-hidden="true"> ↓</span>
          </button>
        ) : (
          <button className="next" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
            back to the alert
            <span aria-hidden="true"> ↑</span>
          </button>
        )}
      </div>
    </article>
  )
}
