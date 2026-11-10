import React, { useEffect, useState } from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';

// "Where HaltSQL sits", animated. A single track runs from the agent to
// Postgres; HaltSQL's stages sit on it. The track fills as the query moves.
// The first scenario is denied (a line draws back to the agent), the second
// is the corrected query, which is allowed through to Postgres.

const X0 = 180; // track start (agent edge)
const X1 = 820; // track end (Postgres edge)
const Y = 150;
const STAGES = [
  { id: 'parse', x: 330, name: 'Parse', sub: 'libpg_query' },
  { id: 'resolve', x: 440, name: 'Resolve', sub: 'names and scopes' },
  { id: 'check', x: 550, name: 'Check', sub: 'policy and tenancy' },
  { id: 'verdict', x: 670, name: 'Verdict', sub: 'allow or deny' },
];
const pct = (x) => ((x - X0) / (X1 - X0)) * 100;
// A single arc from the verdict back over the HaltSQL panel into the agent.
const RETURN = 'M670,141 C640,30 125,30 95,111';

const SCENARIOS = [
  {
    label: 'First attempt',
    sql: 'SELECT name, email FROM customers LIMIT 10',
    allowed: false,
    checks: [
      ['Statement', 'SELECT', true],
      ['Tables', 'app.customers', true],
      ['Columns', 'email is not readable', false],
      ['Tenant', 'no tenant predicate', false],
    ],
    outcome: 'Denied · E_COLUMN_DENIED, E_TENANT_MISSING',
  },
  {
    label: 'Corrected',
    sql: 'SELECT name FROM customers WHERE tenant_id = $1 LIMIT 10',
    allowed: true,
    checks: [
      ['Statement', 'SELECT', true],
      ['Tables', 'app.customers', true],
      ['Columns', 'name', true],
      ['Tenant', 'tenant_id = $1', true],
    ],
    outcome: "Allowed · bind $1 = 'acme'",
  },
];

// Each step: where the head of the query is (stage index or 'start'/'end'),
// how long it lasts, and the caption.
function stepsFor(s) {
  return [
    { at: 'start', ms: 1500, caption: 'The agent writes a query for the user’s question.' },
    { at: 0, ms: 1400, caption: 'HaltSQL parses the exact string with the database’s real grammar.' },
    { at: 1, ms: 1100, caption: 'Every name is resolved: tables, aliases, CTEs, subquery scopes.' },
    { at: 2, ms: 2200, checks: true, caption: 'Each column, function and tenant predicate is checked against the policy.' },
    {
      at: 3,
      ms: 1500,
      verdict: true,
      caption: s.allowed
        ? 'Allowed. The verdict carries the tenant value the application binds.'
        : 'Denied, with stable reason codes and a hint the model can follow.',
    },
    s.allowed
      ? { at: 'end', ms: 2600, caption: 'Only then does the query reach the database, scoped to the caller’s tenant.' }
      : { at: 'return', ms: 2600, caption: 'The reasons go back to the agent, which rewrites its query.' },
  ];
}

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return undefined;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReduced(mq.matches);
    update();
    mq.addEventListener?.('change', update);
    return () => mq.removeEventListener?.('change', update);
  }, []);
  return reduced;
}

export default function FlowAnimation() {
  const reduced = usePrefersReducedMotion();
  const [scenario, setScenario] = useState(0);
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(true);

  const s = SCENARIOS[scenario];
  const steps = stepsFor(s);
  const cur = steps[step];
  const seen = steps.slice(0, step + 1);
  const checksShown = seen.some((x) => x.checks);
  const verdictShown = seen.some((x) => x.verdict);

  useEffect(() => {
    if (!playing) return undefined;
    const t = setTimeout(() => {
      if (step + 1 < steps.length) setStep(step + 1);
      else {
        setScenario((scenario + 1) % SCENARIOS.length);
        setStep(0);
      }
    }, cur.ms);
    return () => clearTimeout(t);
  }, [playing, step, scenario]);

  // How far along the main track the query has travelled.
  const headX =
    cur.at === 'start' ? X0 : cur.at === 'end' ? X1 : cur.at === 'return' ? STAGES[3].x : STAGES[cur.at].x;
  const stageIndex = typeof cur.at === 'number' ? cur.at : cur.at === 'start' ? -1 : 3;
  const tone = verdictShown ? (s.allowed ? 'allow' : 'deny') : 'accent';

  const pick = (i) => {
    setScenario(i);
    setStep(0);
  };

  return (
    <figure
      className={clsx(styles.wrap, reduced && styles.reduced)}
      aria-label="Animated diagram: how HaltSQL checks a query before it reaches the database">
      <div className={styles.bar}>
        <div className={styles.tabs} role="tablist">
          {SCENARIOS.map((x, i) => (
            <button
              key={x.label}
              type="button"
              role="tab"
              aria-selected={i === scenario}
              className={clsx(styles.tab, i === scenario && styles.tabOn)}
              onClick={() => pick(i)}>
              <span className={styles.tabNum}>{String(i + 1).padStart(2, '0')}</span>
              {x.label}
            </button>
          ))}
        </div>
        <button type="button" className={styles.toggle} onClick={() => setPlaying((p) => !p)}>
          {playing ? 'Pause' : 'Play'}
        </button>
      </div>

      <svg viewBox="0 18 1000 226" className={styles.svg} aria-hidden="true">
        {/* HaltSQL region */}
        <rect x="262" y="66" width="476" height="160" rx="14" className={styles.region} />
        <text x="284" y="94" className={styles.regionLabel}>HALTSQL</text>

        {/* track */}
        <line x1={X0} y1={Y} x2={X1} y2={Y} className={styles.track} />
        <line
          x1={X0}
          y1={Y}
          x2={X1}
          y2={Y}
          pathLength="100"
          className={clsx(styles.fill, styles[`tone_${verdictShown && s.allowed ? 'allow' : 'accent'}`])}
          style={{
            strokeDashoffset: 100 - pct(headX),
            transitionDuration: reduced ? '0ms' : `${Math.min(cur.ms * 0.55, 900)}ms`,
          }}
        />
        <g className={clsx(styles.returnGroup, cur.at === 'return' && styles.returnOn, reduced && styles.returnInstant)}>
          <path d={RETURN} pathLength="100" className={styles.returnPath} />
          {/* arrowhead drawn separately so it appears only once the arc arrives */}
          <path d="M0,0 L-10,-5 L-10,5 z" transform="translate(95 112) rotate(110)" className={styles.returnHead} />
          <text x="382" y="45" textAnchor="middle" className={styles.returnLabel}>
            reasons and hints
          </text>
        </g>

        {/* stages */}
        {STAGES.map((st, i) => {
          const state = i < stageIndex ? 'done' : i === stageIndex ? 'current' : 'todo';
          const isVerdict = st.id === 'verdict' && verdictShown;
          return (
            <g key={st.id} className={clsx(styles.stage, styles[`stage_${state}`], isVerdict && styles[`verdict_${tone}`])}>
              <circle cx={st.x} cy={Y} r="6.5" className={styles.stageDot} />
              {state === 'current' && !reduced && <circle cx={st.x} cy={Y} r="6.5" className={styles.pulse} />}
              <text x={st.x} y={Y + 36} textAnchor="middle" className={styles.stageName}>
                {isVerdict ? (s.allowed ? 'Allowed' : 'Denied') : st.name}
              </text>
              <text x={st.x} y={Y + 56} textAnchor="middle" className={styles.stageSub}>
                {st.sub}
              </text>
            </g>
          );
        })}

        {/* moving head */}
        <g
          className={clsx(styles.head, styles[`tone_${cur.at === 'end' ? 'allow' : 'accent'}`], cur.at === 'return' && styles.headHidden)}
          style={{
            transform: `translateX(${headX}px)`,
            transitionDuration: reduced ? '0ms' : `${Math.min(cur.ms * 0.55, 900)}ms`,
          }}>
          <circle cx="0" cy={Y} r="4" />
        </g>

        {/* endpoints */}
        <g className={clsx(styles.endpoint, (cur.at === 'start' || cur.at === 'return') && styles.endpointOn, cur.at === 'return' && styles.endpointDeny)}>
          <rect x="10" y="114" width="170" height="72" rx="12" />
          <text x="95" y="145" textAnchor="middle" className={styles.endTitle}>Agent</text>
          <text x="95" y="166" textAnchor="middle" className={styles.endSub}>
            {cur.at === 'return' ? 'rewrites the query' : 'writes SQL'}
          </text>
        </g>
        <g className={clsx(styles.endpoint, cur.at === 'end' && styles.endpointOn, cur.at === 'end' && styles.endpointAllow)}>
          <rect x="820" y="114" width="170" height="72" rx="12" />
          <text x="905" y="145" textAnchor="middle" className={styles.endTitle}>Database</text>
          <text x="905" y="166" textAnchor="middle" className={styles.endSub}>
            {cur.at === 'end' ? 'tenant bound' : 'never sees a denied query'}
          </text>
        </g>
      </svg>

      <div className={styles.readout}>
        <div className={styles.row}>
          <span className={styles.key}>Query</span>
          <code key={s.sql} className={styles.sql}>
            {s.sql}
          </code>
        </div>
        <div className={styles.row}>
          <span className={styles.key}>Checks</span>
          <ul className={styles.checks}>
            {s.checks.map(([name, detail, ok], i) => (
              <li
                key={`${scenario}-${name}`}
                className={clsx(styles.check, checksShown && (ok ? styles.ok : styles.bad))}
                style={{ transitionDelay: checksShown && cur.checks && !reduced ? `${i * 320}ms` : '0ms' }}>
                <span className={styles.mark} />
                <span className={styles.checkName}>{name}</span>
                <span className={styles.checkDetail}>{detail}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className={styles.row}>
          <span className={styles.key}>Verdict</span>
          <span className={clsx(styles.outcome, verdictShown && styles[`outcome_${tone}`])}>
            {verdictShown ? s.outcome : '—'}
          </span>
        </div>
        <p className={styles.caption} aria-live="polite">
          {cur.caption}
        </p>
      </div>
    </figure>
  );
}
