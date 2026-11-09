import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useBrokenLinks from '@docusaurus/useBrokenLinks';
import { Highlight } from 'prism-react-renderer';
import { featured, platform, integrationCount } from '@site/src/data/integrations';
import styles from './styles.module.css';

// Token colours for the graphite code panel (same in light and dark mode).
const panelTheme = {
  plain: { color: '#e9ecef', backgroundColor: 'transparent' },
  styles: [
    { types: ['comment', 'prolog'], style: { color: '#868e96', fontStyle: 'italic' } },
    { types: ['keyword', 'boolean', 'builtin', 'important'], style: { color: '#9ec5fe' } },
    { types: ['string', 'char', 'attr-value', 'property'], style: { color: '#b2f2bb' } },
    { types: ['function', 'class-name'], style: { color: '#ffd8a8' } },
    { types: ['number', 'constant'], style: { color: '#ffd43b' } },
    { types: ['punctuation', 'operator'], style: { color: '#adb5bd' } },
  ],
};

// Every integration in one list. Featured ones open a code sample; platform
// ones link to the doc that covers them.
const categories = [
  ...featured.map((g) => ({ id: g.id, label: g.label })),
  ...platform.map((g, i) => ({ id: `p${i}`, label: g.label })),
];
const all = [
  ...featured.flatMap((g) => g.items.map((it) => ({ ...it, cat: g.id, catLabel: g.label }))),
  ...platform.flatMap((g, i) =>
    g.items.map((it) => ({
      ...it,
      id: `p${i}-${it.name.toLowerCase().replace(/\W+/g, '-')}`,
      cat: `p${i}`,
      catLabel: g.label,
    })),
  ),
];

const matches = (it, q) =>
  !q || `${it.name} ${it.catLabel} ${it.keywords || ''}`.toLowerCase().includes(q);

// useLayoutEffect warns during server rendering; fall back to useEffect there.
const useIsoLayoutEffect = typeof window === 'undefined' ? useEffect : useLayoutEffect;

function Logo({ file }) {
  const src = useBaseUrl(`/img/integrations/${file}`);
  return (
    <span className={styles.logo}>
      <img src={src} alt="" width="28" height="28" loading="lazy" />
    </span>
  );
}

function CopyButton({ text }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={styles.copy}
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}>
      {done ? 'Copied' : 'Copy'}
    </button>
  );
}

function Drawer({ item }) {
  return (
    <div className={styles.drawer} id="integration-drawer" role="region" aria-label={`${item.name} example`}>
      <div className={styles.snippet}>
        <aside>
          <span className={styles.cat}>{item.catLabel}</span>
          <h3>{item.name}</h3>
          <p>{item.blurb}</p>
          <Link to={item.to}>Read the guide</Link>
          <div className={styles.install}>
            <code>{item.install}</code>
            <CopyButton text={item.install} />
          </div>
        </aside>
        <Highlight code={item.code} language={item.lang} theme={panelTheme}>
          {({ className, style, tokens, getLineProps, getTokenProps }) => (
            <pre className={`${className} ${styles.pre}`} style={style}>
              {tokens.map((line, i) => (
                <div key={i} {...getLineProps({ line })}>
                  {line.map((token, k) => (
                    <span key={k} {...getTokenProps({ token })} />
                  ))}
                </div>
              ))}
            </pre>
          )}
        </Highlight>
      </div>
    </div>
  );
}

export default function IntegrationWall() {
  // The navbar links to /#integrations; tell the link checker the anchor exists.
  useBrokenLinks().collectAnchor('integrations');
  const [query, setQuery] = useState('');
  const [cat, setCat] = useState('all');
  const [open, setOpen] = useState(null);
  const [cols, setCols] = useState(6);
  const gridRef = useRef(null);
  const q = query.trim().toLowerCase();

  const shown = all.filter((it) => (cat === 'all' || it.cat === cat) && matches(it, q));
  const openItem = shown.find((it) => it.id === open && it.code);

  // The drawer goes after the last tile of the opened tile's row, so it needs
  // the number of columns the grid currently has.
  useIsoLayoutEffect(() => {
    const grid = gridRef.current;
    if (!grid) return undefined;
    const measure = () => {
      const n = getComputedStyle(grid).gridTemplateColumns.split(' ').filter(Boolean).length;
      setCols(Math.max(1, n));
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(grid);
    return () => ro.disconnect();
  }, [shown.length > 0]);

  const openIndex = openItem ? shown.indexOf(openItem) : -1;
  const drawerAfter =
    openIndex < 0 ? -1 : Math.min(shown.length - 1, Math.floor(openIndex / cols) * cols + cols - 1);

  return (
    <section className={styles.wall} id="integrations">
      <div className="container">
        <div className={styles.head}>
          <h2 className={styles.title}>Works with your agent stack.</h2>
          <div className={styles.headSide}>
            <p>
              {integrationCount} integrations, one policy file. Every client fails closed and runs
              only the exact string it verified.
            </p>
            <label className={styles.search}>
              <span className="sr-only">Search integrations</span>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="11" cy="11" r="7" />
                <path d="m20 20-3.5-3.5" />
              </svg>
              <input
                type="search"
                placeholder="Search integrations, e.g. OpenMetadata, Vault, LangGraph"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </label>
          </div>
        </div>

        <div className={styles.chips} role="group" aria-label="Filter by category">
          {[{ id: 'all', label: 'All' }, ...categories].map((c) => (
            <button
              key={c.id}
              type="button"
              className={styles.chip}
              aria-pressed={cat === c.id}
              onClick={() => setCat(c.id)}>
              {c.label}
            </button>
          ))}
        </div>

        {shown.length === 0 ? (
          <div className={styles.empty}>
            <p>
              No integration matches “{query.trim()}”
              {cat !== 'all' ? ' in this category' : ''}. Anything that can make an HTTP call can
              use the <Link to="/docs/http-api">verify API</Link>, and unmodified Postgres drivers
              can go through the <Link to="/docs/proxy">wire proxy</Link>.
            </p>
            <button
              type="button"
              onClick={() => {
                setQuery('');
                setCat('all');
              }}>
              Show all integrations
            </button>
          </div>
        ) : (
          <div className={styles.grid} ref={gridRef}>
            {shown.map((it, i) => (
              <React.Fragment key={it.id}>
                {it.code ? (
                  <button
                    type="button"
                    className={styles.tile}
                    aria-expanded={it.id === openItem?.id}
                    aria-controls={it.id === openItem?.id ? 'integration-drawer' : undefined}
                    onClick={() => setOpen(it.id === openItem?.id ? null : it.id)}>
                    <Logo file={it.logo} />
                    <b>{it.name}</b>
                    <small>{it.catLabel}</small>
                  </button>
                ) : (
                  <Link className={styles.tile} to={it.to}>
                    <Logo file={it.logo} />
                    <b>{it.name}</b>
                    <small>{it.catLabel}</small>
                  </Link>
                )}
                {i === drawerAfter && <Drawer item={openItem} />}
              </React.Fragment>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
