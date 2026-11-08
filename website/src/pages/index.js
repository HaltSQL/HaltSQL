import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import CodeBlock from '@theme/CodeBlock';
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
import FlowAnimation from '@site/src/components/FlowAnimation';
import styles from './index.module.css';

const policyYaml = `apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: analytics-agent }
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 1000 }
tenancy:
  mode: bound
  keys: { tenant: "\${ctx.tenant_id}" }
tables:
  app.orders:
    columns: [id, tenant_id, customer_id, status, total_cents, created_at]
    tenant_column: tenant_id
  app.customers:
    columns: [id, tenant_id, name, created_at]   # email and phone stay hidden
    tenant_column: tenant_id`;

const cliExample = `haltsql verify --policy policy.yaml \\
  --context '{"tenant_id":"acme"}' \\
  --sql 'SELECT status, count(*) FROM orders
         WHERE tenant_id = $1 GROUP BY status LIMIT 100'
# exit 0: allowed, bind $1 = 'acme'

haltsql verify --policy policy.yaml \\
  --context '{"tenant_id":"acme"}' \\
  --sql 'SELECT email FROM customers LIMIT 10'
# exit 1: E_COLUMN_DENIED, E_TENANT_MISSING`;

const pythonExample = `from haltsql import HaltSQLClient, guard

hs = HaltSQLClient.from_env()          # talks to the haltsql-server sidecar

# Verify, then run exactly the verified string with HaltSQL's bind values,
# in a READ ONLY transaction with a timeout and a row cap.
result = guard.execute(conn, sql, {"tenant_id": tenant}, verifier=hs,
                       statement_timeout_ms=5000, max_rows=500)`;

const httpExample = `curl -s http://127.0.0.1:8080/v1/verify \\
  -H "Authorization: Bearer $HALTSQL_TOKEN" \\
  -d '{"sql": "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
       "context": {"tenant_id": "acme"}}'

{ "allowed": true, "reasons": [],
  "bind_params": [ { "param": 1, "value": "acme" } ],
  "policy": { "name": "analytics-agent", "version": "sha256:4f1c..." }, ... }`;

const proxyExample = `# Point any Postgres driver at the proxy instead of the database.
haltsql-proxy run -c proxy.yaml --listen 0.0.0.0:6432

psql "host=localhost port=6432 user=analytics dbname=app"
app=> SELECT email FROM customers LIMIT 5;
ERROR:  haltsql: query denied by policy "analytics-agent": column email of app.customers is not readable under this policy
DETAIL: HaltSQL reasons: E_COLUMN_DENIED, E_TENANT_MISSING`;

const checks = [
  ['Statement kinds', 'Only the kinds you allow. DDL, COPY, SET, DO and multi-statement strings are denied.'],
  ['Tables and columns', 'Allowlists per table, including what * would expand to. System catalogs are never reachable.'],
  ['Functions, operators, casts', 'Presets plus explicit allowlists. pg_sleep, dblink and regclass casts are denied.'],
  ['Tenant isolation', 'A provable tenant predicate on every occurrence of every tenant table, in its own scope.'],
  ['Result shape', 'Required LIMIT with a maximum, join budget, no locking clauses, no SELECT INTO.'],
  ['Parameters', 'Every $n must be a tenant value HaltSQL supplies, so the model never chooses a bound value.'],
];

const paths = [
  ['Library', 'Embed', 'Call verify() in-process from OCaml, or shell out to the static CLI.', '/docs/how-it-works/deployment-modes'],
  ['Sidecar', 'HTTP', 'haltsql-server next to your agent: TLS, OIDC, mTLS, audit, metrics.', '/docs/http-api'],
  ['Proxy', 'Wire protocol', 'haltsql-proxy speaks Postgres. No code changes; tenant values bound server side.', '/docs/proxy'],
  ['SDKs', 'Clients', 'Python, TypeScript, Go and Java clients with guarded execution, plus MCP.', '/docs/integrations'],
];

function Hero() {
  return (
    <header className={styles.hero}>
      <div className="container">
        <div className={styles.heroGrid}>
          <div>
            <span className={styles.kicker}>Open source · Apache-2.0</span>
            <Heading as="h1" className={styles.title}>
              Let the model write SQL.
              <br />
              <span className={styles.titleAccent}>Decide what runs.</span>
            </Heading>
            <p className={styles.subtitle}>
              HaltSQL is a policy firewall for LLM-generated PostgreSQL. It parses each query with
              the real Postgres parser, proves it stays inside your policy and inside the caller's
              tenant, and returns a verdict with reasons the model can act on. It never rewrites
              SQL and never connects to your database.
            </p>
            <div className={styles.buttons}>
              <Link className="button button--primary button--lg" to="/docs/quickstart">
                Quickstart: first deny in 5 minutes
              </Link>
              <Link className="button button--secondary button--lg" to="/docs/how-it-works/architecture">
                How it works
              </Link>
            </div>
          </div>
          <div className={styles.verdictCard}>
            <div className={styles.verdictSql}>
              <code>SELECT c.name, c.email FROM customers c LIMIT 10</code>
            </div>
            <div className={styles.verdictDeny}>DENIED</div>
            <ul className={styles.verdictReasons}>
              <li>
                <code>E_COLUMN_DENIED</code> column email of app.customers is not readable
              </li>
              <li>
                <code>E_TENANT_MISSING</code> app.customers (as c) has no provable tenant predicate
              </li>
            </ul>
            <div className={styles.verdictHint}>
              hint: add <code>WHERE c.tenant_id = $1</code>; remove <code>c.email</code>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}

function Section({ title, kicker, children, alt }) {
  return (
    <section className={clsx(styles.section, alt && styles.sectionAlt)}>
      <div className="container">
        {kicker && <span className={styles.kicker}>{kicker}</span>}
        <Heading as="h2">{title}</Heading>
        {children}
      </div>
    </section>
  );
}

export default function Home() {
  return (
    <Layout
      title="Policy firewall for LLM-generated PostgreSQL"
      description="HaltSQL checks LLM-generated PostgreSQL against a declarative policy and tenant isolation rules before it runs.">
      <Hero />
      <main>
        <Section kicker="The big picture" title="Where HaltSQL sits">
          <p className={styles.lead}>
            The agent writes SQL. HaltSQL decides whether that exact string may run for this caller.
            Only an allowed query reaches Postgres, bound with tenant values the model never saw.
            A denied query goes back to the agent with codes and hints so it can try again.
          </p>
          <FlowAnimation />
        </Section>

        <Section alt kicker="Quick start" title="Try it">
          <div className={styles.twoCol}>
            <div>
              <p>
                <strong>1. Write a policy.</strong> YAML or JSON. It lists what the agent may read
                and how rows are scoped to a tenant.
              </p>
              <CodeBlock language="yaml" title="policy.yaml">
                {policyYaml}
              </CodeBlock>
            </div>
            <div>
              <p>
                <strong>2. Check queries</strong> however your stack prefers.
              </p>
              <Tabs groupId="surface">
                <TabItem value="cli" label="CLI" default>
                  <CodeBlock language="bash">{cliExample}</CodeBlock>
                </TabItem>
                <TabItem value="python" label="Python">
                  <CodeBlock language="python">{pythonExample}</CodeBlock>
                </TabItem>
                <TabItem value="http" label="HTTP sidecar">
                  <CodeBlock language="bash">{httpExample}</CodeBlock>
                </TabItem>
                <TabItem value="proxy" label="Proxy">
                  <CodeBlock language="bash">{proxyExample}</CodeBlock>
                </TabItem>
              </Tabs>
            </div>
          </div>
        </Section>

        <Section kicker="What it checks" title="Every query, every rule, fail closed">
          <div className="hs-card-grid">
            {checks.map(([title, body]) => (
              <div key={title} className="hs-card">
                <h3>{title}</h3>
                <p>{body}</p>
              </div>
            ))}
          </div>
          <p className={styles.note}>
            Anything the analyzer does not fully understand is denied with{' '}
            <code>E_UNSUPPORTED</code>, never guessed at. See{' '}
            <Link to="/docs/how-it-works/analyzer">how the analyzer works</Link>.
          </p>
        </Section>

        <Section alt kicker="Choose your path" title="Four ways to deploy">
          <div className="hs-card-grid">
            {paths.map(([title, kicker, body, to]) => (
              <Link key={title} className="hs-card" to={to}>
                <span className="hs-card-kicker">{kicker}</span>
                <h3>{title}</h3>
                <p>{body}</p>
              </Link>
            ))}
          </div>
        </Section>

        <Section kicker="Explore next" title="Learn how it works">
          <div className="hs-card-grid">
            <Link className="hs-card" to="/docs/how-it-works/verification-pipeline">
              <h3>The verification pipeline</h3>
              <p>From SQL string to verdict: parse, typed AST, scopes, rules, bind values.</p>
            </Link>
            <Link className="hs-card" to="/docs/how-it-works/tenancy-proof">
              <h3>The tenancy proof</h3>
              <p>What HaltSQL must prove before it lets a query touch a tenant table.</p>
            </Link>
            <Link className="hs-card" to="/docs/how-it-works/proxy-internals">
              <h3>Inside the proxy</h3>
              <p>How the wire-protocol firewall verifies Parse and rewrites Bind.</p>
            </Link>
            <Link className="hs-card" to="/docs/how-it-works/assurance">
              <h3>How we test it</h3>
              <p>3,300+ tests, an attack corpus, fuzzing and a lab that runs every allowed query.</p>
            </Link>
          </div>
        </Section>
      </main>
    </Layout>
  );
}
