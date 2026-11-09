import React from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import CodeBlock from '@theme/CodeBlock';
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
import FlowAnimation from '@site/src/components/FlowAnimation';
import IntegrationWall from '@site/src/components/IntegrationWall';
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

const modes = [
  ['Library', 'Haltsql.verify / haltsql CLI', 'Call verify in-process, or shell out to the static CLI from scripts and CI.', '/docs/how-it-works/deployment-modes'],
  ['Sidecar', 'POST /v1/verify', 'haltsql-server next to your agent, with TLS, OIDC, audit and metrics, for any language.', '/docs/http-api'],
  ['Proxy', 'Postgres wire protocol', 'haltsql-proxy in front of the database, so unmodified drivers cannot skip the check.', '/docs/proxy'],
];

const controls = [
  ['Tenant isolation', 'A provable tenant predicate on every tenant table, in its own scope. The model never picks the bound value.', '/docs/tenancy'],
  ['Column and function allowlists', 'Including what * expands to. pg_sleep, dblink and regclass casts are denied.', '/docs/policy-reference'],
  ['Hash-chained audit', 'To files, S3, GCS, Kafka or OpenSearch, and checked with haltsql audit verify.', '/docs/audit-sinks'],
  ['OIDC, TLS and mTLS', 'Policies chosen from IdP groups, secret providers, and an optional deny-only OPA check.', '/docs/authentication'],
  ['Signed policy bundles', 'Pulled from OCI, S3 or HTTPS, signature-checked and hot-reloaded.', '/docs/policy-bundles'],
  ['Shadow reports', 'See what a new policy would deny before you enforce it.', '/docs/shadow-reports'],
];

function Hero() {
  return (
    <header className={styles.hero}>
      <div className="container">
        <Heading as="h1" className={styles.title}>
          Stop bad SQL before it runs.
        </Heading>
        <div className={styles.heroRow}>
          <div>
            <p className={styles.lede}>
              HaltSQL is a policy firewall for LLM-generated PostgreSQL. It parses every statement
              your agents write with the real Postgres parser, checks tenants, columns and functions
              against your policy, and returns reasons the model can act on. It never rewrites SQL
              and never connects to your database.
            </p>
            <p className={styles.mcpCallout}>
              Using <code>@modelcontextprotocol/server-postgres</code> with Claude Desktop or Cursor?{' '}
              <Link to="/docs/mcp">
                Swap in <code>haltsql-mcp</code>, the safe drop-in replacement.
              </Link>
            </p>
          </div>
          <div className={styles.ctas}>
            <Link className={styles.btnRed} to="/docs/quickstart">
              Read the quickstart
            </Link>
            <Link className={styles.btnLine} to="#integrations">
              Browse integrations
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}

function SectionHead({ title, children }) {
  return (
    <div className={styles.sHead}>
      <Heading as="h2">{title}</Heading>
      <p>{children}</p>
    </div>
  );
}

export default function Home() {
  return (
    <Layout
      title="Policy firewall for LLM-generated PostgreSQL"
      description="HaltSQL checks LLM-generated PostgreSQL against a declarative policy and tenant isolation rules before it runs. Integrates with MCP, LangChain, LangGraph, OpenAI Agents, Google ADK, OpenMetadata, dbt and more.">
      <Hero />
      <main>
        <IntegrationWall />

        <section className={styles.section}>
          <div className="container">
            <SectionHead title="Where HaltSQL sits.">
              The agent writes SQL. HaltSQL decides whether that exact string may run for this
              caller. Only an allowed query reaches Postgres, bound with tenant values the model
              never saw. A denied query goes back to the agent with codes and hints.
            </SectionHead>
            <FlowAnimation />
          </div>
        </section>

        <section className={styles.section}>
          <div className="container">
            <SectionHead title="Three ways in.">
              Embed the verifier, run it as a sidecar, or put it on the wire. The policy and the
              verdicts are the same in each.
            </SectionHead>
            <div className={styles.modes}>
              {modes.map(([title, how, body, to]) => (
                <Link key={title} to={to} className={styles.mode}>
                  <h3>{title}</h3>
                  <p className={styles.how}>{how}</p>
                  <p>{body}</p>
                </Link>
              ))}
            </div>
          </div>
        </section>

        <section className={styles.section}>
          <div className="container">
            <SectionHead title="Write a policy, check a query.">
              A policy lists what the agent may read and how rows are scoped to a tenant. Check
              queries against it from the CLI, an SDK, the HTTP sidecar or the proxy.
            </SectionHead>
            <div className={styles.twoCol}>
              <CodeBlock language="yaml" title="policy.yaml">
                {policyYaml}
              </CodeBlock>
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
        </section>

        <section className={styles.section}>
          <div className="container">
            <SectionHead title="Passes the security review.">
              The controls platform and security teams ask about before an agent reaches production
              data, all in the MIT-licensed release.
            </SectionHead>
            <div className={styles.checklist}>
              {controls.map(([title, body, to]) => (
                <Link key={title} to={to} className={styles.check}>
                  <i aria-hidden="true" />
                  <h3>{title}</h3>
                  <p>{body}</p>
                </Link>
              ))}
            </div>
            <p className={styles.note}>
              Anything the analyzer does not fully understand is denied with{' '}
              <code>E_UNSUPPORTED</code>, never guessed at. Read the{' '}
              <Link to="/docs/threat-model">threat model</Link> and{' '}
              <Link to="/docs/how-it-works/assurance">how HaltSQL is tested</Link>.
            </p>
          </div>
        </section>

        <section className={styles.final}>
          <div className="container">
            <Heading as="h2">Put a policy in front of your agents today.</Heading>
            <div className={styles.ctas}>
              <Link className={styles.btnRed} to="/docs/quickstart">
                Get started
              </Link>
              <Link className={styles.btnInv} to="https://github.com/HaltSQL/HaltSQL">
                View on GitHub
              </Link>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
