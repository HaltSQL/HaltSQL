// Integrations shown on the landing page.
//
// `featured` groups render as selectable items with a code sample; `platform`
// groups render as links to the doc that covers them. `logo` names a file in
// static/img/integrations: Simple Icons (CC0) in brand colour, otherwise the
// project's own mark.
// Install lines are repository-relative until the packages are published.

export const featured = [
  {
    id: 'mcp',
    label: 'MCP & IDEs',
    note: 'Works in Claude Desktop, Cursor, VS Code and any MCP client. Same query tool as server-postgres, with a policy in front of it.',
    items: [
      {
        id: 'mcp', name: 'MCP server', logo: 'mcp.svg', to: '/docs/mcp', lang: 'json',
        keywords: 'claude desktop cursor vs code server-postgres model context protocol',
        blurb: 'The safe drop-in replacement for @modelcontextprotocol/server-postgres. Same query tool, same connection string.',
        install: 'docker run -i --rm --read-only -v "$PWD:/config:ro" ghcr.io/haltsql/haltsql-mcp:0.0.3',
        code: `{
  "mcpServers": {
    "postgres": {
      "command": "haltsql-mcp",
      "args": ["--local-policy", "/path/to/policy.yaml",
               "postgresql://agent_ro@localhost/mydb"],
      "env": { "HALTSQL_MCP_CONTEXT": "{\\"tenant_id\\": \\"acme\\"}" }
    }
  }
}`,
      },
    ],
  },
  {
    id: 'agents',
    label: 'Agent frameworks',
    items: [
      {
        id: 'langchain', name: 'LangChain', logo: 'langchain.svg', to: '/docs/integrations/langchain', lang: 'python',
        blurb: 'Guard an existing SQLDatabase, or give the agent a tool whose only argument is the SQL.',
        install: "pip install 'haltsql-langchain[langchain]'",
        code: `from langchain_community.utilities import SQLDatabase
from haltsql import HaltSQLClient
from haltsql_langchain import guard_sql_database

db = SQLDatabase.from_uri("postgresql+psycopg://agent_ro@db/app")
guarded = guard_sql_database(
    db, HaltSQLClient.from_env(),
    lambda: {"tenant_id": session.tenant_id},   # from your auth, per call
)
# use guarded in SQLDatabaseToolkit / create_sql_agent`,
      },
      {
        id: 'langgraph', name: 'LangGraph', logo: 'langgraph.svg', to: '/docs/integrations/langgraph', lang: 'python',
        blurb: 'A prebuilt SQL agent graph that returns reason codes to the model and stops after N denials.',
        install: "pip install haltsql-langgraph",
        code: `from haltsql import HaltSQLClient
from haltsql_langgraph import HaltSQLToolRunner, haltsql_query_tool, build_sql_agent_graph

tool = haltsql_query_tool(
    HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN)))
graph = build_sql_agent_graph(llm.bind_tools([tool]), tool, max_denials=3)

out = graph.invoke({"messages": [("user", "How many open orders?")]},
                   context={"haltsql_context": {"tenant_id": user.tenant_id}})`,
      },
      {
        id: 'openai', name: 'OpenAI Agents SDK', logo: 'openai.svg', to: '/docs/integrations/openai-agents', lang: 'python',
        blurb: 'A function tool that verifies the SQL, then runs the exact string with server-bound tenant values.',
        install: "pip install haltsql-openai-agents",
        code: `from agents import Agent, Runner
from haltsql import HaltSQLClient
from haltsql_openai_agents import HaltSQLToolRunner, haltsql_query_tool

runner = HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN))
agent = Agent(name="analyst", instructions="Answer with SQL.",
              tools=[haltsql_query_tool(runner)])

result = await Runner.run(agent, "How many open orders?",
                          context=AppContext(user_id=user.id))`,
      },
      {
        id: 'adk', name: 'Google ADK', logo: 'adk.svg', to: '/docs/integrations/google-adk', lang: 'python',
        keywords: 'agent development kit gemini',
        blurb: 'A ready SQL agent for the Agent Development Kit, with the tenant kept in session state.',
        install: "pip install haltsql-google-adk",
        code: `from google.adk.runners import InMemoryRunner
from haltsql import HaltSQLClient
from haltsql_google_adk import HaltSQLToolRunner, build_sql_agent

runner = HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN))
agent = build_sql_agent(runner, model="gemini-2.5-flash")
adk = InMemoryRunner(agent=agent, app_name="analytics")
session = await adk.session_service.create_session(
    app_name="analytics", user_id=user.id,
    state={"haltsql_context": {"tenant_id": user.tenant_id}})`,
      },
      {
        id: 'llamaindex', name: 'LlamaIndex', logo: 'llamaindex.svg', to: '/docs/integrations/llamaindex', lang: 'python',
        blurb: 'A guarded SQLDatabase, SQLRetriever and NL-to-SQL query engine.',
        install: "pip install 'haltsql-llamaindex[llamaindex]'",
        code: `from llama_index.core import SQLDatabase
from haltsql import HaltSQLClient
from haltsql_llamaindex import guarded_nl_sql_query_engine

db = SQLDatabase(create_engine("postgresql+psycopg://agent_ro@db/app"))
engine = guarded_nl_sql_query_engine(
    db, HaltSQLClient.from_env(),
    lambda: {"tenant_id": session.tenant_id},
    tables=["orders"], llm=llm,
)`,
      },
      {
        id: 'crewai', name: 'CrewAI', logo: 'crewai.svg', to: '/docs/integrations/crewai', lang: 'python',
        blurb: 'A CrewAI tool for your analyst agents. Denials come back as hints the agent can fix.',
        install: "pip install haltsql-crewai",
        code: `from crewai import Agent
from haltsql import HaltSQLClient
from haltsql_crewai import HaltSQLQueryTool, HaltSQLToolRunner

tool = HaltSQLQueryTool(
    runner=HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN)),
    context=lambda: {"tenant_id": session.tenant_id},
)
analyst = Agent(role="Analyst", goal="Answer questions about orders",
                backstory="Writes careful SQL.", tools=[tool])`,
      },
      {
        id: 'sk', name: 'Semantic Kernel', logo: 'sk.svg', to: '/docs/integrations/semantic-kernel', lang: 'python',
        keywords: 'microsoft',
        blurb: 'A kernel plugin that reads the caller’s context from a contextvar on each request.',
        install: "pip install haltsql-semantic-kernel",
        code: `from semantic_kernel import Kernel
from haltsql import HaltSQLClient
from haltsql_semantic_kernel import HaltSQLPlugin, HaltSQLToolRunner, PLUGIN_NAME

current_ctx = contextvars.ContextVar("haltsql_ctx", default=None)  # set per request
runner = HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN))

kernel = Kernel()
kernel.add_plugin(HaltSQLPlugin(runner, context=current_ctx.get),
                  plugin_name=PLUGIN_NAME)`,
      },
      {
        id: 'vanna', name: 'Vanna', logo: 'vanna.svg', to: '/docs/integrations/vanna', lang: 'python',
        blurb: 'An async SqlRunner for Vanna’s RunSqlTool.',
        install: "pip install 'haltsql-vanna[vanna]'",
        code: `from haltsql import AsyncHaltSQLClient
from haltsql_vanna import HaltSQLSqlRunner
from vanna.tools import RunSqlTool

runner = HaltSQLSqlRunner(AsyncHaltSQLClient.from_env(),
                          dsn="postgresql://agent_ro@db/app")
tool = RunSqlTool(sql_runner=runner)`,
      },
    ],
  },
  {
    id: 'sdks',
    label: 'SDKs & proxy',
    items: [
      {
        id: 'python', name: 'Python', logo: 'python.svg', to: '/docs/sdk-python', lang: 'python',
        keywords: 'psycopg asyncpg sqlalchemy',
        blurb: 'Sync and async clients for psycopg 3, asyncpg and SQLAlchemy, plus a local CLI verifier.',
        install: "pip install 'haltsql[psycopg]'",
        code: `from haltsql import HaltSQLClient, guard

hs = HaltSQLClient.from_env()

# Verify, then run exactly the verified string with HaltSQL's bind values,
# in a READ ONLY transaction with a timeout and a row cap.
result = guard.execute(conn, sql, {"tenant_id": tenant}, verifier=hs,
                       statement_timeout_ms=5000, max_rows=500)`,
      },
      {
        id: 'ts', name: 'TypeScript', logo: 'ts.svg', to: '/docs/sdk-typescript', lang: 'typescript',
        keywords: 'node javascript node-postgres',
        blurb: 'A Node.js client with guarded execution for node-postgres.',
        install: 'npm install @haltsql/client',
        code: `import { HaltSQLClient } from "@haltsql/client";

const haltsql = new HaltSQLClient({
  baseUrl: "http://127.0.0.1:8080",
  token: process.env.HALTSQL_TOKEN,
});

const verdict = await haltsql.verify(
  "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
  { tenant_id: session.tenantId },  // from the session, never the prompt
);`,
      },
      {
        id: 'go', name: 'Go', logo: 'go.svg', to: '/docs/sdk-go', lang: 'go',
        keywords: 'golang pgx lib/pq database/sql',
        blurb: 'database/sql, pgx and lib/pq, with retries and mutual TLS built in.',
        install: 'go get github.com/HaltSQL/HaltSQL/clients/go/haltsql',
        code: `hc, err := haltsql.New("http://127.0.0.1:8080",
    haltsql.WithToken(os.Getenv("HALTSQL_TOKEN")),
    haltsql.WithTimeout(2*time.Second))
if err != nil {
    log.Fatal(err)
}

verdict, err := hc.Verify(ctx,
    "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
    haltsql.Context{"tenant_id": session.TenantID})`,
      },
      {
        id: 'java', name: 'Java', logo: 'java.svg', to: '/docs/sdk-java', lang: 'java',
        keywords: 'jdbc pgjdbc jvm kotlin',
        blurb: 'A PgJDBC client with guarded execution and a pluggable SSLContext.',
        install: 'mvn -f clients/java/pom.xml install   # com.haltsql:haltsql-client',
        code: `HaltSQLClient haltsql = HaltSQLClient.builder()
    .baseUrl("http://127.0.0.1:8080")
    .token(System.getenv("HALTSQL_TOKEN"))
    .build();

Verdict verdict = haltsql.verify(
    "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
    Map.of("tenant_id", session.tenantId()));`,
      },
      {
        id: 'proxy', name: 'Wire proxy', logo: 'proxy.svg', to: '/docs/proxy', lang: 'bash',
        keywords: 'psql jdbc pgx driver postgres protocol',
        blurb: 'Speaks the Postgres wire protocol. Point psql, JDBC or pgx at it with no code changes.',
        install: 'docker pull ghcr.io/haltsql/haltsql:0.0.3',
        code: `# Point any Postgres driver at the proxy instead of the database.
haltsql-proxy run -c proxy.yaml --listen 0.0.0.0:6432

psql "host=localhost port=6432 user=analytics dbname=app"
app=> SELECT email FROM customers LIMIT 5;
ERROR:  haltsql: query denied by policy "analytics-agent"
DETAIL: HaltSQL reasons: E_COLUMN_DENIED, E_TENANT_MISSING`,
      },
      {
        id: 'http', name: 'HTTP API', logo: 'http.svg', to: '/docs/http-api', lang: 'bash',
        keywords: 'rest sidecar curl any language',
        blurb: 'One POST /v1/verify call per query, from any language, through the haltsql-server sidecar.',
        install: 'docker pull ghcr.io/haltsql/haltsql:0.0.3',
        code: `curl -s http://127.0.0.1:8080/v1/verify \\
  -H "Authorization: Bearer $HALTSQL_TOKEN" \\
  -d '{"sql": "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
       "context": {"tenant_id": "acme"}}'

{ "allowed": true, "reasons": [],
  "bind_params": [ { "param": 1, "value": "acme" } ], ... }`,
      },
    ],
  },
  {
    id: 'catalogs',
    label: 'Data catalogs',
    note: 'Columns your catalog tags as PII become denied columns in the drafted policy.',
    items: [
      {
        id: 'openmetadata', name: 'OpenMetadata', logo: 'openmetadata.svg', to: '/docs/integrations/data-catalogs', lang: 'bash',
        keywords: 'catalog pii tags glossary live fetch',
        blurb: 'Fetches PII tags and glossary terms live from the OpenMetadata API and drafts a policy from them.',
        install: 'export OPENMETADATA_TOKEN=...   # a bot JWT; DataConsumer is enough',
        code: `haltsql schema pull --dsn "$DATABASE_URL" --schema app -o policies/catalog.json

haltsql schema fetch --from openmetadata --url https://om.example.com/api \\
    --service prod_pg --database app --schema app -o policies/pii.om.json

haltsql policy draft --catalog policies/catalog.json --pii policies/pii.om.json \\
    --tenant-column tenant_id --schema app -o policies/agent.yaml`,
      },
      {
        id: 'datahub', name: 'DataHub', logo: 'datahub.svg', to: '/docs/integrations/data-catalogs', lang: 'bash',
        keywords: 'catalog pii tags glossary acryl',
        blurb: 'Reads tags and glossary terms from DataHub exports or GraphQL responses.',
        install: 'haltsql schema import --help',
        code: `haltsql schema import --from datahub datahub_export.json \\
    -o policies/pii.datahub.json

haltsql policy draft --catalog policies/catalog.json \\
    --pii policies/pii.datahub.json \\
    --tenant-column tenant_id --schema app -o policies/agent.yaml
haltsql lint-policy policies/agent.yaml`,
      },
      {
        id: 'dbt', name: 'dbt', logo: 'dbt.svg', to: '/docs/integrations/data-catalogs', lang: 'bash',
        keywords: 'manifest catalog.json meta tags',
        blurb: 'Reads column tags, meta and policy_tags from manifest.json, and comments from catalog.json.',
        install: 'dbt docs generate   # writes target/manifest.json',
        code: `haltsql schema import --from dbt target/manifest.json \\
    -o policies/pii.dbt.json

haltsql policy draft --catalog policies/catalog.json \\
    --pii policies/pii.dbt.json \\
    --tenant-column tenant_id --schema app -o policies/agent.yaml`,
      },
      {
        id: 'unity', name: 'Unity Catalog', logo: 'unity.svg', to: '/docs/integrations/data-catalogs', lang: 'bash',
        keywords: 'databricks column tags',
        blurb: 'Reads information_schema.column_tags rows or REST table JSON.',
        install: 'haltsql schema import --help',
        code: `haltsql schema import --from unity column_tags.json \\
    -o policies/pii.unity.json`,
      },
      {
        id: 'atlan', name: 'Atlan', logo: 'atlan.png', to: '/docs/integrations/data-catalogs', lang: 'bash',
        blurb: 'Reads classifications, Atlan tags and glossary meanings on Column assets.',
        install: 'haltsql schema import --help',
        code: `haltsql schema import --from atlan atlan_columns.json \\
    -o policies/pii.atlan.json`,
      },
      {
        id: 'collibra', name: 'Collibra', logo: 'collibra.svg', to: '/docs/integrations/data-catalogs', lang: 'bash',
        blurb: 'Reads classification attributes, tags and Business Term relations on Column assets.',
        install: 'haltsql schema import --help',
        code: `haltsql schema import --from collibra collibra_assets.json \\
    -o policies/pii.collibra.json`,
      },
    ],
  },
];

export const platform = [
  {
    label: 'Identity and secrets',
    items: [
      { name: 'Keycloak', logo: 'keycloak.svg', to: '/docs/integrations/identity-providers' },
      { name: 'Microsoft Entra ID', logo: 'entra.svg', to: '/docs/integrations/identity-providers' },
      { name: 'Okta', logo: 'okta.svg', to: '/docs/integrations/identity-providers' },
      { name: 'Auth0', logo: 'auth0.svg', to: '/docs/integrations/identity-providers' },
      { name: 'HashiCorp Vault', logo: 'vault.svg', to: '/docs/integrations/secrets-managers' },
      { name: 'AWS Secrets Manager', logo: 'aws.svg', to: '/docs/integrations/secrets-managers' },
      { name: 'Google Secret Manager', logo: 'gcp.svg', to: '/docs/integrations/secrets-managers' },
    ],
  },
  {
    label: 'Audit and observability',
    items: [
      { name: 'Amazon S3', logo: 's3.svg', to: '/docs/integrations/audit-and-observability' },
      { name: 'Google Cloud Storage', logo: 'gcs.svg', to: '/docs/integrations/audit-and-observability' },
      { name: 'Apache Kafka', logo: 'kafka.svg', to: '/docs/integrations/audit-and-observability' },
      { name: 'Elasticsearch', logo: 'elasticsearch.svg', to: '/docs/integrations/audit-and-observability' },
      { name: 'OpenSearch', logo: 'opensearch.svg', to: '/docs/integrations/audit-and-observability' },
      { name: 'OpenTelemetry', logo: 'otel.svg', to: '/docs/integrations/audit-and-observability' },
      { name: 'Prometheus', logo: 'prometheus.svg', to: '/docs/integrations/audit-and-observability' },
    ],
  },
  {
    label: 'Policy and CI',
    items: [
      { name: 'Open Policy Agent', logo: 'opa.svg', to: '/docs/opa' },
      { name: 'GitHub Actions', logo: 'githubactions.svg', to: '/docs/policy-ci' },
      { name: 'GitLab CI', logo: 'gitlab.svg', to: '/docs/policy-ci' },
      { name: 'pre-commit', logo: 'precommit.svg', to: '/docs/policy-ci' },
      { name: 'OCI registries', logo: 'docker.svg', to: '/docs/policy-bundles' },
    ],
  },
  {
    label: 'Deploy',
    items: [
      { name: 'Kubernetes operator', logo: 'kubernetes.svg', to: '/docs/kubernetes-operator' },
      { name: 'Helm', logo: 'helm.svg', to: '/docs/deployment' },
      { name: 'Terraform', logo: 'terraform.svg', to: '/docs/terraform' },
      { name: 'AWS', logo: 'aws.svg', to: '/docs/deploy-aws' },
      { name: 'Google Cloud', logo: 'gcp.svg', to: '/docs/deploy-gcp' },
      { name: 'Azure', logo: 'azure.svg', to: '/docs/deploy-azure' },
    ],
  },
];

export const integrationCount =
  featured.reduce((n, g) => n + g.items.length, 0) +
  platform.reduce((n, g) => n + g.items.length, 0);
