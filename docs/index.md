# HaltSQL documentation

HaltSQL is a policy firewall for LLM-generated PostgreSQL. It checks whether an
exact SQL string is allowed for a caller under a declarative policy, and returns
a verdict with machine-readable reasons. It never rewrites SQL and never
connects to the database.

These docs describe version **0.0.3** (pre-1.0). The verdict format and reason
codes are stable; other interfaces may still change. See
[Versioning and upgrades](operations/upgrades.md).

## Start here

| If you want to | Read |
|---|---|
| See a denied query in five minutes | [Quickstart](quickstart.md) |
| Give Claude Desktop, Cursor or another MCP client safe Postgres access | [Replace server-postgres](mcp.md), then [Secure an MCP agent](tutorials/secure-an-mcp-agent.md) |
| Protect an agent you are building in Python, TypeScript, Go or Java | [Integrations](integrations.md) |
| Understand the design before you evaluate it | [Architecture](how-it-works/architecture.md) and [Threat model](threat-model.md) |
| Get answers to common evaluation questions | [FAQ](faq.md) |

## Guides by role

### Application and agent developers

- [Quickstart](quickstart.md): install the CLI, write a policy, check queries.
- [Multi-tenant analytics agent](tutorials/multi-tenant-analytics-agent.md): a
  Python agent behind the `haltsql-server` sidecar, end to end.
- Agent frameworks: [LangChain](integrations/langchain.md),
  [LangGraph](integrations/langgraph.md),
  [OpenAI Agents SDK](integrations/openai-agents.md),
  [Google ADK](integrations/google-adk.md),
  [LlamaIndex](integrations/llamaindex.md), [CrewAI](integrations/crewai.md),
  [Semantic Kernel](integrations/semantic-kernel.md) and
  [Vanna](integrations/vanna.md).
- SDKs: [Python](sdk-python.md), [TypeScript](sdk-typescript.md),
  [Go](sdk-go.md) and [Java](sdk-java.md).
- [Reason codes](reason-codes.md): what each denial means and how an agent
  should fix its query.

### Platform and SRE teams

- [Deployment overview](deployment.md), then the cloud guides for
  [AWS](deploy-aws.md), [Google Cloud](deploy-gcp.md) and
  [Azure](deploy-azure.md).
- [Kubernetes operator](kubernetes-operator.md) and [Terraform](terraform.md).
- [Production checklist](operations/production-checklist.md): everything to
  confirm before go-live.
- [High availability and scaling](operations/high-availability.md),
  [Versioning and upgrades](operations/upgrades.md),
  [Troubleshooting](operations/troubleshooting.md) and
  [Runbooks](operations/runbooks.md).
- [Observability](observability.md), [Audit sinks](audit-sinks.md) and
  [Performance](performance.md).

### Security and compliance reviewers

- [Security overview](security/overview.md): data flows, what each component
  sees and stores, and the fail-closed design.
- [Hardening guide](security/hardening.md): the recommended secure baseline.
- [Compliance mapping](security/compliance.md): how HaltSQL features support
  SOC 2, ISO/IEC 27001, GDPR and HIPAA controls.
- [Supply chain and releases](security/supply-chain.md) and the
  [Security questionnaire](security/security-questionnaire.md).
- [Threat model](threat-model.md) and [Defense in depth](defense-in-depth.md).

### Data governance teams

- [Data catalogs](integrations/data-catalogs.md): turn PII labels from dbt,
  DataHub, Unity Catalog, Atlan, Collibra and OpenMetadata into policy.
- [Roll out a policy safely](tutorials/roll-out-a-policy-safely.md): tests,
  CI, shadow mode, signed bundles and rollback.
- [Policy reference](policy-reference.md) and
  [Tenancy semantics](tenancy.md).

## Integrations

| Area | Covered |
|---|---|
| [MCP clients](integrations/mcp-clients.md) | Claude Desktop, Claude Code, Cursor, VS Code and any MCP client |
| [Agent frameworks](agent-frameworks.md) | LangChain, LangGraph, OpenAI Agents SDK, Google ADK, LlamaIndex, CrewAI, Semantic Kernel, Vanna |
| [SDKs](integrations.md) | Python, TypeScript, Go, Java, plus the HTTP API for any language |
| [Data catalogs](integrations/data-catalogs.md) | dbt, DataHub, Unity Catalog, Atlan, Collibra, OpenMetadata |
| [Identity providers](integrations/identity-providers.md) | Keycloak, Microsoft Entra ID, Okta, Auth0 and any OIDC provider |
| [Secrets managers](integrations/secrets-managers.md) | HashiCorp Vault, AWS Secrets Manager, Google Secret Manager |
| [Audit and observability](integrations/audit-and-observability.md) | S3, GCS, Kafka, Elasticsearch, OpenSearch, OpenTelemetry, Prometheus |
| [Wire proxy](proxy.md) | Any PostgreSQL driver: psql, JDBC, pgx, psycopg and others |

## Features

- [CLI](cli.md): every `haltsql` command, flag and exit code.
- [HTTP API](http-api.md): the `haltsql-server` sidecar
  ([OpenAPI 3.1](openapi.yaml)).
- [Wire proxy](proxy.md): `haltsql-proxy`, the PostgreSQL wire-protocol
  firewall.
- [Signed policy bundles](policy-bundles.md) and [Policy CI](policy-ci.md).
- [Shadow mode reports](shadow-reports.md): what would have been denied, and
  conservative policy suggestions.
- [Open Policy Agent](opa.md): an optional deny-only decision after HaltSQL
  allows a query.
- [RLS generation](rls-generation.md) and
  [Schema and PII import](schema-and-pii.md).

## How it works

Explainers with diagrams, from the big picture down to the code:

- [Architecture](how-it-works/architecture.md): components and where HaltSQL sits in your stack.
- [The verification pipeline](how-it-works/verification-pipeline.md): one `verify` call, end to end.
- [The parser](how-it-works/parser.md) and [the analyzer](how-it-works/analyzer.md): from SQL text to typed AST to reasons.
- [The tenancy proof](how-it-works/tenancy-proof.md): what must be proven before a tenant table is read.
- [Policies and config](how-it-works/policies-and-config.md) and [the policy lifecycle](how-it-works/policy-lifecycle.md).
- [Deployment modes](how-it-works/deployment-modes.md), [inside the proxy](how-it-works/proxy-internals.md) and [inside the server](how-it-works/server-internals.md).
- [How HaltSQL is tested](how-it-works/assurance.md): the test suites, attack corpus and enterprise lab.

## Reference

- [Policy reference](policy-reference.md): every key in a `kind: Policy` document.
- [Config reference](config-reference.md): the `kind: Config` document for the CLI and server.
- [Verdict format](verdict.md): the JSON returned for every check.
- [Reason codes](reason-codes.md): what each code means.
- [Tenancy semantics](tenancy.md): exactly what HaltSQL must prove for a tenant-scoped table.
- [Glossary](glossary.md): HaltSQL terms in one place.

### Document kinds at a glance

Everything HaltSQL reads is YAML or JSON with `apiVersion: haltsql.dev/v1` and a
`kind`:

| Kind | Purpose | Reference |
|---|---|---|
| `Policy` | What SQL is allowed | [policy-reference.md](policy-reference.md) |
| `Config` | How the CLI and server run | [config-reference.md](config-reference.md) |
| `TestSuite` | Allow/deny test cases for a policy | [testing.md](testing.md#policy-test-suites) |
| `Catalog` | Schema snapshot (tables and column types) | [policy-reference.md](policy-reference.md#catalog) |
| `Scenario` | Enterprise lab scenario | [testing.md](testing.md#the-enterprise-lab-haltlab) |
| `ProxyConfig` | How `haltsql-proxy` runs | [proxy.md](proxy.md) |
| `PolicyBundle` | Signed set of policies (canonical JSON + `.sig`) | [policy-bundles.md](policy-bundles.md) |

`haltsql validate FILE...` checks `Policy`, `Config`, `TestSuite`, `Catalog`
and `Scenario` documents; `haltsql-proxy validate --config FILE` checks a
`ProxyConfig`, and `haltsql bundle verify` checks a `PolicyBundle`.
`haltsql schema export` writes JSON Schemas for editor autocomplete.

## Project

- [Architecture Decision Records](adr/)
  - [0001: Parse with libpg_query](adr/0001-parser-libpg-query.md)
  - [0002: Typed AST, fail closed](adr/0002-typed-ast-fail-closed.md)
  - [0003: Tenancy semantics](adr/0003-tenancy-semantics.md)
  - [0004: Verdict schema and reason codes](adr/0004-verdict-schema-and-reason-codes.md)
  - [0005: Apache-2.0 license](adr/0005-license-apache-2.md) (superseded by 0006)
  - [0006: MIT license](adr/0006-license-mit.md)
  - [0007: Deny-only external policy and admin API](adr/0007-external-policy-and-admin-api.md)
- [Contributing](../CONTRIBUTING.md), [Security policy](../SECURITY.md),
  [Governance](../GOVERNANCE.md) and [Changelog](../CHANGELOG.md).
