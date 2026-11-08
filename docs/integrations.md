# Integrations

The sidecar's HTTP API is small: one `POST /v1/verify` call per query.

## Official clients

Use these rather than the sketches below. Every one fails closed, checks that
the verdict's `sql_sha256` matches the SQL it sent, and has a guarded-execute
helper that runs exactly the verified string with `bind_params`:

| Language / tool | Location | Guide |
|---|---|---|
| Python (sync + async; psycopg 3, asyncpg, SQLAlchemy; local CLI verifier) | [`clients/python`](../clients/python) | [sdk-python.md](sdk-python.md) |
| TypeScript / Node.js (node-postgres) | [`clients/typescript`](../clients/typescript) | [sdk-typescript.md](sdk-typescript.md) |
| Go (`database/sql`, pgx, lib/pq) | [`clients/go`](../clients/go) | [sdk-go.md](sdk-go.md) |
| Java (PgJDBC) | [`clients/java`](../clients/java) | [sdk-java.md](sdk-java.md) |
| MCP server (`haltsql-mcp`) | [`clients/mcp`](../clients/mcp) | [mcp.md](mcp.md) |
| LangChain | [`integrations/langchain`](../integrations/langchain) | [README](../integrations/langchain/README.md) |
| LlamaIndex | [`integrations/llamaindex`](../integrations/llamaindex) | [README](../integrations/llamaindex/README.md) |
| Vanna | [`integrations/vanna`](../integrations/vanna) | [README](../integrations/vanna/README.md) |
| OpenAI Agents SDK | [`integrations/openai_agents`](../integrations/openai_agents) | [README](../integrations/openai_agents/README.md) |
| LangGraph | [`integrations/langgraph`](../integrations/langgraph) | [README](../integrations/langgraph/README.md) |
| Semantic Kernel | [`integrations/semantic_kernel`](../integrations/semantic_kernel) | [README](../integrations/semantic_kernel/README.md) |
| CrewAI | [`integrations/crewai`](../integrations/crewai) | [README](../integrations/crewai/README.md) |
| Google ADK (Agent Development Kit) | [`integrations/google_adk`](../integrations/google_adk) | [README](../integrations/google_adk/README.md) |

The four language SDKs share the same transport defaults:

| | Python | TypeScript | Go | Java |
|---|---|---|---|---|
| Timeout per attempt | 2 s | 5 s | 5 s | 5 s |
| Retries (after the first attempt) | 2 (`max_attempts=3`) | 2 | 2 | 2 |
| Retried on | connection errors, timeouts, 502/503/504 | network errors, timeouts, 503 | connection errors, timeouts, 503 | connection errors, timeouts, 503 |
| Private CA / mutual TLS | `verify=`, `cert=` | undici `dispatcher` | `WithTLSConfig` | `sslContext()` |
| `User-Agent` | `haltsql-python/<v>` | `haltsql-client-js/<v>` | `haltsql-client-go/<v>` | `haltsql-client-java/<v>` |

In all of them TLS certificate verification is on by default, redirects are
never followed, responses over 8 MiB are rejected, backoff is exponential with
jitter and capped (also capping `Retry-After`), and the bearer token never
appears in error messages or string representations. One client instance is
safe to share across threads or concurrent requests and reuses connections.

Clients can check their behaviour against the shared request/verdict vectors
in [`clients/testvectors`](../clients/testvectors). Drivers that cannot be
changed at all can connect through [haltsql-proxy](proxy.md) instead.

## Sketches

The snippets below show the raw protocol for languages and frameworks without
an official client. They are sketches to adapt.

Every integration follows the same rules:

1. Take the **context** from your authenticated session, never from the model.
2. If the verdict is not `allowed`, or the call fails in any way, **do not run
   the query** (fail closed). Return the reasons to the agent.
3. If allowed, run **exactly** the verified SQL string, binding
   `bind_params` in order of `param`.
4. Run it as a restricted database role with RLS (see
   [defense-in-depth.md](defense-in-depth.md)).

## Python

```python
import os
import requests
import psycopg

HALTSQL_URL = os.environ.get("HALTSQL_URL", "http://127.0.0.1:8080")
HALTSQL_TOKEN = os.environ["HALTSQL_TOKEN"]


class QueryDenied(Exception):
    def __init__(self, reasons):
        super().__init__("; ".join(f'{r["code"]}: {r.get("hint") or r["message"]}' for r in reasons))
        self.reasons = reasons


def verify(sql: str, context: dict) -> dict:
    try:
        resp = requests.post(
            f"{HALTSQL_URL}/v1/verify",
            json={"sql": sql, "context": context},
            headers={"Authorization": f"Bearer {HALTSQL_TOKEN}"},
            timeout=2,
        )
    except requests.RequestException as e:
        raise QueryDenied([{"code": "E_INTERNAL", "message": f"haltsql unavailable: {e}"}])
    if resp.status_code != 200:
        raise QueryDenied([{"code": "E_INTERNAL", "message": f"haltsql HTTP {resp.status_code}"}])
    verdict = resp.json()
    if verdict.get("allowed") is not True:
        raise QueryDenied(verdict.get("reasons", []))
    return verdict


def run_agent_sql(conn: psycopg.Connection, sql: str, tenant_id: str):
    verdict = verify(sql, {"tenant_id": tenant_id})
    params = [p["value"] for p in sorted(verdict["bind_params"], key=lambda p: p["param"])]
    with conn.transaction():
        conn.execute("SET TRANSACTION READ ONLY")
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", [tenant_id])
        # RawCursor (psycopg >= 3.2) sends the SQL text unchanged with native $n
        # placeholders, so Postgres receives exactly the verified string.
        with psycopg.RawCursor(conn) as cur:
            cur.execute(sql, params)
            return cur.fetchall()
```

Note on placeholders: HaltSQL verifies Postgres `$n` syntax. Use a driver path
that sends the SQL text unchanged with positional parameters (psycopg's
`RawCursor`, asyncpg's `fetch(sql, *params)`, node-postgres, pgx). Never
string-format values into the SQL.

## TypeScript

```typescript
import { Pool } from "pg";

const HALTSQL_URL = process.env.HALTSQL_URL ?? "http://127.0.0.1:8080";
const HALTSQL_TOKEN = process.env.HALTSQL_TOKEN!;

type Reason = { code: string; message: string; hint?: string; loc?: number };
type Verdict = {
  allowed: boolean;
  reasons: Reason[];
  bind_params: { param: number; value: string | string[] }[];
};

export class QueryDenied extends Error {
  constructor(public reasons: Reason[]) {
    super(reasons.map((r) => `${r.code}: ${r.hint ?? r.message}`).join("; "));
  }
}

export async function verify(sql: string, context: Record<string, unknown>): Promise<Verdict> {
  let res: Response;
  try {
    res = await fetch(`${HALTSQL_URL}/v1/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${HALTSQL_TOKEN}` },
      body: JSON.stringify({ sql, context }),
      signal: AbortSignal.timeout(2000),
    });
  } catch (e) {
    throw new QueryDenied([{ code: "E_INTERNAL", message: `haltsql unavailable: ${e}` }]);
  }
  if (res.status !== 200) {
    throw new QueryDenied([{ code: "E_INTERNAL", message: `haltsql HTTP ${res.status}` }]);
  }
  const verdict = (await res.json()) as Verdict;
  if (verdict.allowed !== true) throw new QueryDenied(verdict.reasons ?? []);
  return verdict;
}

export async function runAgentSql(pool: Pool, sql: string, tenantId: string) {
  const verdict = await verify(sql, { tenant_id: tenantId });
  const params = [...verdict.bind_params].sort((a, b) => a.param - b.param).map((p) => p.value);
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    const result = await client.query(sql, params); // node-postgres sends $n SQL unchanged
    await client.query("COMMIT");
    return result.rows;
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}
```

## Go

```go
package haltsqlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"
)

type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

type BindParam struct {
	Param int             `json:"param"`
	Value json.RawMessage `json:"value"` // string, or array of strings
}

type Verdict struct {
	Allowed    bool        `json:"allowed"`
	Reasons    []Reason    `json:"reasons"`
	BindParams []BindParam `json:"bind_params"`
}

type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
}

func New(url, token string) *Client {
	return &Client{URL: url, Token: token, HTTP: &http.Client{Timeout: 2 * time.Second}}
}

// Verify returns the verdict, or an error if the query must not run.
// Any transport or HTTP error is treated as a denial.
func (c *Client) Verify(ctx context.Context, sql string, sessionCtx map[string]any) (*Verdict, error) {
	body, _ := json.Marshal(map[string]any{"sql": sql, "context": sessionCtx})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/verify", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("haltsql unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("haltsql HTTP %d", resp.StatusCode)
	}
	var v Verdict
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("haltsql bad response: %w", err)
	}
	if !v.Allowed {
		return &v, fmt.Errorf("query denied: %v", v.Reasons)
	}
	sort.Slice(v.BindParams, func(i, j int) bool { return v.BindParams[i].Param < v.BindParams[j].Param })
	return &v, nil
}
```

With pgx, run the verified string with `tx.Query(ctx, sql, args...)`, decoding
each `BindParam.Value` into a `string` or `[]string`.

## Agent tool wrapper (LangChain-style)

Expose a single "run SQL" tool whose implementation always verifies first and
returns the reasons on denial, so the model can correct itself:

```python
from langchain_core.tools import tool

def make_sql_tool(conn, session):
    @tool
    def run_sql(sql: str) -> str:
        """Run one read-only PostgreSQL SELECT. Use $1 wherever the tenant ID is
        needed (for example `WHERE o.tenant_id = $1`), qualify every column with
        a table alias, and always include LIMIT."""
        try:
            rows = run_agent_sql(conn, sql, tenant_id=session.tenant_id)
        except QueryDenied as e:
            return "Query rejected. Fix it and try again:\n" + "\n".join(
                f'- {r["code"]}: {r.get("hint") or r["message"]}' for r in e.reasons
            )
        return format_rows(rows, max_rows=50)

    return run_sql
```

Notes:

- The tenant ID comes from `session`, captured when the tool is created. The
  model cannot pass it.
- The tool description teaches the model the policy's conventions (bound
  tenancy, aliases, `LIMIT`), which reduces denials.
- Cap retries (for example three attempts) so a model stuck in a loop does not
  burn tokens.

## MCP server sketch

An [MCP](https://modelcontextprotocol.io) server can expose a `query` tool
guarded by HaltSQL. The MCP server holds the database connection and the
caller's identity; the model only supplies SQL.

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("haltsql-guarded-postgres")

@mcp.tool()
def query(sql: str) -> str:
    """Run one read-only SQL SELECT against the analytics database.
    Use $1 for the tenant ID, alias every table, and include LIMIT <= 1000."""
    tenant_id = current_identity().tenant_id   # from the MCP session's auth, not from the model
    try:
        rows = run_agent_sql(get_conn(), sql, tenant_id)
    except QueryDenied as e:
        return "Rejected by policy:\n" + "\n".join(
            f'- {r["code"]}: {r.get("hint") or r["message"]}' for r in e.reasons
        )
    return to_markdown_table(rows)

if __name__ == "__main__":
    mcp.run()
```

Expose a second read-only tool, such as `describe_schema`, that returns only
the tables and columns in the policy, so the model does not guess names.
