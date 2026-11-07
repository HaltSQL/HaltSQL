# @haltsql/client

Fail-closed TypeScript/Node.js client for the HaltSQL sidecar (`haltsql-server`):
verify LLM-generated PostgreSQL against a policy before running it.
Zero runtime dependencies, ESM + CommonJS, Node.js >= 18.

```ts
import { HaltSQLClient, guardedQuery } from "@haltsql/client";

const haltsql = new HaltSQLClient({ baseUrl: "http://127.0.0.1:8080", token: process.env.HALTSQL_TOKEN });
const { result } = await guardedQuery(haltsql, pool, sql, { tenant_id: session.tenantId });
```

Every failure rejects with a `HaltSQLError` (never an allow). Full guide:
[docs/sdk-typescript.md](../../docs/sdk-typescript.md).

Development: `npm ci && npm test`.
