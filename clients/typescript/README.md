# @haltsql/client

Fail-closed TypeScript/Node.js client for the HaltSQL sidecar (`haltsql-server`):
verify LLM-generated PostgreSQL against a policy before running it.
Zero runtime dependencies, ESM + CommonJS, Node.js >= 18.

```ts
import { HaltSQLClient, guardedTransaction } from "@haltsql/client";

const haltsql = new HaltSQLClient({ baseUrl: "http://127.0.0.1:8080", token: process.env.HALTSQL_TOKEN });
const { result } = await guardedTransaction(haltsql, pool, sql, { tenant_id: session.tenantId });
```

`guardedTransaction` runs the verified SQL in a transaction pinned to the
policy's search path (`READ ONLY` for a `SELECT`). `guardedQuery` is the
low-level single-statement form; it does not pin the search path.

Every failure rejects with a `HaltSQLError` (never an allow). Every call has a
timeout (5 s per attempt by default) and bounded retries; TLS verification is
on by default, and a private CA or mutual TLS is configured with an undici
`dispatcher`. The token never appears in errors. Full guide:
[docs/sdk-typescript.md](../../docs/sdk-typescript.md).

## Local verification (no sidecar)

On Linux x64/arm64 (glibc) and macOS arm64, `npm install @haltsql/client` also
installs the compiled engine (`@haltsql/native-<platform>-<arch>`, an optional
dependency). `LocalVerifier` runs it as one long-lived child process and
pipelines requests over stdin/stdout: ~0.1-0.5 ms per warm `verify()`.

```ts
import { LocalVerifier } from "@haltsql/client";

const haltsql = await LocalVerifier.create({ policyFile: "policies/saas.yaml" });
const verdict = await haltsql.verify(sql, { tenant_id: session.tenantId });
await haltsql.check(sql, ctx);          // throws HaltSQLDeniedError unless allowed
await haltsql.verifyMany([sqlA, sqlB], ctx);
await haltsql.close();
```

Same fail-closed contract and verdict type as `HaltSQLClient`. The engine is
found via the `binary` option, then `HALTSQL_BIN`, then the platform package,
then `haltsql` on `PATH`. Details: [docs/sdk-typescript.md](../../docs/sdk-typescript.md#local-verification-no-sidecar).

Development: `npm ci && npm test` (the local-mode tests use
`../../_build/default/bin/haltsql/main.exe` or `HALTSQL_BIN`, and skip if
neither exists). `npm run smoke:native` packs and installs the platform package
for this machine end to end.
