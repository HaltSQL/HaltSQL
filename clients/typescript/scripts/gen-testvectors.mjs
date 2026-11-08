#!/usr/bin/env node
// Regenerates the SDK test vectors (request + real verdict pairs) by running
// the real haltsql-server and recording its responses. The same file is
// written to clients/typescript/testdata, clients/go/haltsql/testdata and
// clients/java/src/test/resources (vectors.json) so the three
// SDKs are tested against identical server output.
//
// Usage (from the repository root, after building the server):
//   eval $(opam env); dune build ./bin/server/main.exe
//   node clients/typescript/scripts/gen-testvectors.mjs [path/to/haltsql-server]
//
// The tokens below are throwaway test tokens that only exist in this script
// and in the vectors; they authenticate nothing outside the test server.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const serverBin =
  process.argv[2] ?? join(root, "_build/default/bin/server/main.exe");

const TOKENS = {
  saas: "test-token-saas-analytics",
  org: "test-token-org-rollup",
};
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const port = 20000 + Math.floor(Math.random() * 20000);

const dir = mkdtempSync(join(tmpdir(), "haltsql-vectors-"));
const cfg = join(dir, "config.yaml");
writeFileSync(
  cfg,
  `apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:${port}
  auth:
    tokens:
      - name: saas
        token_sha256: ${sha256(TOKENS.saas)}
        policy: saas-analytics
      - name: org
        token_sha256: ${sha256(TOKENS.org)}
        policy: org-rollup-reports
policies:
  - path: ${join(root, "examples/policies/saas.yaml")}
  - path: ${join(root, "examples/policies/hierarchical.yaml")}
`,
);

const CASES = [
  {
    name: "allowed_bound_single_tenant",
    token: "saas",
    request: {
      sql: "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
      context: { tenant_id: "acme" },
    },
  },
  {
    name: "allowed_join_two_tenant_params",
    token: "saas",
    request: {
      sql: "SELECT o.id, c.name FROM orders o JOIN customers c ON c.id = o.customer_id AND c.tenant_id = $2 WHERE o.tenant_id = $1 LIMIT 10",
      context: { tenant_id: "acme" },
    },
  },
  {
    name: "allowed_integer_context",
    token: "saas",
    request: {
      sql: "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5",
      context: { tenant_id: 42 },
    },
  },
  {
    name: "allowed_set_valued_tenant",
    token: "org",
    request: {
      sql: "SELECT org_id, day, revenue_cents FROM revenue_daily WHERE org_id = ANY($1) LIMIT 100",
      context: { org_ids: ["acme", "acme-eu", "acme-us"] },
    },
  },
  {
    name: "allowed_global_table_no_params",
    token: "saas",
    request: { sql: "SELECT * FROM currencies LIMIT 10", context: { tenant_id: "acme" } },
  },
  {
    name: "denied_column_and_tenant",
    token: "saas",
    request: {
      sql: "SELECT o.id, c.email FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.tenant_id = $1 LIMIT 50",
      context: { tenant_id: "acme" },
    },
  },
  {
    name: "denied_multi_statement",
    token: "saas",
    request: {
      sql: "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 1; DROP TABLE orders",
      context: { tenant_id: "acme" },
    },
  },
  {
    name: "denied_parse_error",
    token: "saas",
    request: { sql: "SELEC id FROM orders", context: { tenant_id: "acme" } },
  },
  {
    name: "denied_limit_required",
    token: "saas",
    request: {
      sql: "SELECT id FROM orders WHERE tenant_id = $1",
      context: { tenant_id: "acme" },
    },
  },
  {
    name: "denied_delete_statement",
    token: "saas",
    request: {
      sql: "DELETE FROM orders WHERE tenant_id = $1",
      context: { tenant_id: "acme" },
    },
  },
  {
    name: "denied_context_missing",
    token: "saas",
    request: { sql: "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5" },
  },
  {
    name: "error_unauthorized",
    token: null,
    request: { sql: "SELECT 1" },
  },
  {
    name: "error_wrong_token",
    token: "invalid",
    request: { sql: "SELECT 1" },
  },
  {
    name: "error_forbidden_policy",
    token: "saas",
    request: { sql: "SELECT 1", policy: "org-rollup-reports" },
  },
  {
    name: "error_bad_request",
    token: "saas",
    raw: '{"sql": 7}',
  },
];

function tokenValue(t) {
  if (t === null) return null;
  if (t === "invalid") return "not-a-valid-token";
  return TOKENS[t];
}

function expectFor(status, body) {
  if (status !== 200) return { allowed: false, codes: [], positional: null, error_code: body?.error?.code ?? null };
  const bp = [...body.bind_params].sort((a, b) => a.param - b.param);
  return {
    allowed: body.allowed === true,
    codes: body.reasons.map((r) => r.code),
    positional: body.allowed ? bp.map((b) => b.value) : null,
    error_code: null,
  };
}

async function waitReady() {
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/readyz`);
      if (r.status === 200) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("server did not become ready");
}

const srv = spawn(serverBin, ["--config", cfg, "--audit", "none", "--no-watch"], {
  stdio: ["ignore", "ignore", "inherit"],
});
try {
  await waitReady();
  const vectors = [];
  for (const c of CASES) {
    const headers = { "content-type": "application/json" };
    const tok = tokenValue(c.token);
    if (tok) headers.authorization = `Bearer ${tok}`;
    const body = c.raw ?? JSON.stringify(c.request);
    const r = await fetch(`http://127.0.0.1:${port}/v1/verify`, { method: "POST", headers, body });
    const json = await r.json();
    vectors.push({
      name: c.name,
      token: tok,
      request: c.raw === undefined ? c.request : null,
      raw_request: c.raw ?? null,
      status: r.status,
      response: json,
      expect: expectFor(r.status, json),
    });
  }
  const health = await (await fetch(`http://127.0.0.1:${port}/healthz`)).json();
  const ready = await (await fetch(`http://127.0.0.1:${port}/readyz`)).json();
  const policies = await (
    await fetch(`http://127.0.0.1:${port}/v1/policies`, {
      headers: { authorization: `Bearer ${TOKENS.saas}` },
    })
  ).json();
  const doc = {
    description:
      "Real haltsql-server responses recorded by clients/typescript/scripts/gen-testvectors.mjs. Tokens are throwaway test values.",
    tokens: TOKENS,
    healthz: health,
    readyz: ready,
    policies,
    vectors,
  };
  const out = JSON.stringify(doc, null, 2) + "\n";
  for (const sub of ["typescript/testdata", "go/haltsql/testdata", "java/src/test/resources"]) {
    const d = join(root, "clients", sub);
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "vectors.json"), out);
  }
  console.log(`wrote ${vectors.length} vectors`);
} finally {
  srv.kill("SIGTERM");
  rmSync(dir, { recursive: true, force: true });
}
