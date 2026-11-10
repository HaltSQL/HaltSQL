// Integration tests. Each part skips cleanly when its dependency is missing:
//  - Postgres (make -C lab up; localhost:5417): guardedQuery with node-postgres.
//    HALTSQL_REQUIRE_POSTGRES=1 (set in CI) turns that skip into a failure.
//  - haltsql-server binary (_build or HALTSQL_SERVER_BIN): real sidecar.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { HaltSQLClient, HaltSQLDeniedError, guardedQuery } from "../dist/esm/index.js";
import { PG, fakeServer, pgReachable, vector } from "./helpers.mjs";

const DB = "haltsql_polyglot_ts";

const havePg = await pgReachable();

describe("guardedQuery against Postgres", { skip: !havePg && "Postgres not reachable" }, () => {
  let admin;
  let pool;
  before(async () => {
    admin = new pg.Client({ ...PG, database: "postgres" });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${DB}`);
    await admin.query(`CREATE DATABASE ${DB}`);
    pool = new pg.Pool({ ...PG, database: DB, max: 2 });
    await pool.query(`
      CREATE SCHEMA app;
      CREATE TABLE app.orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text, customer_id int);
      INSERT INTO app.orders VALUES (1,'acme','open',1),(2,'acme','paid',1),(3,'globex','open',2);
      CREATE SCHEMA reporting;
      CREATE TABLE reporting.revenue_daily (org_id text, day date, revenue_cents bigint, currency text);
      INSERT INTO reporting.revenue_daily VALUES
        ('acme','2026-01-01',100,'USD'),('acme-eu','2026-01-01',200,'EUR'),('globex','2026-01-01',999,'USD');
    `);
  });
  after(async () => {
    await pool?.end();
    await admin?.query(`DROP DATABASE IF EXISTS ${DB}`);
    await admin?.end();
  });

  async function withVector(name, fn) {
    const v = vector(name);
    const srv = await fakeServer(() => ({ status: v.status, body: v.response }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, token: v.token });
      await fn(c, v);
    } finally {
      await srv.close();
    }
  }

  test("bound tenant param returns only that tenant's rows", async () => {
    await withVector("allowed_bound_single_tenant", async (c, v) => {
      // search_path matches the policy's search_path: [app].
      const client = await pool.connect();
      try {
        await client.query("SET search_path = app");
        const { result } = await guardedQuery(c, client, v.request.sql, v.request.context);
        assert.deepEqual(result.rows.map((r) => r.id).sort(), [1, 2]);
      } finally {
        client.release();
      }
    });
  });

  test("set-valued tenant binds a text[] for = ANY($1)", async () => {
    await withVector("allowed_set_valued_tenant", async (c, v) => {
      const client = await pool.connect();
      try {
        await client.query("SET search_path = reporting, public");
        const { result } = await guardedQuery(c, client, v.request.sql, v.request.context);
        assert.deepEqual(result.rows.map((r) => r.org_id).sort(), ["acme", "acme-eu"]);
      } finally {
        client.release();
      }
    });
  });

  test("denied SQL never reaches Postgres", async () => {
    await withVector("denied_multi_statement", async (c, v) => {
      const client = await pool.connect();
      try {
        await client.query("SET search_path = app");
        await assert.rejects(guardedQuery(c, client, v.request.sql, v.request.context), HaltSQLDeniedError);
        const { rows } = await client.query("SELECT count(*)::int AS n FROM app.orders");
        assert.equal(rows[0].n, 3); // DROP TABLE did not run
      } finally {
        client.release();
      }
    });
  });
});

const root = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const serverBin = process.env.HALTSQL_SERVER_BIN ?? join(root, "_build/default/bin/server/main.exe");
const haveServer = existsSync(serverBin);
if (!haveServer) console.log(`# skipping real-server tests: ${serverBin} not found`);

describe("against the real haltsql-server", { skip: !haveServer && "server binary not built" }, () => {
  const token = "it-token-" + Math.random().toString(36).slice(2);
  const port = 30000 + Math.floor(Math.random() * 20000);
  let proc;
  let dir;
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "haltsql-ts-"));
    const cfg = join(dir, "config.yaml");
    writeFileSync(cfg, `apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:${port}
  auth:
    tokens:
      - name: it
        token_sha256: ${createHash("sha256").update(token).digest("hex")}
        policy: saas-analytics
policies:
  - path: ${join(root, "examples/policies/saas.yaml")}
`);
    proc = spawn(serverBin, ["--config", cfg, "--audit", "none", "--no-watch", "--log-level", "error"], { stdio: "ignore" });
    const c = new HaltSQLClient({ baseUrl: `http://127.0.0.1:${port}` });
    for (let i = 0; i < 100; i++) {
      try {
        if ((await c.ready()).ready) return;
      } catch {}
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("server did not start");
  });
  after(() => {
    proc?.kill("SIGTERM");
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  test("allow, deny, auth failure, policies", async () => {
    const c = new HaltSQLClient({ baseUrl: `http://127.0.0.1:${port}`, token });
    const ok = await c.verify("SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50", { tenant_id: "acme" });
    assert.equal(ok.allowed, true);
    assert.deepEqual(ok.bind_params, [{ param: 1, value: "acme" }]);
    const no = await c.verify("SELECT email FROM customers LIMIT 1", { tenant_id: "acme" });
    assert.equal(no.allowed, false);
    assert.ok(no.reasons.some((r) => r.code === "E_COLUMN_DENIED"));
    const bad = new HaltSQLClient({ baseUrl: `http://127.0.0.1:${port}`, token: "wrong" });
    await assert.rejects(bad.verify("SELECT 1"), (e) => e.status === 401 && e.code === "UNAUTHORIZED");
    assert.deepEqual((await c.policies()).map((p) => p.name), ["saas-analytics"]);
    assert.deepEqual(await c.health(), { status: "ok" });
  });
});
