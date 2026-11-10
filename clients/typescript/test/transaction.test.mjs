// guardedTransaction / guardedTransactionOnClient: the transaction-owning
// guard that pins the verdict's search path.
//  - With a fake pool: the exact statements, their order, and what happens on
//    errors.
//  - Against Postgres (make -C lab up; localhost:5417): the pin really decides
//    which table is read. Skipped when Postgres is not reachable, unless
//    HALTSQL_REQUIRE_POSTGRES=1 (set in CI), which makes that a failure.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import {
  HaltSQLDeniedError,
  HaltSQLTransportError,
  HaltSQLUsageError,
  guardedQuery,
  guardedTransaction,
  guardedTransactionOnClient,
  searchPathSetting,
} from "../dist/esm/index.js";
import { PG, pgReachable, vector } from "./helpers.mjs";

/** A stub verifier: the recorded allow verdict (search_path [app], $1 = acme), changed by `patch`. */
function verifier(patch = {}) {
  const base = vector("allowed_bound_single_tenant").response;
  const verdict = { ...base, ...patch, policy: { ...base.policy, ...(patch.policy ?? {}) } };
  if (patch.policy && "search_path" in patch.policy && patch.policy.search_path === undefined) {
    delete verdict.policy.search_path;
  }
  return { verify: async () => verdict };
}
const SHADOW = { shadow_reasons: [{ code: "E_TENANT_MISSING", message: "m", rule: "r" }] };
const SET = "SELECT set_config($1, $2, true)";

describe("guardedTransaction (fake driver)", () => {
  const SQL = "  SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5 -- c\n";
  /** A fake pool with one client; statements for which `failOn(text)` is true reject. */
  function fakePool(failOn = () => false) {
    const calls = [];
    const released = [];
    let connects = 0;
    const client = {
      query: async (text, values) => {
        calls.push(values === undefined ? { text } : { text, values });
        if (failOn(text)) throw new Error(`boom: ${text.trim().split(" ")[0]}`);
        return { rows: [{ ok: 1 }] };
      },
      release: (...a) => released.push(a[0]),
    };
    return { calls, released, client, connects: () => connects, connect: async () => (connects++, client) };
  }

  test("select: BEGIN READ ONLY, settings, pin last, the verified string, COMMIT", async () => {
    const pool = fakePool();
    const seen = [];
    const { result, verdict } = await guardedTransaction(verifier(), pool, SQL, { tenant_id: "acme" }, {
      settings: { "app.tenant_id": "acme", search_path: "public" },
      onVerdict: (v) => seen.push(v),
    });
    assert.deepEqual(result.rows, [{ ok: 1 }]);
    assert.equal(verdict.allowed, true);
    assert.equal(seen.length, 1);
    assert.deepEqual(pool.calls, [
      { text: "BEGIN READ ONLY" },
      { text: SET, values: ["app.tenant_id", "acme"] },
      { text: SET, values: ["search_path", "public"] },
      { text: SET, values: ["search_path", '"app"'] },
      { text: SQL, values: ["acme"] },
      { text: "COMMIT" },
    ]);
    assert.equal(pool.connects(), 1);
    assert.deepEqual(pool.released, [undefined]);
  });

  test("a write verdict is not forced read-only", async () => {
    for (const kind of ["insert", "update", "delete"]) {
      const pool = fakePool();
      await guardedTransaction(verifier({ statement_kind: kind }), pool, SQL, {});
      assert.deepEqual(pool.calls.map((c) => c.text), ["BEGIN", SET, SQL, "COMMIT"]);
    }
  });

  test("schema names are quoted as identifiers", async () => {
    const v = verifier({ policy: { search_path: ["app", 'we"ird', "Mixed", "a,b", ""] } });
    assert.equal(searchPathSetting(await v.verify()), '"app", "we""ird", "Mixed", "a,b", ""');
    const pool = fakePool();
    await guardedTransaction(v, pool, SQL, {});
    assert.deepEqual(pool.calls[1], { text: SET, values: ["search_path", '"app", "we""ird", "Mixed", "a,b", ""'] });
    // An empty list is still pinned (to an empty path); only an absent field is not.
    assert.equal(searchPathSetting(await verifier({ policy: { search_path: [] } }).verify()), "");
  });

  test("a verdict without search_path (older engine) runs and does not pin", async () => {
    const v = verifier({ policy: { search_path: undefined } });
    assert.equal(searchPathSetting(await v.verify()), undefined);
    const pool = fakePool();
    await guardedTransaction(v, pool, SQL, {}, { settings: { search_path: "app" } });
    assert.deepEqual(pool.calls, [
      { text: "BEGIN READ ONLY" },
      { text: SET, values: ["search_path", "app"] },
      { text: SQL, values: ["acme"] },
      { text: "COMMIT" },
    ]);
    const single = fakePool();
    await guardedTransactionOnClient(v, single.client, SQL, {});
    assert.deepEqual(single.calls.map((c) => c.text), ["BEGIN READ ONLY", SQL, "COMMIT"]);
  });

  test("an error in the transaction rolls back, rethrows and releases the client", async () => {
    for (const failing of [SQL, SET, "COMMIT"]) {
      const pool = fakePool((text) => text === failing);
      await assert.rejects(guardedTransaction(verifier(), pool, SQL, {}), /^Error: boom/);
      assert.equal(pool.calls.at(-1).text, "ROLLBACK", failing);
      if (failing === SET) assert.ok(!pool.calls.some((c) => c.text === SQL), "ran without the pin");
      assert.deepEqual(pool.released, [undefined]);

      const single = fakePool((text) => text === failing);
      await assert.rejects(guardedTransactionOnClient(verifier(), single.client, SQL, {}), /^Error: boom/);
      assert.equal(single.calls.at(-1).text, "ROLLBACK", failing);
      assert.deepEqual(single.released, []);
    }
  });

  test("a failed ROLLBACK destroys the pooled client and keeps the first error", async () => {
    const pool = fakePool((text) => text === SQL || text === "ROLLBACK");
    await assert.rejects(guardedTransaction(verifier(), pool, SQL, {}), /boom: SELECT/);
    assert.equal(pool.released.length, 1);
    assert.match(String(pool.released[0]), /boom: ROLLBACK/);
    const single = fakePool((text) => text === SQL || text === "ROLLBACK");
    await assert.rejects(guardedTransactionOnClient(verifier(), single.client, SQL, {}), /boom: SELECT/);
    assert.deepEqual(single.released, []);
  });

  test("a failed BEGIN sends nothing else and releases the client", async () => {
    const pool = fakePool((text) => text.startsWith("BEGIN"));
    await assert.rejects(guardedTransaction(verifier(), pool, SQL, {}), /boom: BEGIN/);
    assert.equal(pool.calls.length, 1);
    assert.deepEqual(pool.released, [undefined]);
  });

  test("denied, shadow would-deny and verifier errors never open a transaction", async () => {
    const denied = vector("denied_column_and_tenant").response;
    const down = async () => {
      throw new HaltSQLTransportError("down");
    };
    const cases = [
      [{ verify: async () => denied }, HaltSQLDeniedError],
      [verifier(SHADOW), HaltSQLDeniedError],
      [verifier({ allowed: "true" }), HaltSQLDeniedError],
      [{ verify: down }, HaltSQLTransportError],
    ];
    for (const [v, type] of cases) {
      const pool = fakePool();
      await assert.rejects(guardedTransaction(v, pool, SQL, {}), type);
      assert.equal(pool.connects(), 0);
      await assert.rejects(guardedTransactionOnClient(v, pool.client, SQL, {}), type);
      assert.deepEqual(pool.calls, []);
    }
    const pool = fakePool();
    await guardedTransaction(verifier(SHADOW), pool, SQL, {}, { allowShadow: true });
    assert.equal(pool.calls.at(-1).text, "COMMIT");
  });

  test("bad arguments are refused before verifying", async () => {
    let verified = 0;
    const v = { verify: async () => (verified++, vector("allowed_bound_single_tenant").response) };
    const pool = fakePool();
    for (const settings of [{ "bad name": "x" }, { "x;y": "1" }, { "": "1" }, { ok: 1 }, [], null, "s"]) {
      await assert.rejects(guardedTransaction(v, pool, SQL, {}, { settings }), HaltSQLUsageError);
      await assert.rejects(guardedTransactionOnClient(v, pool.client, SQL, {}, { settings }), HaltSQLUsageError);
    }
    await assert.rejects(guardedTransaction(v, { query: async () => ({}) }, SQL, {}), HaltSQLUsageError);
    await assert.rejects(guardedTransaction(v, null, SQL, {}), HaltSQLUsageError);
    await assert.rejects(guardedTransactionOnClient(v, {}, SQL, {}), HaltSQLUsageError);
    // A pool's query() may use a different session for each statement.
    for (const poolLike of [{ totalCount: 0 }, { idleCount: 0 }]) {
      await assert.rejects(
        guardedTransactionOnClient(v, { query: pool.client.query, ...poolLike }, SQL, {}),
        HaltSQLUsageError,
      );
    }
    assert.equal(verified, 0);
    assert.deepEqual(pool.calls, []);
    // A pg.Client passed as a pool: its connect() resolves to nothing usable.
    await assert.rejects(guardedTransaction(v, { connect: async () => undefined }, SQL, {}), HaltSQLUsageError);
  });
});

const havePg = await pgReachable();

describe("guardedTransaction against Postgres", { skip: !havePg && "Postgres not reachable" }, () => {
  const DB = "haltsql_polyglot_ts_tx";
  let admin;
  let pool; // its sessions start with search_path = public, app: the decoy comes first
  before(async () => {
    admin = new pg.Client({ ...PG, database: "postgres" });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${DB}`);
    pool = new pg.Pool({ ...PG, database: DB, max: 2, options: "-c search_path=public,app" });
    await pool.query(`
      CREATE SCHEMA app;
      CREATE TABLE app.orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text);
      INSERT INTO app.orders VALUES (1,'acme','open'),(2,'acme','paid'),(3,'globex','open');
      CREATE TABLE public.orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text);
      INSERT INTO public.orders VALUES (666,'acme','decoy');
      CREATE SCHEMA "Mixed";
      CREATE TABLE "Mixed".orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text);
      INSERT INTO "Mixed".orders VALUES (50,'acme','mixed');
      CREATE SCHEMA "we""ird, app";
      CREATE TABLE "we""ird, app".orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text);
      INSERT INTO "we""ird, app".orders VALUES (70,'acme','weird');
    `);
  });
  after(async () => {
    await pool?.end();
    await admin?.query(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`);
    await admin?.end();
  });

  const SQL = "SELECT id FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 50";
  const ids = (r) => r.result.rows.map((x) => x.id);
  const showPath = async (c) => (await c.query("SHOW search_path")).rows[0].search_path;
  const count = async (table) => (await pool.query(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n;
  async function withClient(fn) {
    const client = await pool.connect();
    try {
      return await fn(client);
    } finally {
      client.release();
    }
  }

  test("the session default points at the decoy, and the low-level form follows it", async () => {
    await withClient(async (client) => {
      assert.equal(await showPath(client), "public,app");
      assert.deepEqual(ids(await guardedQuery(verifier(), client, SQL, {})), [666]);
    });
  });

  test("pool: the pinned transaction reads the policy's table, not the decoy", async () => {
    assert.deepEqual(ids(await guardedTransaction(verifier(), pool, SQL, {})), [1, 2]);
  });

  test("client: pinned, and the pin is transaction-local", async () => {
    await withClient(async (client) => {
      assert.deepEqual(ids(await guardedTransactionOnClient(verifier(), client, SQL, {})), [1, 2]);
      assert.equal(await showPath(client), "public,app");
      assert.deepEqual((await client.query("SELECT id FROM orders")).rows, [{ id: 666 }]);
    });
    // The pool's own sessions keep their search path too.
    await guardedTransaction(verifier(), pool, SQL, {});
    await guardedTransaction(verifier(), pool, SQL, {});
    await withClient(async (a) => {
      await withClient(async (b) => {
        assert.equal(await showPath(a), "public,app");
        assert.equal(await showPath(b), "public,app");
      });
    });
  });

  test("a search_path in settings does not override the pin; other settings apply", async () => {
    const sql =
      "SELECT id, current_setting('app.tenant_id') AS t, current_setting('search_path') AS sp " +
      "FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 50";
    const r = await guardedTransaction(verifier(), pool, sql, {}, {
      settings: { search_path: "public, app", "app.tenant_id": "acme" },
    });
    assert.deepEqual(r.result.rows, [
      { id: 1, t: "acme", sp: '"app"' },
      { id: 2, t: "acme", sp: '"app"' },
    ]);
  });

  test("upper-case and quoted schema names are pinned as identifiers", async () => {
    const run = (search_path) => guardedTransaction(verifier({ policy: { search_path } }), pool, SQL, {});
    assert.deepEqual(ids(await run(["Mixed"])), [50]);
    assert.deepEqual(ids(await run(['we"ird, app'])), [70]);
    assert.deepEqual(ids(await run(["nosuch", 'we"ird, app', "app"])), [70]);
  });

  test("a verdict without search_path runs under the session's search path", async () => {
    const v = verifier({ policy: { search_path: undefined } });
    assert.deepEqual(ids(await guardedTransaction(v, pool, SQL, {})), [666]);
    assert.deepEqual(ids(await guardedTransaction(v, pool, SQL, {}, { settings: { search_path: "app" } })), [1, 2]);
  });

  test("Postgres receives the verified string byte for byte", async () => {
    for (const sql of [
      "  SELECT current_query() AS q, $1::text AS t /* c */ -- tenant $1\n ",
      "\n\tSELECT current_query() AS q -- no params\n\n",
    ]) {
      const bind_params = sql.includes("$1") ? [{ param: 1, value: "acme" }] : [];
      const r = await guardedTransaction(verifier({ bind_params }), pool, sql, {});
      assert.equal(r.result.rows[0].q, sql);
      await withClient(async (client) => {
        const r2 = await guardedTransactionOnClient(verifier({ bind_params }), client, sql, {});
        assert.equal(r2.result.rows[0].q, sql);
      });
    }
  });

  test("an error rolls back and leaves the client usable", async () => {
    await withClient(async (client) => {
      const bad = "SELECT 1 / (id - id) FROM orders WHERE tenant_id = $1";
      await assert.rejects(guardedTransactionOnClient(verifier(), client, bad, {}), /division by zero/);
      // Not left in an aborted transaction, and the session search path is back.
      assert.equal(await showPath(client), "public,app");
      assert.deepEqual(ids(await guardedTransactionOnClient(verifier(), client, SQL, {})), [1, 2]);
    });
    // A write that fails after it has produced rows leaves nothing behind.
    const ins = "INSERT INTO orders SELECT g, $1, 'x' FROM generate_series(100, 103) g WHERE 10 / (103 - g) > 0";
    const one = new pg.Pool({ ...PG, database: DB, max: 1 });
    try {
      await assert.rejects(guardedTransaction(verifier({ statement_kind: "insert" }), one, ins, {}), /division by zero/);
      // max: 1, so this is the same session, returned to the pool in a usable state.
      assert.deepEqual(ids(await guardedTransaction(verifier(), one, SQL, {})), [1, 2]);
      assert.equal(one.totalCount, 1);
      assert.equal(one.idleCount, 1);
    } finally {
      await one.end();
    }
    assert.equal(await count("app.orders"), 3);
  });

  test("a select verdict runs read-only; an allowed write is committed", async () => {
    const ins = "INSERT INTO orders VALUES (200, $1, 'new')";
    const e = await guardedTransaction(verifier(), pool, ins, {}).catch((x) => x);
    assert.equal(e.code, "25006"); // read_only_sql_transaction
    assert.equal(await count("app.orders"), 3);
    const r = await guardedTransaction(verifier({ statement_kind: "insert" }), pool, ins, {});
    assert.equal(r.result.rowCount, 1);
    // Committed, and into the policy's table rather than the decoy.
    assert.deepEqual((await pool.query("SELECT tenant_id FROM app.orders WHERE id = 200")).rows, [{ tenant_id: "acme" }]);
    assert.equal(await count("public.orders"), 1);
    await pool.query("DELETE FROM app.orders WHERE id = 200");
  });

  test("denied and shadow would-deny verdicts never reach Postgres", async () => {
    const denied = { verify: async () => vector("denied_multi_statement").response };
    let connects = 0;
    const counting = { connect: () => (connects++, pool.connect()) };
    for (const v of [denied, verifier(SHADOW)]) {
      await assert.rejects(guardedTransaction(v, counting, "DELETE FROM orders", {}), HaltSQLDeniedError);
      await withClient(async (client) => {
        let sent = 0;
        const spy = { query: (...a) => (sent++, client.query(...a)) };
        await assert.rejects(guardedTransactionOnClient(v, spy, "DELETE FROM orders", {}), HaltSQLDeniedError);
        assert.equal(sent, 0);
      });
    }
    assert.equal(connects, 0);
    assert.equal(await count("app.orders"), 3);
    assert.equal(await count("public.orders"), 1);
  });

  test("a pg.Pool is refused where a single client is needed", async () => {
    await assert.rejects(guardedTransactionOnClient(verifier(), pool, SQL, {}), HaltSQLUsageError);
    assert.deepEqual(ids(await guardedTransaction(verifier(), pool, SQL, {})), [1, 2]);
  });
});
