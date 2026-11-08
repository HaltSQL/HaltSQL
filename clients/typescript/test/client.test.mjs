import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  HaltSQLClient,
  HaltSQLError,
  HaltSQLHttpError,
  HaltSQLProtocolError,
  HaltSQLTimeoutError,
  HaltSQLTransportError,
  HaltSQLUsageError,
  HaltSQLDeniedError,
  bindParamsToPositional,
  toPgArrayLiteral,
  guardedQuery,
} from "../dist/esm/index.js";
import { fakeServer, vectors, vector } from "./helpers.mjs";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const fast = { retryBaseDelayMs: 1, retryMaxDelayMs: 5 };

/** A fake that replays a recorded vector's status and body. */
function replay(v) {
  return () => ({ status: v.status, body: v.response });
}

describe("recorded vectors (real haltsql-server output)", () => {
  for (const v of vectors.vectors) {
    test(v.name, async () => {
      const srv = await fakeServer(replay(v));
      try {
        const c = new HaltSQLClient({ baseUrl: srv.url, token: v.token ?? undefined, ...fast });
        const sql = v.request ? v.request.sql : "SELECT 1";
        const p = c.verify(sql, v.request?.context, v.request?.policy ? { policy: v.request.policy } : {});
        if (v.status === 200) {
          const verdict = await p;
          assert.equal(verdict.allowed, v.expect.allowed);
          assert.deepEqual(verdict.reasons.map((r) => r.code), v.expect.codes);
          assert.deepEqual(verdict.bind_params, v.response.bind_params);
          assert.equal(verdict.policy.version, v.response.policy.version);
          if (v.expect.allowed) assert.deepEqual(bindParamsToPositional(verdict), v.expect.positional);
          else assert.throws(() => bindParamsToPositional(verdict), HaltSQLUsageError);
        } else {
          await assert.rejects(p, (e) => {
            assert.ok(e instanceof HaltSQLHttpError);
            assert.equal(e.status, v.status);
            assert.equal(e.code, v.expect.error_code);
            assert.equal(e.allowed, false);
            return true;
          });
        }
        // The request on the wire.
        const req = srv.requests[0];
        assert.equal(req.method, "POST");
        assert.equal(req.url, "/v1/verify");
        assert.equal(req.headers["content-type"], "application/json");
        if (v.token) assert.equal(req.headers.authorization, `Bearer ${v.token}`);
        else assert.equal(req.headers.authorization, undefined);
        if (v.request) {
          const sent = JSON.parse(req.body);
          assert.equal(sent.sql, v.request.sql);
          assert.deepEqual(sent.context, v.request.context ?? {});
          assert.equal(sent.policy, v.request.policy);
        }
      } finally {
        await srv.close();
      }
    });
  }
});

describe("operations endpoints", () => {
  test("health, ready, policies", async () => {
    const srv = await fakeServer((r) => {
      if (r.url === "/healthz") return { status: 200, body: vectors.healthz };
      if (r.url === "/readyz") return { status: 200, body: vectors.readyz };
      if (r.url === "/v1/policies") return { status: 200, body: vectors.policies };
      return { status: 404, body: { error: { code: "NOT_FOUND", message: "x" } } };
    });
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, token: "tok" });
      assert.deepEqual(await c.health(), { status: "ok" });
      assert.deepEqual(await c.ready(), { ready: true, status: "ready", policies: 2 });
      const ps = await c.policies();
      assert.deepEqual(ps, [
        { name: "saas-analytics", version: vectors.policies.policies[0].version, mode: "enforce" },
      ]);
      // Token only on /v1/*.
      assert.equal(srv.requests[0].headers.authorization, undefined);
      assert.equal(srv.requests[1].headers.authorization, undefined);
      assert.equal(srv.requests[2].headers.authorization, "Bearer tok");
    } finally {
      await srv.close();
    }
  });

  test("readyz 503 resolves ready=false without retrying", async () => {
    const srv = await fakeServer(() => ({ status: 503, body: { status: "not_ready", policies: 0 } }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, ...fast });
      assert.deepEqual(await c.ready(), { ready: false, status: "not_ready", policies: 0 });
      assert.equal(srv.requests.length, 1);
    } finally {
      await srv.close();
    }
  });
});

describe("retry and timeouts", () => {
  const ok = vector("allowed_bound_single_tenant");
  const sql = ok.request.sql;

  test("503 twice then 200 succeeds after 3 attempts", async () => {
    const srv = await fakeServer((_r, n) =>
      n < 3
        ? { status: 503, body: { error: { code: "POLICY_UNAVAILABLE", message: "reloading" } } }
        : { status: 200, body: ok.response },
    );
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, maxRetries: 2, ...fast });
      const v = await c.verify(sql, ok.request.context);
      assert.equal(v.allowed, true);
      assert.equal(srv.requests.length, 3);
    } finally {
      await srv.close();
    }
  });

  test("persistent 503 rejects with the last 503 after maxRetries+1 attempts", async () => {
    const srv = await fakeServer(() => ({
      status: 503,
      body: { error: { code: "AUDIT_UNAVAILABLE", message: "audit sink down" } },
      headers: { "retry-after": "0" },
    }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, maxRetries: 3, ...fast });
      await assert.rejects(c.verify(sql), (e) => e instanceof HaltSQLHttpError && e.status === 503 && e.code === "AUDIT_UNAVAILABLE");
      assert.equal(srv.requests.length, 4);
    } finally {
      await srv.close();
    }
  });

  for (const status of [400, 401, 403, 404, 413, 500]) {
    test(`HTTP ${status} is not retried`, async () => {
      const srv = await fakeServer(() => ({ status, body: { error: { code: "X", message: "m" } } }));
      try {
        const c = new HaltSQLClient({ baseUrl: srv.url, maxRetries: 3, ...fast });
        await assert.rejects(c.verify(sql), (e) => e instanceof HaltSQLHttpError && e.status === status);
        assert.equal(srv.requests.length, 1);
      } finally {
        await srv.close();
      }
    });
  }

  test("timeout is retried, then rejects with HaltSQLTimeoutError", async () => {
    const srv = await fakeServer(() => ({ status: 200, body: ok.response, delayMs: 300 }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, timeoutMs: 50, maxRetries: 1, ...fast });
      await assert.rejects(c.verify(sql, ok.request.context), (e) => e instanceof HaltSQLTimeoutError && e.allowed === false);
      assert.equal(srv.requests.length, 2);
    } finally {
      await srv.close();
    }
  });

  test("connection refused rejects with HaltSQLTransportError", async () => {
    const srv = await fakeServer(() => ({ status: 200, body: {} }));
    const url = srv.url;
    await srv.close();
    const c = new HaltSQLClient({ baseUrl: url, maxRetries: 2, ...fast });
    await assert.rejects(c.verify(sql), HaltSQLTransportError);
  });

  test("dropped connection is retried", async () => {
    const srv = await fakeServer((_r, n) => (n === 1 ? { destroy: true } : { status: 200, body: ok.response }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, maxRetries: 1, ...fast });
      assert.equal((await c.verify(sql, ok.request.context)).allowed, true);
      assert.equal(srv.requests.length, 2);
    } finally {
      await srv.close();
    }
  });

  test("caller abort stops without retrying", async () => {
    const srv = await fakeServer(() => ({ status: 200, body: ok.response, delayMs: 200 }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, maxRetries: 5, ...fast });
      const ac = new AbortController();
      setTimeout(() => ac.abort(), 20);
      await assert.rejects(c.verify(sql, {}, { signal: ac.signal }), HaltSQLTransportError);
      assert.equal(srv.requests.length, 1);
    } finally {
      await srv.close();
    }
  });
});

describe("fail closed on bad responses", () => {
  const ok = vector("allowed_bound_single_tenant");
  const sql = ok.request.sql;
  const cases = {
    "non-JSON 200": "not json",
    "allowed as string": { ...ok.response, allowed: "true" },
    "missing allowed": (() => { const { allowed, ...r } = ok.response; return r; })(),
    "allowed with reasons": { ...ok.response, reasons: [{ code: "E_TABLE_DENIED", message: "m", rule: "r" }] },
    "bad reason code": { ...vector("denied_parse_error").response, reasons: [{ code: "nope", message: "m", rule: "r" }] },
    "bind param 0": { ...ok.response, bind_params: [{ param: 0, value: "acme" }] },
    "bind value number": { ...ok.response, bind_params: [{ param: 1, value: 7 }] },
    "sql hash mismatch": { ...ok.response, sql_sha256: sha("SELECT 2") },
    "missing tables": (() => { const { tables, ...r } = ok.response; return r; })(),
    "array body": [ok.response],
  };
  for (const [name, body] of Object.entries(cases)) {
    test(name, async () => {
      const srv = await fakeServer(() => ({ status: 200, body }));
      try {
        const c = new HaltSQLClient({ baseUrl: srv.url, ...fast });
        await assert.rejects(c.verify(sql, ok.request.context), (e) => e instanceof HaltSQLProtocolError && e.allowed === false);
      } finally {
        await srv.close();
      }
    });
  }

  test("redirect is not followed and is an error", async () => {
    const srv = await fakeServer(() => ({ status: 307, body: "", headers: { location: "http://example.invalid/" } }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, token: "tok" });
      await assert.rejects(c.verify(sql), (e) => e instanceof HaltSQLHttpError && e.status === 307 && e.code === "HTTP_307");
      assert.equal(srv.requests.length, 1);
    } finally {
      await srv.close();
    }
  });

  test("oversized body is rejected", async () => {
    const srv = await fakeServer(() => ({ status: 200, body: { ...ok.response, pad: "x".repeat(5000) } }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, maxResponseBytes: 1024 });
      await assert.rejects(c.verify(sql, ok.request.context), HaltSQLProtocolError);
    } finally {
      await srv.close();
    }
  });

  test("unknown extra fields are ignored", async () => {
    const srv = await fakeServer(() => ({ status: 200, body: { ...ok.response, future_field: { a: 1 } } }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url });
      assert.equal((await c.verify(sql, ok.request.context)).allowed, true);
    } finally {
      await srv.close();
    }
  });

  test("errors never contain the token", async () => {
    const token = "super-secret-token-value";
    const srv = await fakeServer(() => ({ status: 401, body: { error: { code: "UNAUTHORIZED", message: "invalid bearer token" } } }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, token });
      const e = await c.verify(sql).catch((x) => x);
      assert.ok(e instanceof HaltSQLError);
      assert.ok(!String(e.message).includes(token));
      assert.ok(!JSON.stringify(e).includes(token));
      assert.ok(!require_inspect(c).includes(token));
    } finally {
      await srv.close();
    }
  });
});

import { inspect } from "node:util";
function require_inspect(x) {
  return inspect(x, { depth: 5, showHidden: true });
}

describe("input validation", () => {
  test("bad options", () => {
    assert.throws(() => new HaltSQLClient({ baseUrl: "ftp://x" }), HaltSQLUsageError);
    assert.throws(() => new HaltSQLClient({ baseUrl: "not a url" }), HaltSQLUsageError);
    assert.throws(() => new HaltSQLClient({ baseUrl: "http://u:p@h" }), HaltSQLUsageError);
    assert.throws(() => new HaltSQLClient({ baseUrl: "http://h", token: "a\r\nX-Evil: 1" }), HaltSQLUsageError);
    assert.throws(() => new HaltSQLClient({ baseUrl: "http://h", token: "" }), HaltSQLUsageError);
    assert.throws(() => new HaltSQLClient({ baseUrl: "http://h", timeoutMs: 0 }), HaltSQLUsageError);
    assert.throws(() => new HaltSQLClient({ baseUrl: "http://h", headers: { Authorization: "x" } }), HaltSQLUsageError);
  });

  test("bad context values are rejected before sending", async () => {
    const c = new HaltSQLClient({ baseUrl: "http://127.0.0.1:1" });
    for (const ctx of [{ t: 1.5 }, { t: true }, { t: null }, { t: [1, {}] }, { t: 2 ** 60 }, [1]]) {
      await assert.rejects(c.verify("SELECT 1", ctx), HaltSQLUsageError);
    }
    await assert.rejects(c.verify(42), HaltSQLUsageError);
  });
});

describe("bind params", () => {
  const base = vector("allowed_join_two_tenant_params").response;
  test("out of order params are placed by number", () => {
    const v = { ...base, bind_params: [{ param: 2, value: "b" }, { param: 1, value: "a" }] };
    assert.deepEqual(bindParamsToPositional(v), ["a", "b"]);
  });
  test("gap, duplicate and denied all throw", () => {
    assert.throws(() => bindParamsToPositional({ ...base, bind_params: [{ param: 2, value: "b" }] }), HaltSQLUsageError);
    assert.throws(() => bindParamsToPositional({ ...base, bind_params: [{ param: 1, value: "a" }, { param: 1, value: "b" }] }), HaltSQLUsageError);
    assert.throws(() => bindParamsToPositional({ ...base, allowed: false }), HaltSQLUsageError);
  });
  test("array literal escaping", () => {
    assert.equal(toPgArrayLiteral(["a", 'b"c', "d\\e", "", "x,y}"]), '{"a","b\\"c","d\\\\e","","x,y}"}');
  });
});

describe("guardedQuery", () => {
  function fakeDb() {
    const calls = [];
    return { calls, query: async (text, values) => { calls.push({ text, values }); return { rows: [{ ok: 1 }] }; } };
  }

  test("allowed: runs the exact SQL with positional params", async () => {
    const v = vector("allowed_set_valued_tenant");
    const srv = await fakeServer(replay(v));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, token: v.token });
      const db = fakeDb();
      const seen = [];
      const { result, verdict } = await guardedQuery(c, db, v.request.sql, v.request.context, { onVerdict: (x) => seen.push(x) });
      assert.deepEqual(result.rows, [{ ok: 1 }]);
      assert.equal(verdict.allowed, true);
      assert.equal(seen.length, 1);
      assert.deepEqual(db.calls, [{ text: v.request.sql, values: [["acme", "acme-eu", "acme-us"]] }]);
    } finally {
      await srv.close();
    }
  });

  test("denied: throws HaltSQLDeniedError and never touches the database", async () => {
    const v = vector("denied_column_and_tenant");
    const srv = await fakeServer(replay(v));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, token: v.token });
      const db = fakeDb();
      const e = await guardedQuery(c, db, v.request.sql, v.request.context).catch((x) => x);
      assert.ok(e instanceof HaltSQLDeniedError);
      assert.deepEqual(e.codes, ["E_COLUMN_DENIED", "E_TENANT_MISSING"]);
      assert.equal(db.calls.length, 0);
    } finally {
      await srv.close();
    }
  });

  test("sidecar error: throws and never touches the database", async () => {
    const srv = await fakeServer(() => ({ status: 500, body: { error: { code: "INTERNAL", message: "boom" } } }));
    try {
      const c = new HaltSQLClient({ baseUrl: srv.url, maxRetries: 0 });
      const db = fakeDb();
      await assert.rejects(guardedQuery(c, db, "SELECT 1", {}), HaltSQLHttpError);
      assert.equal(db.calls.length, 0);
    } finally {
      await srv.close();
    }
  });
});
