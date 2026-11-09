// LocalVerifier against the real haltsql engine (bundled-binary mode) and
// against fake engines that misbehave. The real-engine tests need the CLI:
// HALTSQL_BIN, or <repo>/_build/default/bin/haltsql/main.exe
// (`opam exec -- dune build ./bin/haltsql/main.exe`). They skip when it is
// missing unless HALTSQL_REQUIRE_NATIVE=1.
import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { cpus, loadavg, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  LocalVerifier,
  NATIVE_PLATFORMS,
  nativePackageName,
  resolveLocalBinary,
  HaltSQLError,
  HaltSQLDeniedError,
  HaltSQLProtocolError,
  HaltSQLTimeoutError,
  HaltSQLTransportError,
  HaltSQLUsageError,
  guardedQuery,
} from "../dist/esm/index.js";
import { vectors as serverVectors } from "./helpers.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const repo = resolve(here, "../../..");
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");

const BIN = process.env.HALTSQL_BIN || join(repo, "_build/default/bin/haltsql/main.exe");
const HAVE_BIN = existsSync(BIN);
const REQUIRE = process.env.HALTSQL_REQUIRE_NATIVE === "1";
const SKIP = HAVE_BIN
  ? false
  : `haltsql CLI not found at ${BIN} (build it with \`opam exec -- dune build ./bin/haltsql/main.exe\` or set HALTSQL_BIN)`;
if (!HAVE_BIN && REQUIRE) {
  test("HALTSQL_REQUIRE_NATIVE=1 needs the haltsql CLI", () => assert.fail(SKIP));
}

const SAAS = join(repo, "test/fixtures/policies/saas.yaml");
const SAAS_JSON = join(repo, "test/fixtures/policies/saas.json");
const OK_SQL = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5";
const DENY_SQL = "SELECT id FROM orders LIMIT 5";
// The fixtures reference their catalog snapshot relative to the policy file;
// an in-memory policy needs an absolute path (it is written to a temp dir).
const CATALOG = join(repo, "test/fixtures/catalogs/saas.json");
const inMemory = (file) => readFileSync(file, "utf8").replace("../catalogs/saas.json", CATALOG);

const scratch = realpathSync(mkdtempSync(join(tmpdir(), "haltsql-local-test-")));
after(() => rmSync(scratch, { recursive: true, force: true }));

/** Writes an executable fake engine (a Node.js script) and returns its path. */
let fakeN = 0;
function fakeEngine(body) {
  const p = join(scratch, `fake-${++fakeN}.mjs`);
  writeFileSync(
    p,
    `#!${process.execPath}
import { createHash } from "node:crypto";
import { createInterface } from "node:readline";
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const verdict = (req, extra = {}) => ({
  id: req.id, allowed: false,
  reasons: [{ code: "E_FAKE", message: "fake é😀 中文", rule: "fake" }],
  shadow_reasons: [], policy: { name: "fake", version: "sha256:0" }, statement_kind: null,
  tables: [], columns: [], bind_params: [], fingerprint: null, sql_sha256: sha(req.sql),
  elapsed_us: 1, ...extra,
});
const lines = createInterface({ input: process.stdin });
${body}
`,
  );
  chmodSync(p, 0o755);
  return p;
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitDead(pid, ms = 3000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (!alive(pid)) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return !alive(pid);
}

/** Field path from a vector's `compare` list, e.g. `reasons[].code`. */
function pick(obj, path) {
  const m = /^(\w+)\[\]\.(\w+)$/.exec(path);
  if (m) return obj[m[1]].map((x) => x[m[2]]);
  return path.split(".").reduce((o, k) => (o == null ? o : o[k]), obj);
}

const isDeny = (e) => e instanceof HaltSQLError && e.allowed === false;

describe("binary resolution", () => {
  const exe = (p) => {
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, "#!/bin/sh\nexit 0\n");
    chmodSync(p, 0o755);
    return p;
  };
  const root = join(scratch, "resolve");
  const optBin = exe(join(root, "opt/haltsql"));
  const envBin = exe(join(root, "env/haltsql"));
  const pathDir = join(root, "pathdir");
  const pathBin = exe(join(pathDir, "haltsql"));
  const proj = join(root, "proj");
  const pkgDir = join(proj, "node_modules/@haltsql/native-linux-arm64");
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(join(pkgDir, "package.json"), JSON.stringify({ name: "@haltsql/native-linux-arm64", version: "0.1.0" }));
  const pkgBin = exe(join(pkgDir, "bin/haltsql"));
  const empty = join(root, "empty");
  mkdirSync(empty, { recursive: true });
  const base = { platform: "linux", arch: "arm64", resolveFrom: proj };

  test("explicit binary beats HALTSQL_BIN, the package and PATH", () => {
    const r = resolveLocalBinary({ ...base, binary: optBin, env: { HALTSQL_BIN: envBin, PATH: pathDir } });
    assert.deepEqual(r, { path: optBin, source: "option" });
  });
  test("HALTSQL_BIN beats the package and PATH", () => {
    const r = resolveLocalBinary({ ...base, env: { HALTSQL_BIN: envBin, PATH: pathDir } });
    assert.deepEqual(r, { path: envBin, source: "env" });
  });
  test("the platform package beats PATH", () => {
    const r = resolveLocalBinary({ ...base, env: { PATH: pathDir } });
    assert.deepEqual(r, { path: pkgBin, source: "package" });
  });
  test("resolveFrom also accepts a file URL", () => {
    const r = resolveLocalBinary({ ...base, resolveFrom: new URL(`file://${proj}/index.js`).href, env: {} });
    assert.equal(r.source, "package");
  });
  test("PATH is the last resort; relative PATH entries are ignored", () => {
    const r = resolveLocalBinary({ ...base, resolveFrom: empty, env: { PATH: `relative/dir:${pathDir}` } });
    assert.deepEqual(r, { path: pathBin, source: "path" });
  });
  test("an unsupported platform skips the package step", () => {
    const r = resolveLocalBinary({ platform: "linux", arch: "riscv64", resolveFrom: proj, env: { PATH: pathDir } });
    assert.equal(r.source, "path");
  });
  test("nothing found names the expected platform package", () => {
    assert.throws(
      () => resolveLocalBinary({ platform: "linux", arch: "x64", resolveFrom: empty, env: { PATH: "" } }),
      (e) => e instanceof HaltSQLUsageError && /@haltsql\/native-linux-x64/.test(e.message) && /HALTSQL_BIN/.test(e.message),
    );
    assert.throws(
      () => resolveLocalBinary({ platform: "freebsd", arch: "x64", resolveFrom: empty, env: { PATH: "" } }),
      (e) => e instanceof HaltSQLUsageError && /no prebuilt engine for freebsd-x64/.test(e.message),
    );
  });
  test("an explicit choice that is not executable is an error, not a fallback", () => {
    const notExec = join(root, "plain");
    writeFileSync(notExec, "x");
    chmodSync(notExec, 0o644);
    assert.throws(() => resolveLocalBinary({ ...base, binary: notExec, env: {} }), HaltSQLUsageError);
    assert.throws(() => resolveLocalBinary({ ...base, binary: join(root, "missing"), env: {} }), HaltSQLUsageError);
    assert.throws(() => resolveLocalBinary({ ...base, env: { HALTSQL_BIN: notExec, PATH: pathDir } }), /HALTSQL_BIN/);
    assert.throws(() => resolveLocalBinary({ ...base, env: { HALTSQL_BIN: root } }), HaltSQLUsageError); // a directory
  });
  test("an installed package without an executable binary is an error", () => {
    const broken = join(root, "broken");
    const d = join(broken, "node_modules/@haltsql/native-darwin-arm64");
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "package.json"), "{}");
    assert.throws(
      () => resolveLocalBinary({ platform: "darwin", arch: "arm64", resolveFrom: broken, env: { PATH: pathDir } }),
      (e) => e instanceof HaltSQLUsageError && /reinstall/.test(e.message),
    );
  });
  test("package names", () => {
    assert.deepEqual([...NATIVE_PLATFORMS], ["linux-x64", "linux-arm64", "darwin-arm64"]);
    assert.equal(nativePackageName("linux", "x64"), "@haltsql/native-linux-x64");
    assert.equal(nativePackageName(), `@haltsql/native-${process.platform}-${process.arch}`);
  });
});

describe("options", () => {
  const fake = fakeEngine(`lines.on("line", () => {});`);
  test("exactly one of policyFile / policy", () => {
    assert.throws(() => new LocalVerifier({ binary: fake }), HaltSQLUsageError);
    assert.throws(() => new LocalVerifier({ binary: fake, policyFile: "a.yaml", policy: "x: 1" }), HaltSQLUsageError);
    assert.throws(() => new LocalVerifier({ binary: fake, policy: "  " }), HaltSQLUsageError);
    assert.throws(() => new LocalVerifier({ binary: fake, policyFile: "a.yaml", policyFormat: "json" }), HaltSQLUsageError);
    assert.throws(() => new LocalVerifier({ binary: fake, policy: "x", policyFormat: "toml" }), HaltSQLUsageError);
  });
  test("timeoutMs must be a positive integer", () => {
    assert.throws(() => new LocalVerifier({ binary: fake, policyFile: "a.yaml", timeoutMs: 0 }), HaltSQLUsageError);
    assert.throws(() => new LocalVerifier({ binary: fake, policyFile: "a.yaml", timeoutMs: 1.5 }), HaltSQLUsageError);
  });
  test("nothing is spawned until first use", async () => {
    const v = new LocalVerifier({ binary: fake, policyFile: "a.yaml" });
    assert.equal(v.pid, undefined);
    assert.equal(v.binarySource, "option");
    await v.close();
  });
});

describe("fake engines (fail closed)", () => {
  test("timeout: an engine that never answers rejects within the bound and is killed", async () => {
    const bin = fakeEngine(`lines.on("line", () => {}); setInterval(() => {}, 1e6);`);
    const v = new LocalVerifier({ binary: bin, policyFile: "p.yaml", timeoutMs: 300 });
    const t0 = Date.now();
    const p1 = v.verify("SELECT 1");
    const pid = v.pid;
    const p2 = v.verify("SELECT 2");
    await assert.rejects(p1, (e) => e instanceof HaltSQLTimeoutError && e.allowed === false);
    await assert.rejects(p2, (e) => e instanceof HaltSQLTransportError);
    const took = Date.now() - t0;
    assert.ok(took >= 290 && took < 2000, `timeout took ${took} ms`);
    assert.ok(await waitDead(pid), "engine was not killed");
    await v.close();
  });

  test("garbage output rejects everything pending and kills the engine", async () => {
    const bin = fakeEngine(`lines.on("line", () => process.stdout.write("not json\\n"));`);
    const v = new LocalVerifier({ binary: bin, policyFile: "p.yaml" });
    const ps = [v.verify("SELECT 1"), v.verify("SELECT 2"), v.verify("SELECT 3")];
    const pid = v.pid;
    const rs = await Promise.allSettled(ps);
    assert.ok(rs.every((r) => r.status === "rejected" && r.reason instanceof HaltSQLProtocolError), JSON.stringify(rs));
    assert.match(rs[0].reason.message, /non-JSON/);
    assert.ok(await waitDead(pid));
    await v.close();
  });

  test("an answer with the wrong id rejects everything pending", async () => {
    const bin = fakeEngine(
      `lines.on("line", (l) => { const r = JSON.parse(l); process.stdout.write(JSON.stringify(verdict({ ...r, id: r.id + 1 })) + "\\n"); });`,
    );
    const v = new LocalVerifier({ binary: bin, policyFile: "p.yaml" });
    const rs = await Promise.allSettled([v.verify("SELECT 1"), v.verify("SELECT 2")]);
    assert.ok(rs.every((r) => r.status === "rejected" && r.reason instanceof HaltSQLProtocolError));
    assert.match(rs[0].reason.message, /answered id 2 while 1 was expected/);
    await v.close();
  });

  test("a verdict for different SQL (sql_sha256 mismatch) is rejected", async () => {
    const bin = fakeEngine(
      `lines.on("line", (l) => { const r = JSON.parse(l); process.stdout.write(JSON.stringify(verdict(r, { allowed: true, reasons: [], sql_sha256: sha("other") })) + "\\n"); });`,
    );
    const v = new LocalVerifier({ binary: bin, policyFile: "p.yaml" });
    await assert.rejects(v.verify("SELECT 1"), (e) => e instanceof HaltSQLProtocolError && /sql_sha256/.test(e.message));
    await v.close();
    const lax = new LocalVerifier({ binary: bin, policyFile: "p.yaml", verifySqlHash: false });
    assert.equal((await lax.verify("SELECT 1")).allowed, true);
    await lax.close();
  });

  test("an invalid verdict (allowed with reasons) is rejected", async () => {
    const bin = fakeEngine(
      `lines.on("line", (l) => process.stdout.write(JSON.stringify(verdict(JSON.parse(l), { allowed: true })) + "\\n"));`,
    );
    const v = new LocalVerifier({ binary: bin, policyFile: "p.yaml" });
    await assert.rejects(v.verify("SELECT 1"), HaltSQLProtocolError);
    await v.close();
  });

  test("an engine error line fails only that request", async () => {
    const bin = fakeEngine(
      `let n = 0; lines.on("line", (l) => { const r = JSON.parse(l); process.stdout.write(JSON.stringify(n++ === 0 ? { id: r.id, error: "bad request" } : verdict(r)) + "\\n"); });`,
    );
    const v = new LocalVerifier({ binary: bin, policyFile: "p.yaml" });
    await assert.rejects(v.verify("SELECT 1"), (e) => e instanceof HaltSQLProtocolError && /bad request/.test(e.message));
    const pid = v.pid;
    const ok = await v.verify("SELECT 2");
    assert.equal(ok.allowed, false);
    assert.equal(v.pid, pid, "engine should keep running");
    await v.close();
  });

  test("answers split into 1-byte chunks (multi-byte UTF-8 across chunks) parse correctly", async () => {
    const bin = fakeEngine(`
      const q = [];
      let busy = false;
      async function drain() {
        if (busy) return; busy = true;
        while (q.length) {
          const buf = Buffer.from(JSON.stringify(verdict(q.shift())) + "\\n", "utf8");
          for (const b of buf) await new Promise((r) => process.stdout.write(Buffer.from([b]), r));
        }
        busy = false;
      }
      lines.on("line", (l) => { q.push(JSON.parse(l)); drain(); });`);
    const v = new LocalVerifier({ binary: bin, policyFile: "p.yaml" });
    const sqls = ["SELECT 'é'", "SELECT '😀'", "SELECT '中文'"];
    const out = await Promise.all(sqls.map((s) => v.verify(s)));
    for (const [i, o] of out.entries()) {
      assert.equal(o.reasons[0].message, "fake é😀 中文");
      assert.equal(o.sql_sha256, sha(sqls[i]));
    }
    await v.close();
  });

  test("an engine that dies mid-request rejects pending; the next call respawns", async () => {
    const marker = join(scratch, "died-once");
    const bin = fakeEngine(`
      import { existsSync, writeFileSync } from "node:fs";
      const first = !existsSync(${JSON.stringify(marker)});
      lines.on("line", (l) => {
        if (first) { writeFileSync(${JSON.stringify(marker)}, ""); process.stderr.write("boom\\n"); process.exit(3); }
        process.stdout.write(JSON.stringify(verdict(JSON.parse(l))) + "\\n");
      });`);
    const v = new LocalVerifier({ binary: bin, policyFile: "p.yaml" });
    const rs = await Promise.allSettled([v.verify("SELECT 1"), v.verify("SELECT 2")]);
    for (const r of rs) {
      assert.equal(r.status, "rejected");
      assert.ok(r.reason instanceof HaltSQLTransportError);
      assert.match(r.reason.message, /exited with code 3: boom/);
    }
    const ok = await v.verify("SELECT 3");
    assert.equal(ok.sql_sha256, sha("SELECT 3"));
    await v.close();
  });

  test("close(): pending rejected, idempotent, process gone, later calls rejected", async () => {
    const bin = fakeEngine(`lines.on("line", () => {}); setInterval(() => {}, 1e6);`);
    const v = new LocalVerifier({ binary: bin, policyFile: "p.yaml" });
    const p = v.verify("SELECT 1");
    const pid = v.pid;
    const c1 = v.close();
    const c2 = v.close();
    assert.equal(c1, c2);
    await assert.rejects(p, (e) => e instanceof HaltSQLTransportError && /closed/.test(e.message));
    await c1;
    assert.ok(await waitDead(pid));
    assert.equal(v.closed, true);
    await assert.rejects(v.verify("SELECT 1"), (e) => e instanceof HaltSQLUsageError && /closed/.test(e.message));
    await v.close();
  });

  test("a binary that cannot run rejects with a clear error", async () => {
    const bad = join(scratch, "badbin");
    writeFileSync(bad, "#!/nonexistent/interpreter\n");
    chmodSync(bad, 0o755);
    const v = new LocalVerifier({ binary: bad, policyFile: "p.yaml" });
    await assert.rejects(v.verify("SELECT 1"), (e) => isDeny(e) && /haltsql engine/.test(e.message));
    await v.close();
  });
});

describe("real engine", { skip: SKIP }, () => {
  test("conformance vectors (clients/testvectors/cases)", async () => {
    const dir = join(repo, "clients/testvectors/cases");
    const cases = readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")));
    assert.ok(cases.length >= 20, `only ${cases.length} cases`);
    const verifiers = new Map();
    try {
      for (const c of cases) {
        let v = verifiers.get(c.policy_file);
        if (!v) {
          v = await LocalVerifier.create({ binary: BIN, policyFile: join(repo, c.policy_file) });
          verifiers.set(c.policy_file, v);
        }
        const got = await v.verify(c.request.sql, c.request.context);
        for (const f of c.compare) assert.deepEqual(pick(got, f), pick(c.verdict, f), `${c.name}: ${f}`);
        assert.equal(got.sql_sha256, sha(c.request.sql), c.name);
      }
    } finally {
      await Promise.all([...verifiers.values()].map((v) => v.close()));
    }
  });

  test("recorded sidecar vectors (testdata/vectors.json) give the same verdicts locally", async () => {
    const files = {
      "saas-analytics": join(repo, "examples/policies/saas.yaml"),
      "org-rollup-reports": join(repo, "examples/policies/hierarchical.yaml"),
    };
    const verifiers = {};
    try {
      let n = 0;
      for (const vec of serverVectors.vectors) {
        if (vec.status !== 200) continue; // HTTP-level errors have no local equivalent
        const name = vec.response.policy.name;
        verifiers[name] ??= await LocalVerifier.create({ binary: BIN, policyFile: files[name] });
        const got = await verifiers[name].verify(vec.request.sql, vec.request.context);
        assert.equal(got.allowed, vec.expect.allowed, vec.name);
        assert.deepEqual(got.reasons.map((r) => r.code), vec.expect.codes, vec.name);
        for (const f of ["policy", "statement_kind", "tables", "columns", "bind_params", "fingerprint", "sql_sha256"]) {
          assert.deepEqual(got[f], vec.response[f], `${vec.name}: ${f}`);
        }
        n++;
      }
      assert.ok(n >= 10);
    } finally {
      await Promise.all(Object.values(verifiers).map((v) => v.close()));
    }
  });

  const tempPolicyDirs = () => new Set(readdirSync(tmpdir()).filter((d) => d.startsWith("haltsql-policy-")));

  test("in-memory YAML policy: private temp file, removed on close", async () => {
    const before = tempPolicyDirs();
    const v = await LocalVerifier.create({ binary: BIN, policy: inMemory(SAAS) });
    const created = [...tempPolicyDirs()].filter((d) => !before.has(d));
    assert.equal(created.length, 1);
    const dir = join(tmpdir(), created[0]);
    assert.equal(statSync(dir).mode & 0o777, 0o700);
    assert.equal(statSync(join(dir, "policy.yaml")).mode & 0o777, 0o600);
    const got = await v.verify(OK_SQL, { tenant_id: "acme" });
    assert.equal(got.allowed, true);
    assert.equal(got.policy.name, "saas");
    await v.close();
    assert.equal(existsSync(dir), false, "temp policy dir not removed");
  });

  test("in-memory JSON policy (format detected, and explicit)", async () => {
    const text = inMemory(SAAS_JSON);
    for (const opts of [{ policy: text }, { policy: text, policyFormat: "json" }]) {
      const v = await LocalVerifier.create({ binary: BIN, ...opts });
      assert.equal((await v.verify(OK_SQL, { tenant_id: "acme" })).allowed, true);
      assert.equal((await v.verify(DENY_SQL, { tenant_id: "acme" })).allowed, false);
      await v.close();
    }
  });

  test("an invalid policy fails create() with the engine's message", async () => {
    const before = tempPolicyDirs();
    await assert.rejects(
      LocalVerifier.create({ binary: BIN, policy: "apiVersion: [\n" }),
      (e) => e instanceof HaltSQLUsageError && /failed to start/.test(e.message) && /cannot load policy/.test(e.message),
    );
    assert.deepEqual(tempPolicyDirs(), before, "temp policy dir leaked");
    await assert.rejects(
      LocalVerifier.create({ binary: BIN, policyFile: join(scratch, "missing.yaml") }),
      (e) => e instanceof HaltSQLUsageError && /missing\.yaml/.test(e.message),
    );
    // Lazily, the same error comes from verify().
    const v = new LocalVerifier({ binary: BIN, policy: "{ not json" , policyFormat: "json" });
    await assert.rejects(v.verify("SELECT 1"), (e) => e instanceof HaltSQLUsageError && /cannot load policy/.test(e.message));
    await v.close();
  });

  describe("with one verifier", () => {
    let v;
    test("create", async () => {
      v = await LocalVerifier.create({ binary: BIN, policyFile: SAAS });
      assert.equal(typeof v.pid, "number");
      assert.equal(v.binary, resolve(BIN));
    });

    test("1000 concurrent verifies resolve correctly and in order", async () => {
      const n = 1000;
      const reqs = Array.from({ length: n }, (_, i) =>
        i % 3 === 2 ? { sql: `${DENY_SQL} -- ${i}`, ctx: { tenant_id: `t${i}` } } : { sql: `${OK_SQL} -- ${i}`, ctx: { tenant_id: `t${i}` } },
      );
      const order = [];
      const out = await Promise.all(
        reqs.map((r, i) =>
          v.verify(r.sql, r.ctx).then((verdict) => {
            order.push(i);
            return verdict;
          }),
        ),
      );
      assert.deepEqual(order, [...order].sort((a, b) => a - b), "resolved out of order");
      for (const [i, got] of out.entries()) {
        assert.equal(got.sql_sha256, sha(reqs[i].sql));
        if (i % 3 === 2) assert.equal(got.allowed, false);
        else assert.deepEqual(got.bind_params, [{ param: 1, value: `t${i}` }]);
      }
    });

    test("verifyMany: strings with a shared context, objects with their own", async () => {
      const out = await v.verifyMany([OK_SQL, { sql: OK_SQL, context: { tenant_id: "other" } }, DENY_SQL], { tenant_id: "acme" });
      assert.deepEqual(out.map((x) => x.allowed), [true, true, false]);
      assert.equal(out[0].bind_params[0].value, "acme");
      assert.equal(out[1].bind_params[0].value, "other");
      assert.deepEqual(await v.verifyMany([]), []);
      await assert.rejects(v.verifyMany([OK_SQL, { sql: OK_SQL, context: { tenant_id: 1.5 } }]), HaltSQLUsageError);
      await assert.rejects(v.verifyMany([OK_SQL, 7]), HaltSQLUsageError);
    });

    test("check() resolves an allow and throws HaltSQLDeniedError on deny", async () => {
      assert.equal((await v.check(OK_SQL, { tenant_id: "acme" })).allowed, true);
      await assert.rejects(v.check(DENY_SQL, { tenant_id: "acme" }), (e) => {
        assert.ok(e instanceof HaltSQLDeniedError);
        assert.equal(e.allowed, false);
        assert.ok(e.codes.length > 0);
        return true;
      });
    });

    test("NUL bytes, unicode and newlines in SQL: hash covers the full string", async () => {
      const nul = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5\u0000; DROP TABLE orders";
      const g1 = await v.verify(nul, { tenant_id: "acme" });
      assert.equal(g1.allowed, false);
      assert.deepEqual(g1.reasons.map((r) => r.code), ["E_PARSE"]);
      assert.equal(g1.sql_sha256, sha(nul));
      const uni = "SELECT id FROM orders WHERE tenant_id = $1 AND status = 'é😀中文 ' LIMIT 5";
      const g2 = await v.verify(uni, { tenant_id: "ünï😀" });
      assert.equal(g2.allowed, true);
      assert.equal(g2.sql_sha256, sha(uni));
      assert.deepEqual(g2.bind_params, [{ param: 1, value: "ünï😀" }]);
      const nl = "SELECT id\nFROM orders\r\nWHERE tenant_id = $1\nLIMIT 5";
      const g3 = await v.verify(nl, { tenant_id: "acme" });
      assert.equal(g3.allowed, true);
      assert.equal(g3.sql_sha256, sha(nl));
      await assert.rejects(v.verify("SELECT '\ud800'", {}), (e) => e instanceof HaltSQLUsageError && /surrogate/.test(e.message));
    });

    test("oversized SQL is denied (E_LIMIT) without breaking the stream", async () => {
      const big = `SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5 -- ${"x".repeat(1 << 20)}`;
      const got = await v.verify(big, { tenant_id: "acme" });
      assert.equal(got.allowed, false);
      assert.deepEqual(got.reasons.map((r) => r.code), ["E_LIMIT"]);
      assert.equal(got.sql_sha256, sha(big));
      assert.equal((await v.verify(OK_SQL, { tenant_id: "acme" })).allowed, true);
    });

    test("invalid context is rejected before anything is sent", async () => {
      for (const ctx of [{ tenant_id: {} }, { tenant_id: 1.5 }, { tenant_id: [null] }, [], "acme", { tenant_id: NaN }]) {
        await assert.rejects(v.verify(OK_SQL, ctx), HaltSQLUsageError, JSON.stringify(ctx));
      }
      await assert.rejects(v.verify(42), HaltSQLUsageError);
      const fresh = new LocalVerifier({ binary: BIN, policyFile: SAAS });
      await assert.rejects(fresh.verify(OK_SQL, { tenant_id: true }), HaltSQLUsageError);
      assert.equal(fresh.pid, undefined, "an invalid request must not start the engine");
      await fresh.close();
    });

    test("crash resilience: killing the engine rejects pending; the next call respawns", async () => {
      const pid = v.pid;
      const ps = Array.from({ length: 2000 }, (_, i) => v.verify(`${OK_SQL} -- ${i}`, { tenant_id: "acme" }));
      process.kill(pid, "SIGKILL");
      const rs = await Promise.allSettled(ps);
      const rejected = rs.filter((r) => r.status === "rejected");
      assert.ok(rejected.length > 0, "nothing was pending when the engine died");
      for (const r of rejected) {
        assert.ok(r.reason instanceof HaltSQLTransportError, String(r.reason));
        assert.match(r.reason.message, /killed by SIGKILL|exited/);
      }
      for (const [i, r] of rs.entries()) if (r.status === "fulfilled") assert.equal(r.value.sql_sha256, sha(`${OK_SQL} -- ${i}`));
      assert.ok(await waitDead(pid));
      const ok = await v.verify(OK_SQL, { tenant_id: "acme" });
      assert.equal(ok.allowed, true);
      assert.notEqual(v.pid, pid);
    });

    test("warm latency: < 1 ms per sequential verify", async (t) => {
      for (let i = 0; i < 200; i++) await v.verify(OK_SQL, { tenant_id: "acme" });
      // Best of several batches, so a burst of load from other processes on a
      // shared CI machine does not decide the result (~2000 calls in total).
      const batches = [];
      for (let b = 0; b < 5; b++) {
        const n = 400;
        const t0 = process.hrtime.bigint();
        for (let i = 0; i < n; i++) await v.verify(OK_SQL, { tenant_id: "acme" });
        batches.push(Number(process.hrtime.bigint() - t0) / 1e6 / n);
      }
      const best = Math.min(...batches);
      const load = loadavg()[0];
      t.diagnostic(
        `warm sequential verify: best ${(best * 1000).toFixed(1)} us/call; batches ${batches.map((x) => (x * 1000).toFixed(0)).join(", ")} us; load ${load.toFixed(1)} on ${cpus().length} CPUs`,
      );
      if (best >= 1 && load > 2 * cpus().length && process.env.HALTSQL_STRICT_LATENCY !== "1") {
        t.diagnostic("machine overloaded: latency not asserted (set HALTSQL_STRICT_LATENCY=1 to enforce)");
        return;
      }
      assert.ok(best < 1, `best batch average ${best.toFixed(3)} ms`);
    });

    test("guardedQuery works with a LocalVerifier", async () => {
      const calls = [];
      const db = { query: async (text, values) => (calls.push({ text, values }), { rows: [] }) };
      const { verdict } = await guardedQuery(v, db, OK_SQL, { tenant_id: "acme" });
      assert.equal(verdict.allowed, true);
      assert.deepEqual(calls, [{ text: OK_SQL, values: ["acme"] }]);
      await assert.rejects(guardedQuery(v, db, DENY_SQL, { tenant_id: "acme" }), HaltSQLDeniedError);
      assert.equal(calls.length, 1);
    });

    test("Symbol.asyncDispose closes", async () => {
      const pid = v.pid;
      await v[Symbol.asyncDispose]();
      assert.equal(v.closed, true);
      assert.ok(await waitDead(pid));
    });
  });

  test("an idle verifier that is never closed does not keep the process alive", async () => {
    const script = `
      import { LocalVerifier } from ${JSON.stringify(new URL("../dist/esm/index.js", import.meta.url).href)};
      const v = new LocalVerifier({ binary: ${JSON.stringify(BIN)}, policy: ${JSON.stringify(inMemory(SAAS))} });
      const r = await v.verify(${JSON.stringify(OK_SQL)}, { tenant_id: "acme" });
      console.log(JSON.stringify({ allowed: r.allowed, pid: v.pid }));
    `;
    const before = tempPolicyDirs();
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: ["ignore", "pipe", "inherit"] });
    let out = "";
    child.stdout.on("data", (c) => (out += c));
    const code = await new Promise((ok, fail) => {
      const t = setTimeout(() => {
        child.kill("SIGKILL");
        fail(new Error("child process did not exit on its own within 5 s"));
      }, 5000);
      child.on("exit", (c) => {
        clearTimeout(t);
        ok(c);
      });
    });
    assert.equal(code, 0);
    const res = JSON.parse(out);
    assert.equal(res.allowed, true);
    assert.ok(await waitDead(res.pid), "engine outlived its parent");
    assert.deepEqual(tempPolicyDirs(), before, "temp policy dir not removed at exit");
  });
});
