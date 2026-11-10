// The CommonJS build loads with require() and exposes the same API.
const { test } = require("node:test");
const assert = require("node:assert/strict");

test("CommonJS build", () => {
  const m = require("../dist/cjs/index.js");
  assert.equal(typeof m.HaltSQLClient, "function");
  assert.equal(typeof m.guardedQuery, "function");
  assert.equal(typeof m.guardedTransaction, "function");
  assert.equal(typeof m.guardedTransactionOnClient, "function");
  assert.equal(typeof m.searchPathSetting, "function");
  assert.equal(typeof m.bindParamsToPositional, "function");
  assert.equal(m.VERSION, "0.0.3");
  const e = new m.HaltSQLTimeoutError(5);
  assert.ok(e instanceof m.HaltSQLError);
  assert.equal(e.allowed, false);
  assert.equal(e.kind, "timeout");
});

test("package exports resolve both conditions", () => {
  const pkg = require("../package.json");
  assert.equal(pkg.exports["."].require.default, "./dist/cjs/index.js");
  assert.equal(pkg.exports["."].import.default, "./dist/esm/index.js");
  assert.deepEqual(Object.keys(pkg.dependencies ?? {}), []);
});

test("CommonJS build: LocalVerifier and binary resolution (no import.meta in CJS)", () => {
  const m = require("../dist/cjs/index.js");
  assert.equal(typeof m.LocalVerifier, "function");
  assert.equal(typeof m.resolveLocalBinary, "function");
  const src = require("node:fs").readFileSync(require.resolve("../dist/cjs/meta.js"), "utf8");
  assert.ok(!src.includes("import.meta"));
  assert.equal(require("../dist/cjs/meta.js").moduleUrl, require("node:url").pathToFileURL(require.resolve("../dist/cjs/meta.js")).href);
  // Resolution from this module's location runs without throwing a SyntaxError/TypeError:
  // it finds @haltsql/native-linux-x64 where npm installed it (a linux-x64 machine), or
  // reports that package as missing.
  let resolved;
  try {
    resolved = m.resolveLocalBinary({ platform: "linux", arch: "x64", env: { PATH: "" } });
  } catch (e) {
    assert.ok(e instanceof m.HaltSQLUsageError, `unexpected ${e && e.name}: ${e && e.message}`);
    assert.match(e.message, /@haltsql\/native-linux-x64/);
  }
  if (resolved !== undefined) {
    assert.match(JSON.stringify(resolved), /@haltsql[\\/]+native-linux-x64/);
  }
});
