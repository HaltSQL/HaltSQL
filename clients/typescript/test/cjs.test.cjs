// The CommonJS build loads with require() and exposes the same API.
const { test } = require("node:test");
const assert = require("node:assert/strict");

test("CommonJS build", () => {
  const m = require("../dist/cjs/index.js");
  assert.equal(typeof m.HaltSQLClient, "function");
  assert.equal(typeof m.guardedQuery, "function");
  assert.equal(typeof m.bindParamsToPositional, "function");
  assert.equal(m.VERSION, "0.1.0");
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
