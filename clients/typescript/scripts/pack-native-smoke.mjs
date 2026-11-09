#!/usr/bin/env node
// End-to-end check of the npm packaging: builds the platform package for this
// machine from the compiled engine, `npm pack`s it and @haltsql/client,
// installs both tarballs into a fresh project (offline), and runs an ESM and a
// CommonJS script there that create a LocalVerifier with NO binary option and
// NO HALTSQL_BIN, so the engine must come from node_modules/@haltsql/native-*.
//
// Usage (from clients/typescript, after `npm run build` and building the engine):
//   node scripts/pack-native-smoke.mjs [--binary PATH] [--lib PATH] [--allow-nonsystem-deps] [--keep]
// Defaults: <repo>/_build/default/bin/haltsql/main.exe and
// <repo>/_build/default/native/libhaltsql.so. CI runs this per platform.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const repo = resolve(tsRoot, "../..");
const { values } = parseArgs({
  options: {
    binary: { type: "string", default: join(repo, "_build/default/bin/haltsql/main.exe") },
    lib: { type: "string", default: join(repo, "_build/default/native/libhaltsql.so") },
    "allow-nonsystem-deps": { type: "boolean", default: false },
    keep: { type: "boolean", default: false },
  },
});

const platform = `${process.platform}-${process.arch}`;
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

function run(cmd, args, opts = {}) {
  console.log(`$ ${cmd} ${args.join(" ")}${opts.cwd ? `   (in ${opts.cwd})` : ""}`);
  const r = spawnSync(cmd, args, { stdio: ["ignore", "pipe", "inherit"], encoding: "utf8", ...opts });
  if (r.status !== 0) {
    if (r.stdout) process.stdout.write(r.stdout);
    throw new Error(`${cmd} ${args.join(" ")} failed (${r.error?.message ?? `exit ${r.status}`})`);
  }
  return r.stdout;
}

if (!existsSync(join(tsRoot, "dist/esm/index.js")) || !existsSync(join(tsRoot, "dist/cjs/index.js"))) {
  throw new Error("dist/ is missing: run `npm run build` first");
}
for (const p of [values.binary, values.lib]) if (!existsSync(p)) throw new Error(`${p} not found; build the engine first`);

const work = realpathSync(mkdtempSync(join(tmpdir(), "haltsql-pack-smoke-")));
let ok = false;
try {
  // 1. The platform package.
  const nativeDir = join(work, "native");
  const buildArgs = [
    join(here, "build-native-package.mjs"),
    "--platform", platform,
    "--binary", values.binary,
    "--lib", values.lib,
    "--out", nativeDir,
  ];
  if (values["allow-nonsystem-deps"]) buildArgs.push("--allow-nonsystem-deps");
  process.stdout.write(run(process.execPath, buildArgs));

  // 2. Tarballs.
  const tarballs = join(work, "tarballs");
  mkdirSync(tarballs);
  run(npm, ["pack", "--silent", "--pack-destination", tarballs], { cwd: nativeDir });
  run(npm, ["pack", "--silent", "--pack-destination", tarballs], { cwd: tsRoot });
  const tgz = readdirSync(tarballs).filter((f) => f.endsWith(".tgz")).map((f) => join(tarballs, f));
  if (tgz.length !== 2) throw new Error(`expected 2 tarballs, got ${tgz.join(", ")}`);
  const listing = run("tar", ["-tzvf", tgz.find((f) => f.includes("native"))]);
  console.log(listing);
  if (!/-rwxr-xr-x .* package\/bin\/haltsql\b/.test(listing)) throw new Error("bin/haltsql is not 0755 in the tarball");

  // 3. A fresh consumer project, installed offline from the tarballs only.
  const proj = join(work, "project");
  mkdirSync(proj);
  writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "haltsql-smoke", version: "1.0.0", private: true }) + "\n");
  run(npm, ["install", ...tgz, "--no-audit", "--no-fund", "--offline", "--no-package-lock"], { cwd: proj });
  const installed = readdirSync(join(proj, "node_modules/@haltsql")).sort();
  console.log(`installed: ${installed.map((n) => `@haltsql/${n}`).join(", ")}`);

  // 4. ESM and CJS consumers: no binary option, no HALTSQL_BIN.
  const vector = JSON.parse(readFileSync(join(repo, "clients/testvectors/cases/saas_allow_bound_simple.json"), "utf8"));
  const deny = JSON.parse(readFileSync(join(repo, "clients/testvectors/cases/saas_deny_missing_limit.json"), "utf8"));
  const body = (importLine) => `${importLine}
const policyFile = ${JSON.stringify(join(repo, vector.policy_file))};
const v = await LocalVerifier.create({ policyFile });
if (v.binarySource !== "package") throw new Error("engine came from " + v.binarySource + ": " + v.binary);
if (!v.binary.startsWith(${JSON.stringify(join(proj, "node_modules"))})) throw new Error("unexpected engine path " + v.binary);
const got = await v.verify(${JSON.stringify(vector.request.sql)}, ${JSON.stringify(vector.request.context)});
const want = ${JSON.stringify(vector.verdict)};
for (const f of ["allowed", "statement_kind", "fingerprint", "sql_sha256"]) {
  if (JSON.stringify(got[f]) !== JSON.stringify(want[f])) throw new Error(f + ": " + JSON.stringify(got[f]) + " != " + JSON.stringify(want[f]));
}
if (JSON.stringify(got.bind_params) !== JSON.stringify(want.bind_params)) throw new Error("bind_params differ");
const d = await v.verify(${JSON.stringify(deny.request.sql)}, ${JSON.stringify(deny.request.context)});
if (d.allowed !== false) throw new Error("expected a deny");
await v.close();
console.log("ok: " + got.allowed + " / " + d.reasons.map((r) => r.code).join(",") + " via " + v.binary);
`;
  writeFileSync(join(proj, "esm.mjs"), body(`import { LocalVerifier } from "@haltsql/client";`));
  writeFileSync(
    join(proj, "cjs.cjs"),
    `(async () => {\n${body(`const { LocalVerifier } = require("@haltsql/client");`)}\n})().catch((e) => { console.error(e); process.exit(1); });\n`,
  );
  const env = { ...process.env };
  delete env.HALTSQL_BIN;
  env.PATH = dirname(process.execPath); // node only: no haltsql on PATH to fall back to
  for (const f of ["esm.mjs", "cjs.cjs"]) {
    process.stdout.write(`${f}: ` + run(process.execPath, [f], { cwd: proj, env }));
  }
  ok = true;
  console.log(`pack-native-smoke: PASS (${platform})`);
} finally {
  if (values.keep || !ok) console.log(`work dir kept: ${work}`);
  else rmSync(work, { recursive: true, force: true });
}
