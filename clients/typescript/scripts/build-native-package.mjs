#!/usr/bin/env node
// Builds a ready-to-publish platform package @haltsql/native-<platform> that
// carries the compiled haltsql CLI and libhaltsql. @haltsql/client lists these
// packages as optionalDependencies (esbuild-style) and LocalVerifier runs the
// CLI from them.
//
// Usage (from the repository root, after building the engine):
//   eval $(opam env); dune build ./bin/haltsql/main.exe ./native/libhaltsql.so
//   node clients/typescript/scripts/build-native-package.mjs \
//     --platform linux-x64 \
//     --binary _build/default/bin/haltsql/main.exe \
//     --lib _build/default/native/libhaltsql.so \
//     --out dist-native/linux-x64 [--version 0.1.0] [--allow-nonsystem-deps]
//
// Then: (cd dist-native/linux-x64 && npm publish --access public)
//
// The binary and library are checked against the target platform (ELF or
// Mach-O header, CPU), and their dynamic dependencies are checked (with
// readelf/otool when available) so a package never ships a binary that needs
// a library the user does not have (e.g. Homebrew's libgmp). Pass
// --allow-nonsystem-deps to downgrade that check to a warning (local smoke
// tests only; never for a published package).

import { spawnSync } from "node:child_process";
import {
  accessSync,
  chmodSync,
  constants,
  copyFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  closeSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const here = dirname(fileURLToPath(import.meta.url));
const tsRoot = resolve(here, "..");
const repoRoot = resolve(tsRoot, "../..");

export const PLATFORMS = {
  "linux-x64": { os: "linux", cpu: "x64", libc: ["glibc"], lib: "libhaltsql.so", format: "elf", machine: 0x3e },
  "linux-arm64": { os: "linux", cpu: "arm64", libc: ["glibc"], lib: "libhaltsql.so", format: "elf", machine: 0xb7 },
  "darwin-arm64": { os: "darwin", cpu: "arm64", libc: null, lib: "libhaltsql.dylib", format: "macho", machine: 0x0100000c },
};

function die(msg) {
  console.error(`build-native-package: ${msg}`);
  process.exit(2);
}

function readHeader(path, n = 64) {
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.alloc(n);
    const got = readSync(fd, buf, 0, n, 0);
    return buf.subarray(0, got);
  } finally {
    closeSync(fd);
  }
}

/** Checks that `path` is an ELF/Mach-O file for the target CPU. */
function checkObjectFormat(path, target, what) {
  const h = readHeader(path);
  if (target.format === "elf") {
    if (h.length < 20 || h.readUInt32BE(0) !== 0x7f454c46) die(`${what} ${path} is not an ELF file (needed for ${target.os})`);
    if (h[4] !== 2) die(`${what} ${path} is not a 64-bit ELF file`);
    const le = h[5] === 1;
    const machine = le ? h.readUInt16LE(18) : h.readUInt16BE(18);
    if (machine !== target.machine) {
      die(`${what} ${path} is for ELF machine 0x${machine.toString(16)}, expected 0x${target.machine.toString(16)} (${target.cpu})`);
    }
  } else {
    if (h.length < 8 || h.readUInt32LE(0) !== 0xfeedfacf) die(`${what} ${path} is not a 64-bit Mach-O file (needed for darwin)`);
    const cpu = h.readUInt32LE(4);
    if (cpu !== target.machine) die(`${what} ${path} is for Mach-O CPU 0x${cpu.toString(16)}, expected arm64`);
  }
}

function tool(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8" });
  if (r.error || r.status !== 0) return null;
  return r.stdout;
}

/** Returns dynamic dependencies that a stock system may not have. */
function nonSystemDeps(path, target) {
  if (target.format === "macho") {
    const out = tool("otool", ["-L", path]);
    if (out === null) return null;
    return out
      .split("\n")
      .slice(1)
      .map((l) => l.trim().split(" (")[0])
      .filter((d) => d && !d.startsWith("/usr/lib/") && !d.startsWith("/System/"))
      // A dylib's first entry is its own install name (fixed below).
      .filter((d) => !/haltsql/.test(d));
  }
  const out = tool("readelf", ["-d", path]) ?? tool("objdump", ["-p", path]);
  if (out === null) return null;
  const glibc = /^(libc|libm|libdl|libpthread|librt|libutil|ld-linux[\w.-]*|libgcc_s)\.so(\.\d+)*$/;
  const needed = [...out.matchAll(/(?:NEEDED\s+(?:Shared library: \[)?)([^\]\s]+)/g)].map((m) => m[1]);
  return needed.filter((n) => !glibc.test(n));
}

function main() {
  const { values } = parseArgs({
    options: {
      platform: { type: "string" },
      binary: { type: "string" },
      lib: { type: "string" },
      out: { type: "string" },
      version: { type: "string" },
      "allow-nonsystem-deps": { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
    strict: true,
  });
  if (values.help) {
    console.log(
      "usage: build-native-package.mjs --platform <" +
        Object.keys(PLATFORMS).join("|") +
        "> --binary PATH --lib PATH --out DIR [--version V] [--allow-nonsystem-deps]",
    );
    return;
  }
  const platform = values.platform;
  if (!platform) die("--platform is required");
  const target = PLATFORMS[platform];
  if (!target) die(`unknown platform ${JSON.stringify(platform)}; known: ${Object.keys(PLATFORMS).join(", ")}`);
  for (const k of ["binary", "lib", "out"]) if (!values[k]) die(`--${k} is required`);
  const binary = resolve(values.binary);
  const lib = resolve(values.lib);
  const out = resolve(values.out);

  if (!existsSync(binary) || !statSync(binary).isFile()) die(`--binary ${binary} is not a file`);
  try {
    accessSync(binary, constants.X_OK);
  } catch {
    die(`--binary ${binary} is not executable`);
  }
  if (!existsSync(lib) || !statSync(lib).isFile()) die(`--lib ${lib} is not a file`);
  checkObjectFormat(binary, target, "--binary");
  checkObjectFormat(lib, target, "--lib");

  const clientPkg = JSON.parse(readFileSync(join(tsRoot, "package.json"), "utf8"));
  const version = values.version ?? clientPkg.version;
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) die(`invalid --version ${JSON.stringify(version)}`);

  const host = `${process.platform}-${process.arch}`;
  for (const [what, p] of [["--binary", binary], ["--lib", lib]]) {
    const deps = nonSystemDeps(p, target);
    if (deps === null) {
      console.warn(`build-native-package: warning: cannot inspect dynamic dependencies of ${what} on ${host} (no otool/readelf)`);
    } else if (deps.length > 0) {
      const msg = `${what} ${p} depends on libraries a stock ${target.os} system may not have: ${deps.join(", ")}; link them statically`;
      if (values["allow-nonsystem-deps"]) console.warn(`build-native-package: warning: ${msg}`);
      else die(`${msg} (or pass --allow-nonsystem-deps for a local test)`);
    }
  }

  if (existsSync(out) && readdirSync(out).length > 0) die(`--out ${out} exists and is not empty`);
  mkdirSync(join(out, "bin"), { recursive: true });
  mkdirSync(join(out, "lib"), { recursive: true });
  mkdirSync(join(out, "include"), { recursive: true });

  const binOut = join(out, "bin", "haltsql");
  copyFileSync(binary, binOut);
  chmodSync(binOut, 0o755);
  const libOut = join(out, "lib", target.lib);
  copyFileSync(lib, libOut);
  chmodSync(libOut, 0o755);
  if (target.format === "macho" && process.platform === "darwin") {
    // Give the dylib a relocatable install name, then re-sign it (arm64
    // requires a valid signature after any load-command change).
    const id = spawnSync("install_name_tool", ["-id", `@rpath/${target.lib}`, libOut], { stdio: "inherit" });
    if (id.status !== 0) die("install_name_tool -id failed");
    const sign = spawnSync("codesign", ["--force", "--sign", "-", libOut], { stdio: "inherit" });
    if (sign.status !== 0) die("codesign failed");
  }
  copyFileSync(join(repoRoot, "native/include/haltsql.h"), join(out, "include", "haltsql.h"));
  copyFileSync(join(repoRoot, "LICENSE"), join(out, "LICENSE"));
  copyFileSync(join(repoRoot, "NOTICE"), join(out, "NOTICE"));
  copyFileSync(join(repoRoot, "vendor/libpg_query/LICENSE"), join(out, "LICENSE.libpg_query"));

  const fill = (s) =>
    s
      .replaceAll("{{platform}}", platform)
      .replaceAll("{{version}}", version)
      .replaceAll("{{os}}", target.os)
      .replaceAll("{{cpu}}", target.cpu)
      .replaceAll("{{lib}}", target.lib)
      .replaceAll("{{libc_note}}", target.libc ? "glibc" : "macOS 11 or newer");
  const tmplDir = join(tsRoot, "npm/native");
  const tmpl = JSON.parse(fill(readFileSync(join(tmplDir, "package.template.json"), "utf8")));
  const pkg = {};
  for (const [k, v] of Object.entries(tmpl)) {
    pkg[k] = v;
    // npm (>= 10.4) skips the package on musl systems; LocalVerifier then
    // falls back to HALTSQL_BIN or PATH.
    if (k === "cpu" && target.libc) pkg.libc = target.libc;
  }
  writeFileSync(join(out, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
  writeFileSync(join(out, "README.md"), fill(readFileSync(join(tmplDir, "README.md"), "utf8")));

  // Smoke-check the copied binary when it can run here.
  if (platform === host) {
    const r = spawnSync(binOut, ["version"], { encoding: "utf8" });
    if (r.status !== 0) die(`${binOut} version failed: ${(r.stderr || r.error?.message || "").trim()}`);
    console.log(`build-native-package: ${r.stdout.split("\n")[0]}`);
  }
  console.log(`build-native-package: wrote ${pkg.name}@${version} to ${out}`);
}

main();
