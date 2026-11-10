#!/usr/bin/env node
// Add the @haltsql/native-<platform> optional dependencies to package.json, at this
// package's own version. Run right before `npm pack` / `npm publish` of
// @haltsql/client (.github/workflows/native-packages.yml does), never committed:
//
//   node scripts/set-native-deps.mjs
//
// Why they are not in the committed package.json: a release publishes the platform
// packages and the client together, so a version's platform packages never exist
// on npm while that version is developed. Declared as dependencies, they would sit
// in package-lock.json without lock entries, and `npm ci` refuses that ("Missing:
// @haltsql/native-... from lock file") once any version of them is on npm. Keeping
// them out of the repository keeps `npm ci` working for every version; users get
// them from the published package.json, as before.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgPath = join(here, "..", "package.json");

// The platforms build-native-package.mjs builds (its PLATFORMS table). Checked
// against that table below so the two cannot drift.
const PLATFORMS = ["darwin-arm64", "linux-arm64", "linux-x64"];

const builder = readFileSync(join(here, "build-native-package.mjs"), "utf8");
const table = builder.slice(builder.indexOf("export const PLATFORMS"), builder.indexOf("};", builder.indexOf("export const PLATFORMS")));
const built = [...table.matchAll(/^\s*"([a-z0-9-]+)":\s*\{/gm)].map((m) => m[1]).sort();
if (JSON.stringify(built) !== JSON.stringify([...PLATFORMS].sort())) {
  console.error(`set-native-deps: platforms ${PLATFORMS.join(", ")} do not match build-native-package.mjs (${built.join(", ")})`);
  process.exit(1);
}

const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(pkg.version)) {
  console.error(`set-native-deps: unexpected version ${JSON.stringify(pkg.version)}`);
  process.exit(1);
}
pkg.optionalDependencies = Object.fromEntries(PLATFORMS.map((p) => [`@haltsql/native-${p}`, pkg.version]));
writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
console.log(`set-native-deps: ${pkg.name}@${pkg.version} optionalDependencies = ${JSON.stringify(pkg.optionalDependencies)}`);
