/**
 * URL of this module, used as the base for resolving the bundled engine
 * package. The ESM build keeps `import.meta.url`; the CommonJS build cannot
 * contain `import.meta` at all, so scripts/write-cjs-package.mjs replaces the
 * compiled dist/cjs/meta.js with an equivalent based on `__filename`.
 * @internal
 */
// @ts-ignore TS1343 under the CommonJS build; the emitted file is replaced there.
export const moduleUrl: string = import.meta.url;
