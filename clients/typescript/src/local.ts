/**
 * Local (in-process-speed) verification with the bundled `haltsql` engine.
 *
 * `npm install @haltsql/client` also installs a prebuilt engine for supported
 * platforms (`@haltsql/native-<platform>-<arch>`, an optional dependency).
 * {@link LocalVerifier} runs it as one long-lived child process in JSONL
 * batch mode (`haltsql verify --policy FILE --batch`) and pipelines requests
 * over its stdin/stdout, so no sidecar is needed and a warm verification
 * costs tens of microseconds.
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants as fsConstants, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve as resolvePath } from "node:path";
import { constantTimeEqual } from "./client.js";
import {
  HaltSQLDeniedError,
  HaltSQLError,
  HaltSQLProtocolError,
  HaltSQLTimeoutError,
  HaltSQLTransportError,
  HaltSQLUsageError,
} from "./errors.js";
import { moduleUrl } from "./meta.js";
import type { Context, Verdict } from "./types.js";
import { checkContext, parseVerdict } from "./validate.js";

/** Platforms with a prebuilt engine package (`process.platform-process.arch`). */
export const NATIVE_PLATFORMS = ["linux-x64", "linux-arm64", "darwin-arm64"] as const;

/** Name of the engine package for a platform, e.g. `@haltsql/native-linux-x64`. */
export function nativePackageName(platform: string = process.platform, arch: string = process.arch): string {
  return `@haltsql/native-${platform}-${arch}`;
}

export interface LocalVerifierOptions {
  /** Path of a policy file (`.yaml`, `.yml` or `.json`). Give this or `policy`. */
  policyFile?: string;
  /**
   * The policy document itself (YAML or JSON text). It is written to a private
   * temporary file (directory 0700, file 0600) that is removed by `close()`
   * (and, as a fallback, when the process exits). Give this or `policyFile`.
   */
  policy?: string;
  /** Format of `policy`. Default: `json` if it starts with `{`, else `yaml`. */
  policyFormat?: "yaml" | "json";
  /**
   * Path of the `haltsql` executable. Default: `HALTSQL_BIN`, then the
   * bundled platform package, then `haltsql` on `PATH`.
   */
  binary?: string;
  /** Per-request timeout in milliseconds (from the call to the answer). Default 30000. */
  timeoutMs?: number;
  /**
   * Check that `verdict.sql_sha256` equals SHA-256 of the SQL that was sent,
   * so a verdict can never be applied to a different string. Default `true`.
   */
  verifySqlHash?: boolean;
}

/** One item for {@link LocalVerifier.verifyMany}. */
export type LocalVerifyItem = string | { sql: string; context?: Context };

/** Where {@link resolveLocalBinary} found the engine. */
export interface ResolvedBinary {
  path: string;
  source: "option" | "env" | "package" | "path";
}

/** Inputs of {@link resolveLocalBinary}; every field defaults to the current process. */
export interface ResolveBinaryOptions {
  binary?: string | undefined;
  env?: Record<string, string | undefined>;
  platform?: string;
  arch?: string;
  /** File or directory URL/path to resolve the platform package from. Default: this module. */
  resolveFrom?: string;
}

function isExecutableFile(p: string): boolean {
  try {
    if (!statSync(p).isFile()) return false;
    accessSync(p, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function requireExecutable(p: string, what: string): string {
  const abs = resolvePath(p);
  if (!isExecutableFile(abs)) throw new HaltSQLUsageError(`${what} ${JSON.stringify(abs)} is not an executable file`);
  return abs;
}

/**
 * Finds the `haltsql` engine: the explicit `binary`, then `HALTSQL_BIN`, then
 * the bundled package `@haltsql/native-<platform>-<arch>`, then `haltsql` on
 * `PATH`. An explicit choice that is not executable is an error (no silent
 * fallback). Throws {@link HaltSQLUsageError} if nothing is found.
 */
export function resolveLocalBinary(opts: ResolveBinaryOptions = {}): ResolvedBinary {
  const env = opts.env ?? process.env;
  if (opts.binary !== undefined) {
    if (typeof opts.binary !== "string" || opts.binary === "") throw new HaltSQLUsageError("binary must be a non-empty string");
    return { path: requireExecutable(opts.binary, "binary"), source: "option" };
  }
  const fromEnv = env.HALTSQL_BIN;
  if (fromEnv !== undefined && fromEnv !== "") {
    return { path: requireExecutable(fromEnv, "HALTSQL_BIN"), source: "env" };
  }
  const platform = opts.platform ?? process.platform;
  const arch = opts.arch ?? process.arch;
  const pkg = nativePackageName(platform, arch);
  const supported = (NATIVE_PLATFORMS as readonly string[]).includes(`${platform}-${arch}`);
  if (supported) {
    let pkgJson: string | undefined;
    try {
      let base = opts.resolveFrom ?? moduleUrl;
      // createRequire needs a file; a trailing slash marks a directory.
      if (!base.startsWith("file:") && !base.endsWith("/")) {
        try {
          if (statSync(base).isDirectory()) base = join(base, "noop.js");
        } catch {
          /* not a path on disk; let createRequire decide */
        }
      }
      pkgJson = createRequire(base).resolve(`${pkg}/package.json`);
    } catch {
      pkgJson = undefined; // not installed (unsupported libc, --no-optional, ...)
    }
    if (pkgJson !== undefined) {
      const bin = join(dirname(pkgJson), "bin", "haltsql");
      if (!isExecutableFile(bin)) {
        throw new HaltSQLUsageError(
          `${pkg} is installed but ${JSON.stringify(bin)} is not an executable file; reinstall it`,
        );
      }
      return { path: bin, source: "package" };
    }
  }
  const names = platform === "win32" ? ["haltsql.exe", "haltsql"] : ["haltsql"];
  for (const dir of (env.PATH ?? "").split(delimiter)) {
    if (dir === "" || !isAbsolute(dir)) continue; // never resolve relative to the cwd
    for (const n of names) {
      const p = join(dir, n);
      if (isExecutableFile(p)) return { path: p, source: "path" };
    }
  }
  const hint = supported
    ? `install the optional dependency ${pkg} (npm installs it with @haltsql/client unless optional dependencies are omitted)`
    : `there is no prebuilt engine for ${platform}-${arch} (supported: ${NATIVE_PLATFORMS.join(", ")})`;
  throw new HaltSQLUsageError(
    `cannot find the haltsql engine: ${hint}, set HALTSQL_BIN, pass the binary option, or put haltsql on PATH`,
  );
}

// ---------------------------------------------------------------------------
// Temporary policy files: removed on close() and, as a fallback, at exit.

const tempDirs = new Set<string>();
let exitHookInstalled = false;

function removeTempDir(dir: string): void {
  tempDirs.delete(dir);
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

function writeTempPolicy(text: string, format: "yaml" | "json"): { dir: string; file: string } {
  if (!exitHookInstalled) {
    exitHookInstalled = true;
    process.once("exit", () => {
      for (const d of [...tempDirs]) removeTempDir(d);
    });
  }
  const dir = mkdtempSync(join(tmpdir(), "haltsql-policy-")); // mode 0700
  tempDirs.add(dir);
  const file = join(dir, `policy.${format}`);
  try {
    writeFileSync(file, text, { mode: 0o600, flag: "wx" });
  } catch (e) {
    removeTempDir(dir);
    throw new HaltSQLUsageError(`cannot write the temporary policy file: ${(e as Error).message}`);
  }
  return { dir, file };
}

// ---------------------------------------------------------------------------

const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const STDERR_KEEP = 8192;
const MAX_LINE_BYTES = 64 << 20;

interface Pending {
  id: number;
  sql: string;
  deadline: number;
  resolve: (v: Verdict) => void;
  reject: (e: HaltSQLError) => void;
}

/**
 * One engine child process. Requests are answered strictly in order, so the
 * pending queue is FIFO and every answer must carry the id of its head. Any
 * deviation kills the process and rejects everything still pending; the
 * owner then starts a fresh engine on the next call.
 * @internal
 */
class Engine {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #queue: Pending[] = [];
  #head = 0;
  #nextId = 1;
  #partial: Buffer[] = [];
  #partialBytes = 0;
  #stderr = "";
  #answered = false;
  #dead = false;
  #reffed = true;
  #timer: NodeJS.Timeout | undefined;
  readonly #closed: Promise<void>;

  constructor(
    binary: string,
    policyFile: string,
    readonly timeoutMs: number,
    readonly checkHash: boolean,
    readonly onDead: (e: Engine) => void,
  ) {
    // Only the policy path is on the command line; SQL and context go over stdin.
    this.#child = spawn(binary, ["verify", `--policy=${policyFile}`, "--batch"], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let closedResolve!: () => void;
    this.#closed = new Promise((r) => (closedResolve = r));
    const c = this.#child;
    c.stdout.on("data", (chunk: Buffer) => this.#onData(chunk));
    c.stderr.on("data", (chunk: Buffer) => {
      this.#stderr = (this.#stderr + chunk.toString("utf8")).slice(-STDERR_KEEP);
    });
    // EPIPE and friends: the process is going away; "close" reports why.
    c.stdin.on("error", () => this.#kill());
    c.stdout.on("error", () => this.#kill());
    c.stderr.on("error", () => {});
    c.on("error", (e) => {
      this.#fail(new HaltSQLTransportError(`cannot run the haltsql engine ${JSON.stringify(binary)}: ${e.message}`, e));
      closedResolve();
    });
    c.on("close", (code, signal) => {
      closedResolve();
      if (this.#dead) return;
      const why = signal ? `was killed by ${signal}` : `exited with code ${code}`;
      const tail = this.#stderr.trim();
      const detail = tail ? `: ${tail.slice(-2000)}` : "";
      if (!this.#answered && code === 2) {
        this.#fail(new HaltSQLUsageError(`haltsql engine failed to start (policy or usage error)${detail}`));
      } else {
        this.#fail(new HaltSQLTransportError(`haltsql engine ${why}${detail}`));
      }
    });
    this.#setRef(false);
  }

  get pid(): number | undefined {
    return this.#child.pid;
  }

  get pending(): number {
    return this.#queue.length - this.#head;
  }

  get dead(): boolean {
    return this.#dead;
  }

  /** Resolves once the process has exited and its pipes are closed. */
  get closed(): Promise<void> {
    return this.#closed;
  }

  send(sql: string, context: Context): Promise<Verdict> {
    if (this.#dead) return Promise.reject(new HaltSQLTransportError("haltsql engine is not running"));
    const id = this.#nextId++;
    const line = JSON.stringify({ id, sql, context }) + "\n";
    return new Promise<Verdict>((resolve, reject) => {
      this.#queue.push({ id, sql, deadline: Date.now() + this.timeoutMs, resolve, reject });
      if (this.pending === 1) {
        this.#setRef(true);
        this.#arm();
      }
      this.#child.stdin.write(line);
    });
  }

  /**
   * Rejects everything pending with `err`, kills the process and waits (at
   * most `waitMs`) for it to exit.
   */
  async shutdown(err: HaltSQLError, waitMs: number): Promise<void> {
    this.#fail(err);
    let timer: NodeJS.Timeout | undefined;
    const gaveUp = await Promise.race([
      this.#closed.then(() => false),
      new Promise<boolean>((r) => (timer = setTimeout(() => r(true), waitMs))),
    ]);
    clearTimeout(timer);
    if (gaveUp) this.#setRef(false);
  }

  #setRef(on: boolean): void {
    if (this.#reffed === on) return;
    this.#reffed = on;
    const c = this.#child;
    const m = on ? "ref" : "unref";
    c[m]();
    for (const s of [c.stdin, c.stdout, c.stderr] as unknown as Array<{ ref?: () => void; unref?: () => void }>) {
      s[m]?.();
    }
  }

  #arm(): void {
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    const head = this.#queue[this.#head];
    if (head === undefined) return;
    // FIFO with one timeout for all: the head always has the earliest deadline.
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      const h = this.#queue[this.#head];
      if (h === undefined || this.#dead) return;
      if (Date.now() < h.deadline) return this.#arm();
      this.#popHead();
      h.reject(new HaltSQLTimeoutError(this.timeoutMs));
      this.#fail(new HaltSQLTransportError("haltsql engine was stopped after an earlier request timed out"));
    }, Math.max(0, head.deadline - Date.now()));
  }

  #popHead(): Pending | undefined {
    const p = this.#queue[this.#head];
    if (p === undefined) return undefined;
    this.#queue[this.#head] = undefined as unknown as Pending;
    this.#head++;
    if (this.#head > 1024 && this.#head * 2 > this.#queue.length) {
      this.#queue.splice(0, this.#head);
      this.#head = 0;
    }
    if (this.pending === 0) {
      this.#queue.length = 0;
      this.#head = 0;
    }
    return p;
  }

  #onData(chunk: Buffer): void {
    let start = 0;
    while (!this.#dead) {
      const nl = chunk.indexOf(0x0a, start);
      if (nl === -1) break;
      let line: Buffer;
      if (this.#partialBytes > 0) {
        this.#partial.push(chunk.subarray(start, nl));
        line = Buffer.concat(this.#partial);
        this.#partial = [];
        this.#partialBytes = 0;
      } else {
        line = chunk.subarray(start, nl);
      }
      start = nl + 1;
      // Decoding whole lines (split on the 0x0A byte) keeps multi-byte UTF-8
      // sequences that straddle chunk boundaries intact.
      this.#onLine(line.toString("utf8"));
    }
    if (this.#dead || start >= chunk.length) return;
    this.#partial.push(chunk.subarray(start));
    this.#partialBytes += chunk.length - start;
    if (this.#partialBytes > MAX_LINE_BYTES) {
      this.#fail(new HaltSQLProtocolError(`haltsql engine wrote a line longer than ${MAX_LINE_BYTES} bytes`));
    }
  }

  #onLine(text: string): void {
    this.#answered = true;
    const head = this.#queue[this.#head];
    if (head === undefined) {
      return this.#fail(new HaltSQLProtocolError("haltsql engine wrote output nobody asked for"));
    }
    let obj: unknown;
    try {
      obj = JSON.parse(text);
    } catch {
      return this.#fail(new HaltSQLProtocolError(`haltsql engine wrote a non-JSON line: ${JSON.stringify(text.slice(0, 200))}`));
    }
    if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
      return this.#fail(new HaltSQLProtocolError("haltsql engine wrote a line that is not a JSON object"));
    }
    const rec = obj as Record<string, unknown>;
    if (rec.id !== head.id) {
      return this.#fail(
        new HaltSQLProtocolError(`haltsql engine answered id ${JSON.stringify(rec.id)} while ${head.id} was expected`),
      );
    }
    if ("error" in rec) {
      // The stream is still in sync (the id matched): only this request fails.
      this.#popHead();
      this.#afterAnswer();
      const msg = typeof rec.error === "string" ? rec.error.slice(0, 500) : "unknown error";
      return head.reject(new HaltSQLProtocolError(`haltsql engine rejected the request: ${msg}`));
    }
    let verdict: Verdict;
    try {
      verdict = parseVerdict(rec);
    } catch (e) {
      return this.#fail(e instanceof HaltSQLError ? e : new HaltSQLProtocolError(String(e)));
    }
    if (this.checkHash) {
      const expected = createHash("sha256").update(head.sql, "utf8").digest("hex");
      if (!constantTimeEqual(expected, verdict.sql_sha256)) {
        return this.#fail(new HaltSQLProtocolError("sql_sha256 does not match the SQL that was sent"));
      }
    }
    this.#popHead();
    this.#afterAnswer();
    head.resolve(verdict);
  }

  #afterAnswer(): void {
    if (this.pending === 0) {
      if (this.#timer !== undefined) clearTimeout(this.#timer);
      this.#timer = undefined;
      this.#setRef(false);
    } else {
      this.#arm();
    }
  }

  #kill(): void {
    try {
      this.#child.kill("SIGKILL");
    } catch {
      /* already gone */
    }
  }

  #fail(err: HaltSQLError): void {
    if (this.#dead) return;
    this.#dead = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    const victims = this.#queue.slice(this.#head);
    this.#queue.length = 0;
    this.#head = 0;
    this.#partial = [];
    this.#partialBytes = 0;
    this.#kill();
    // Hold the event loop until the "close" event so shutdown() can be awaited
    // (and the process reaped); SIGKILL makes that prompt.
    this.#setRef(true);
    void this.#closed.then(() => this.#setRef(false));
    this.onDead(this);
    for (const p of victims) p.reject(err);
  }
}

function positiveInt(name: string, v: number | undefined, dflt: number): number {
  if (v === undefined) return dflt;
  if (!Number.isSafeInteger(v) || v < 1) throw new HaltSQLUsageError(`${name} must be an integer >= 1`);
  return v;
}

/**
 * Verifies SQL locally with the `haltsql` engine, without a sidecar.
 *
 * ```ts
 * import { LocalVerifier } from "@haltsql/client";
 * const haltsql = await LocalVerifier.create({ policyFile: "policies/saas.yaml" });
 * const v = await haltsql.verify(sql, { tenant_id: session.tenantId });
 * if (v.allowed) { ... }
 * await haltsql.close();
 * ```
 *
 * The engine is one long-lived child process, started on first use (or by
 * {@link LocalVerifier.create} / {@link LocalVerifier.start}). Concurrent
 * calls are pipelined over its stdin and answered in order. An idle verifier
 * does not keep the Node.js event loop alive.
 *
 * Fail-closed contract: `verify()` resolves only with a strictly validated
 * verdict whose `sql_sha256` matches the SQL. A timeout, a crash, malformed
 * output or an answer out of order rejects (with a {@link HaltSQLError},
 * whose `allowed` is always `false`) every request still in flight, stops
 * the process, and the next call starts a fresh one.
 */
export class LocalVerifier {
  readonly #binary: string;
  readonly #binarySource: ResolvedBinary["source"];
  readonly #policyText: { text: string; format: "yaml" | "json" } | undefined;
  #policyFile: string | undefined;
  #tempDir: string | undefined;
  readonly #timeoutMs: number;
  readonly #checkHash: boolean;
  #engine: Engine | undefined;
  #closed = false;
  #closing: Promise<void> | undefined;

  /**
   * Validates the options and finds the engine binary; nothing is spawned
   * until the first call. Throws {@link HaltSQLUsageError} on bad options or
   * when no engine is found.
   */
  constructor(opts: LocalVerifierOptions) {
    if (typeof opts !== "object" || opts === null) throw new HaltSQLUsageError("options are required");
    const hasFile = opts.policyFile !== undefined;
    const hasText = opts.policy !== undefined;
    if (hasFile === hasText) throw new HaltSQLUsageError("give exactly one of policyFile or policy");
    if (hasFile) {
      if (typeof opts.policyFile !== "string" || opts.policyFile === "") {
        throw new HaltSQLUsageError("policyFile must be a non-empty string");
      }
      this.#policyFile = resolvePath(opts.policyFile);
    } else {
      if (typeof opts.policy !== "string" || opts.policy.trim() === "") {
        throw new HaltSQLUsageError("policy must be a non-empty string");
      }
      const fmt = opts.policyFormat ?? (opts.policy.trimStart().startsWith("{") ? "json" : "yaml");
      if (fmt !== "yaml" && fmt !== "json") throw new HaltSQLUsageError('policyFormat must be "yaml" or "json"');
      this.#policyText = { text: opts.policy, format: fmt };
    }
    if (opts.policyFormat !== undefined && hasFile) {
      throw new HaltSQLUsageError("policyFormat applies to policy only; a policyFile's format comes from its extension");
    }
    this.#timeoutMs = positiveInt("timeoutMs", opts.timeoutMs, 30000);
    this.#checkHash = opts.verifySqlHash ?? true;
    const found = resolveLocalBinary({ binary: opts.binary });
    this.#binary = found.path;
    this.#binarySource = found.source;
  }

  /**
   * Creates a verifier and starts the engine, so a bad policy or a missing
   * binary fails here rather than on the first `verify()`.
   */
  static async create(opts: LocalVerifierOptions): Promise<LocalVerifier> {
    const v = new LocalVerifier(opts);
    try {
      await v.start();
    } catch (e) {
      await v.close();
      throw e;
    }
    return v;
  }

  /** Absolute path of the engine binary in use. */
  get binary(): string {
    return this.#binary;
  }

  /** How the binary was found: `option`, `env` (`HALTSQL_BIN`), `package` or `path`. */
  get binarySource(): ResolvedBinary["source"] {
    return this.#binarySource;
  }

  /** PID of the running engine, or `undefined` when none is running. */
  get pid(): number | undefined {
    return this.#engine?.pid;
  }

  /** `true` once `close()` has been called. */
  get closed(): boolean {
    return this.#closed;
  }

  /**
   * Starts the engine (if it is not running) and waits until it has loaded
   * the policy and answered a probe. Rejects with the engine's error message
   * if the policy cannot be loaded.
   */
  async start(): Promise<void> {
    await this.#engineFor().send("SELECT 1", {});
  }

  /**
   * Verifies one SQL string. Resolves with the verdict (allowed or denied);
   * rejects with a {@link HaltSQLError} on any failure.
   * Only `verdict.allowed === true` permits running the SQL.
   */
  async verify(sql: string, context?: Context): Promise<Verdict> {
    const ctx = checkInput(sql, context);
    return this.#engineFor().send(sql, ctx);
  }

  /** Like {@link LocalVerifier.verify}, but rejects with {@link HaltSQLDeniedError} unless allowed. */
  async check(sql: string, context?: Context): Promise<Verdict> {
    const v = await this.verify(sql, context);
    if (!v.allowed) throw new HaltSQLDeniedError(v);
    return v;
  }

  /**
   * Verifies many statements in one pipelined burst; resolves with the
   * verdicts in input order. A string item uses `context`. Every item is
   * validated before anything is sent. Rejects if any item fails.
   */
  async verifyMany(items: Iterable<LocalVerifyItem>, context?: Context): Promise<Verdict[]> {
    const shared = context === undefined ? undefined : checkContext(context);
    const reqs: Array<{ sql: string; ctx: Context }> = [];
    for (const it of items) {
      if (typeof it === "string") reqs.push({ sql: it, ctx: checkInput(it, shared) });
      else if (typeof it === "object" && it !== null) reqs.push({ sql: it.sql, ctx: checkInput(it.sql, it.context ?? shared) });
      else throw new HaltSQLUsageError("verifyMany items must be strings or { sql, context } objects");
    }
    if (reqs.length === 0) return [];
    const engine = this.#engineFor();
    return Promise.all(reqs.map((r) => engine.send(r.sql, r.ctx)));
  }

  /**
   * Stops the engine and removes the temporary policy file. Requests still
   * in flight reject with {@link HaltSQLTransportError}. Idempotent.
   */
  close(): Promise<void> {
    if (this.#closing) return this.#closing;
    this.#closed = true;
    const engine = this.#engine;
    this.#engine = undefined;
    this.#closing = (async () => {
      if (engine) {
        await engine.shutdown(new HaltSQLTransportError("LocalVerifier was closed"), 2000);
      }
      if (this.#tempDir !== undefined) removeTempDir(this.#tempDir);
      this.#tempDir = undefined;
    })();
    return this.#closing;
  }

  /** `await using v = new LocalVerifier(...)` closes it at the end of the scope. */
  [Symbol.asyncDispose](): Promise<void> {
    return this.close();
  }

  #engineFor(): Engine {
    if (this.#closed) throw new HaltSQLUsageError("LocalVerifier is closed");
    if (this.#engine && !this.#engine.dead) return this.#engine;
    if (this.#policyFile === undefined) {
      const t = writeTempPolicy(this.#policyText!.text, this.#policyText!.format);
      this.#tempDir = t.dir;
      this.#policyFile = t.file;
    }
    const engine = new Engine(this.#binary, this.#policyFile, this.#timeoutMs, this.#checkHash, (e) => {
      if (this.#engine === e) this.#engine = undefined;
    });
    this.#engine = engine;
    return engine;
  }
}

function checkInput(sql: unknown, context: unknown): Context {
  if (typeof sql !== "string") throw new HaltSQLUsageError("sql must be a string");
  // A lone surrogate has no UTF-8 encoding: the engine and the hash check
  // would each substitute something, so the verdict would not be for `sql`.
  if (LONE_SURROGATE.test(sql)) throw new HaltSQLUsageError("sql contains a lone UTF-16 surrogate (not valid Unicode)");
  return checkContext(context);
}
