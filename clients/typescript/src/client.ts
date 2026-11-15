import { createHash } from "node:crypto";
import {
  HaltSQLError,
  HaltSQLHttpError,
  HaltSQLProtocolError,
  HaltSQLTimeoutError,
  HaltSQLTransportError,
  HaltSQLUsageError,
} from "./errors.js";
import type { Context, HealthStatus, PolicySummary, ReadyStatus, Verdict } from "./types.js";
import { checkContext, parsePolicies, parseVerdict } from "./validate.js";

/** SDK version, sent in the `User-Agent` header. */
export const VERSION = "0.0.3";

export interface ClientOptions {
  /** Sidecar base URL, e.g. `http://127.0.0.1:8080`. Must be http(s). */
  baseUrl: string;
  /** Bearer token. Sent only to `/v1/*`. Never logged or put in errors. */
  token?: string;
  /** Per-attempt timeout in milliseconds. Default 5000. */
  timeoutMs?: number;
  /** Retries after the first attempt on 503, network errors and timeouts. Default 2. */
  maxRetries?: number;
  /** First backoff delay in ms (doubles each retry, full jitter). Default 100. */
  retryBaseDelayMs?: number;
  /** Maximum backoff delay in ms (also caps `Retry-After`). Default 2000. */
  retryMaxDelayMs?: number;
  /** Largest response body accepted, in bytes. Default 8 MiB. */
  maxResponseBytes?: number;
  /**
   * Check that `verdict.sql_sha256` equals SHA-256 of the SQL that was sent,
   * so a verdict can never be applied to a different string. Default `true`.
   */
  checkSqlHash?: boolean;
  /** Extra headers for every request (cannot override `Authorization`). */
  headers?: Record<string, string>;
  /** `fetch` implementation; defaults to the global one (Node >= 18). */
  fetch?: typeof fetch;
  /**
   * An undici `Dispatcher` (e.g. `new Agent({ connect: { ca, cert, key } })`
   * from the `undici` package) passed to every `fetch` call. Use it for a
   * private CA, mutual TLS, a proxy or connection-pool tuning with Node's
   * built-in fetch. TLS certificate verification is on unless you turn it off
   * here.
   */
  dispatcher?: unknown;
}

export interface VerifyOptions {
  /** Policy name; with a token it must equal the token's pinned policy. */
  policy?: string;
  /** Sent as `X-Request-Id` to correlate with server logs. */
  requestId?: string;
  /** Aborts the call (no retry after an abort). */
  signal?: AbortSignal;
}

interface RawResponse {
  status: number;
  body: string;
  requestId: string | undefined;
  retryAfterMs: number | undefined;
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const t = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(t);
      reject(signal!.reason);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });

function positiveInt(name: string, v: number | undefined, dflt: number, min = 0): number {
  if (v === undefined) return dflt;
  if (!Number.isSafeInteger(v) || v < min) {
    throw new HaltSQLUsageError(`${name} must be an integer >= ${min}`);
  }
  return v;
}

/**
 * Client for the HaltSQL sidecar HTTP API.
 *
 * Fail-closed contract: {@link HaltSQLClient.verify} resolves only with a
 * strictly validated verdict from an HTTP 200 response. Anything else (non-200,
 * timeout, network error, malformed body, hash mismatch) rejects with a
 * {@link HaltSQLError}, whose `allowed` is always `false`.
 */
export class HaltSQLClient {
  readonly baseUrl: string;
  readonly #token: string | undefined;
  readonly #timeoutMs: number;
  readonly #maxRetries: number;
  readonly #baseDelay: number;
  readonly #maxDelay: number;
  readonly #maxBytes: number;
  readonly #checkHash: boolean;
  readonly #headers: Record<string, string>;
  readonly #fetch: typeof fetch;
  readonly #dispatcher: unknown;

  constructor(opts: ClientOptions) {
    let url: URL;
    try {
      url = new URL(opts.baseUrl);
    } catch {
      throw new HaltSQLUsageError("baseUrl is not a valid URL");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new HaltSQLUsageError("baseUrl must use http or https");
    }
    if (url.username || url.password) {
      throw new HaltSQLUsageError("baseUrl must not contain credentials; use token");
    }
    this.baseUrl = url.toString().replace(/\/+$/, "");
    if (opts.token !== undefined) {
      // RFC 6750 token68-ish: visible ASCII, no spaces, no CR/LF injection.
      if (!/^[\x21-\x7e]+$/.test(opts.token)) {
        throw new HaltSQLUsageError("token must be non-empty visible ASCII");
      }
    }
    this.#token = opts.token;
    this.#timeoutMs = positiveInt("timeoutMs", opts.timeoutMs, 5000, 1);
    this.#maxRetries = positiveInt("maxRetries", opts.maxRetries, 2);
    this.#baseDelay = positiveInt("retryBaseDelayMs", opts.retryBaseDelayMs, 100);
    this.#maxDelay = positiveInt("retryMaxDelayMs", opts.retryMaxDelayMs, 2000);
    this.#maxBytes = positiveInt("maxResponseBytes", opts.maxResponseBytes, 8 << 20, 1);
    this.#checkHash = opts.checkSqlHash ?? true;
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(opts.headers ?? {})) {
      if (k.toLowerCase() === "authorization") {
        throw new HaltSQLUsageError("set the token option instead of an Authorization header");
      }
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(k) || typeof v !== "string" || /[\r\n\0]/.test(v)) {
        throw new HaltSQLUsageError(`header ${JSON.stringify(k)} is not a valid header`);
      }
      headers[k] = v;
    }
    this.#headers = headers;
    const f = opts.fetch ?? globalThis.fetch;
    if (typeof f !== "function") throw new HaltSQLUsageError("no fetch implementation (Node >= 18 required)");
    this.#fetch = f;
    this.#dispatcher = opts.dispatcher;
  }

  /**
   * Verifies one SQL string. Resolves with the verdict (allowed or denied);
   * rejects with a {@link HaltSQLError} on any failure.
   * Only `verdict.allowed === true` permits running the SQL.
   */
  async verify(sql: string, context?: Context, opts: VerifyOptions = {}): Promise<Verdict> {
    if (typeof sql !== "string") throw new HaltSQLUsageError("sql must be a string");
    const body: Record<string, unknown> = { sql, context: checkContext(context) };
    if (opts.policy !== undefined) {
      if (typeof opts.policy !== "string" || opts.policy === "") {
        throw new HaltSQLUsageError("policy must be a non-empty string");
      }
      body.policy = opts.policy;
    }
    if (opts.requestId !== undefined && !/^[\x20-\x7e]{1,200}$/.test(opts.requestId)) {
      throw new HaltSQLUsageError("requestId must be 1-200 printable ASCII characters");
    }
    const res = await this.#request("POST", "/v1/verify", {
      body: JSON.stringify(body),
      auth: true,
      retry: true,
      requestId: opts.requestId,
      signal: opts.signal,
    });
    if (res.status !== 200) throw httpError(res);
    const verdict = parseVerdict(parseJson(res), res.requestId);
    if (this.#checkHash) {
      const expected = createHash("sha256").update(sql, "utf8").digest("hex");
      if (!constantTimeEqual(expected, verdict.sql_sha256)) {
        throw new HaltSQLProtocolError("sql_sha256 does not match the SQL that was sent", res.requestId);
      }
    }
    return verdict;
  }

  /** `GET /healthz`. Rejects unless the server answers 200. */
  async health(signal?: AbortSignal): Promise<HealthStatus> {
    const res = await this.#request("GET", "/healthz", { auth: false, retry: true, signal });
    if (res.status !== 200) throw httpError(res);
    const j = parseJson(res);
    if (!isRecord(j) || typeof j.status !== "string") {
      throw new HaltSQLProtocolError("healthz body has no status", res.requestId);
    }
    return { status: j.status };
  }

  /**
   * `GET /readyz`. Resolves `{ready: false}` on a 503 not-ready answer (not
   * retried: a probe should report the current state). Rejects on network
   * errors and on any other status.
   */
  async ready(signal?: AbortSignal): Promise<ReadyStatus> {
    const res = await this.#request("GET", "/readyz", { auth: false, retry: false, signal });
    if (res.status !== 200 && res.status !== 503) throw httpError(res);
    const j = parseJson(res);
    if (!isRecord(j) || typeof j.status !== "string") {
      throw new HaltSQLProtocolError("readyz body has no status", res.requestId);
    }
    const out: ReadyStatus = { ready: res.status === 200 && j.status === "ready", status: j.status };
    if (typeof j.policies === "number") out.policies = j.policies;
    return out;
  }

  /** `GET /v1/policies`: the policies this caller may use. */
  async policies(signal?: AbortSignal): Promise<PolicySummary[]> {
    const res = await this.#request("GET", "/v1/policies", { auth: true, retry: true, signal });
    if (res.status !== 200) throw httpError(res);
    return parsePolicies(parseJson(res), res.requestId);
  }

  async #request(
    method: "GET" | "POST",
    path: string,
    o: { body?: string; auth: boolean; retry: boolean; requestId?: string | undefined; signal?: AbortSignal | undefined },
  ): Promise<RawResponse> {
    const attempts = o.retry ? this.#maxRetries + 1 : 1;
    let last: HaltSQLError | undefined;
    for (let i = 0; i < attempts; i++) {
      if (i > 0) {
        const cap = Math.min(this.#maxDelay, this.#baseDelay * 2 ** (i - 1));
        let delay = Math.floor(Math.random() * (cap + 1));
        if (last instanceof HaltSQLHttpError && retryAfter.has(last)) {
          delay = Math.min(this.#maxDelay, retryAfter.get(last)!);
        }
        try {
          await sleep(delay, o.signal);
        } catch (e) {
          throw new HaltSQLTransportError("aborted", e);
        }
      }
      try {
        const res = await this.#once(method, path, o);
        if (res.status === 503 && i + 1 < attempts) {
          last = httpError(res);
          if (res.retryAfterMs !== undefined) retryAfter.set(last, res.retryAfterMs);
          continue;
        }
        return res;
      } catch (e) {
        if (!(e instanceof HaltSQLError)) throw new HaltSQLTransportError(String(e), e);
        if (o.signal?.aborted) throw e;
        if (e.kind !== "transport" && e.kind !== "timeout") throw e;
        last = e;
      }
    }
    throw last ?? new HaltSQLTransportError("no attempt was made");
  }

  async #once(
    method: string,
    path: string,
    o: { body?: string; auth: boolean; requestId?: string | undefined; signal?: AbortSignal | undefined },
  ): Promise<RawResponse> {
    const headers: Record<string, string> = {
      ...this.#headers,
      accept: "application/json",
      "user-agent": `haltsql-client-js/${VERSION}`,
    };
    if (o.body !== undefined) headers["content-type"] = "application/json";
    if (o.auth && this.#token !== undefined) headers.authorization = `Bearer ${this.#token}`;
    if (o.requestId !== undefined) headers["x-request-id"] = o.requestId;

    const ctl = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      ctl.abort();
    }, this.#timeoutMs);
    const onAbort = () => ctl.abort();
    if (o.signal?.aborted) ctl.abort();
    o.signal?.addEventListener("abort", onAbort, { once: true });
    try {
      let resp: Response;
      try {
        const init: RequestInit & { dispatcher?: unknown } = {
          method,
          headers,
          body: o.body,
          signal: ctl.signal,
          redirect: "manual",
          cache: "no-store",
        };
        if (this.#dispatcher !== undefined) init.dispatcher = this.#dispatcher;
        resp = await this.#fetch(this.baseUrl + path, init);
      } catch (e) {
        if (timedOut) throw new HaltSQLTimeoutError(this.#timeoutMs);
        throw new HaltSQLTransportError(o.signal?.aborted ? "aborted" : describe(e), e);
      }
      const rid = resp.headers.get("x-request-id") ?? undefined;
      const declared = Number(resp.headers.get("content-length") ?? "NaN");
      if (Number.isFinite(declared) && declared > this.#maxBytes) {
        await resp.body?.cancel().catch(() => {});
        throw new HaltSQLProtocolError(`response larger than ${this.#maxBytes} bytes`, rid);
      }
      let text: string;
      try {
        text = await resp.text();
      } catch (e) {
        if (timedOut) throw new HaltSQLTimeoutError(this.#timeoutMs);
        throw new HaltSQLTransportError(`reading response: ${describe(e)}`, e);
      }
      if (Buffer.byteLength(text, "utf8") > this.#maxBytes) {
        throw new HaltSQLProtocolError(`response larger than ${this.#maxBytes} bytes`, rid);
      }
      const ra = resp.headers.get("retry-after");
      const raSec = ra !== null && /^\d{1,6}$/.test(ra) ? Number(ra) * 1000 : undefined;
      return { status: resp.status, body: text, requestId: rid, retryAfterMs: raSec };
    } finally {
      clearTimeout(timer);
      o.signal?.removeEventListener("abort", onAbort);
    }
  }
}

const retryAfter = new WeakMap<HaltSQLError, number>();

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function describe(e: unknown): string {
  if (e instanceof Error) {
    const c = (e as { cause?: unknown }).cause;
    const code = isRecord(c) && typeof c.code === "string" ? ` (${c.code})` : "";
    return e.message + code;
  }
  return String(e);
}

function parseJson(res: RawResponse): unknown {
  try {
    return JSON.parse(res.body);
  } catch {
    throw new HaltSQLProtocolError(`HTTP ${res.status} body is not JSON`, res.requestId);
  }
}

function httpError(res: RawResponse): HaltSQLHttpError {
  let code = `HTTP_${res.status}`;
  let message = "unexpected status";
  try {
    const j = JSON.parse(res.body);
    if (isRecord(j) && isRecord(j.error)) {
      if (typeof j.error.code === "string") code = j.error.code;
      if (typeof j.error.message === "string") message = j.error.message.slice(0, 500);
    }
  } catch {
    /* non-JSON error body: keep the generic code */
  }
  return new HaltSQLHttpError(res.status, code, message, res.requestId);
}

/** Constant-time comparison of two ASCII strings. */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
