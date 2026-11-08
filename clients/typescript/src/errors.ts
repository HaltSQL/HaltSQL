import type { Verdict } from "./types.js";

/**
 * Base class of every error this SDK raises. Every error means **deny**:
 * `allowed` is always `false` so a careless `if (result.allowed)` on a caught
 * error still fails closed.
 */
export class HaltSQLError extends Error {
  /** Always `false`: an error is never an allow. */
  readonly allowed = false as const;
  /** Machine-readable kind. */
  readonly kind: "http" | "transport" | "timeout" | "protocol" | "denied" | "usage";
  /** `X-Request-Id` of the last attempt, when the server sent one. */
  readonly requestId: string | undefined;

  constructor(
    kind: HaltSQLError["kind"],
    message: string,
    options?: { cause?: unknown; requestId?: string | undefined },
  ) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = new.target.name;
    this.kind = kind;
    this.requestId = options?.requestId;
  }
}

/** The server answered with a non-200 status (`{"error":{code,message}}`). */
export class HaltSQLHttpError extends HaltSQLError {
  /** HTTP status code. */
  readonly status: number;
  /** `error.code` from the body (e.g. `UNAUTHORIZED`), or `HTTP_<status>`. */
  readonly code: string;
  constructor(status: number, code: string, message: string, requestId?: string) {
    super("http", `haltsql: HTTP ${status} ${code}: ${message}`, { requestId });
    this.status = status;
    this.code = code;
  }
}

/** The request could not be sent or the connection failed. */
export class HaltSQLTransportError extends HaltSQLError {
  constructor(message: string, cause?: unknown) {
    super("transport", `haltsql: transport error: ${message}`, { cause });
  }
}

/** An attempt did not complete within the configured timeout. */
export class HaltSQLTimeoutError extends HaltSQLError {
  constructor(timeoutMs: number) {
    super("timeout", `haltsql: request timed out after ${timeoutMs} ms`);
  }
}

/**
 * The server returned something that is not a valid verdict (bad JSON,
 * missing fields, inconsistent `allowed`, or a `sql_sha256` that does not
 * match the SQL that was sent).
 */
export class HaltSQLProtocolError extends HaltSQLError {
  constructor(message: string, requestId?: string) {
    super("protocol", `haltsql: invalid response: ${message}`, { requestId });
  }
}

/** Invalid arguments (bad context value, bad options, unusable verdict). */
export class HaltSQLUsageError extends HaltSQLError {
  constructor(message: string) {
    super("usage", `haltsql: ${message}`);
  }
}

/** Raised by the guarded-execute helpers when the policy denies the SQL. */
export class HaltSQLDeniedError extends HaltSQLError {
  readonly verdict: Verdict;
  constructor(verdict: Verdict) {
    const codes = verdict.reasons.map((r) => r.code).join(", ") || "no reasons";
    super("denied", `haltsql: denied by policy ${verdict.policy.name}: ${codes}`);
    this.verdict = verdict;
  }
  /** Reason codes, in server order. */
  get codes(): string[] {
    return this.verdict.reasons.map((r) => r.code);
  }
}
