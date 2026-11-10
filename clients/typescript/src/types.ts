/**
 * Wire types of the HaltSQL sidecar API (`haltsql.dev/v1`).
 * See docs/verdict.md and docs/openapi.yaml in the HaltSQL repository.
 */

/** A context value: a string, a safe integer, or a set of those. */
export type ContextScalar = string | number;
export type ContextValue = ContextScalar | ContextScalar[];

/**
 * Values from the caller's authenticated session (tenant id, user id, ...).
 * Never take these from the prompt or from the SQL.
 */
export type Context = Record<string, ContextValue>;

/** Stable reason code such as `E_TENANT_MISSING`. Unknown codes mean deny. */
export type ReasonCode = string;

/** One reason a statement was (or, in shadow mode, would have been) denied. */
export interface Reason {
  /** Stable code; match on this, never on `message`. */
  code: ReasonCode;
  /** Human-readable explanation. Not stable. */
  message: string;
  /** Identifier of the rule that produced the reason. Not stable. */
  rule: string;
  /** Byte offset into the SQL string, when known. */
  loc?: number;
  /** Short instruction an LLM agent can follow to fix its query. */
  hint?: string;
}

/** A value the caller must bind to placeholder `$param`. */
export interface BindParam {
  /** Placeholder number n of `$n` (1-based). */
  param: number;
  /** A string, or an array of strings when the context value is a set. */
  value: string | string[];
}

export type StatementKind = "select" | "insert" | "update" | "delete";

/** The verdict for one SQL string. */
export interface Verdict {
  /** `true` only if the caller may run this exact SQL string. */
  allowed: boolean;
  reasons: Reason[];
  /** Shadow mode only: reasons the statement would have been denied. */
  shadow_reasons: Reason[];
  /**
   * The policy that produced the verdict. `search_path` (absent from older
   * engines) lists the schemas unqualified names were resolved against: the
   * verdict holds only if the session that runs the SQL uses it.
   */
  policy: { name: string; version: string; search_path?: string[] };
  /** `null` if the SQL did not parse or is another kind of statement. */
  statement_kind: StatementKind | (string & {}) | null;
  tables: string[];
  columns: string[];
  /** Values to bind, one per `$n`. Always empty when denied. */
  bind_params: BindParam[];
  fingerprint: string | null;
  /** Lower-case hex SHA-256 of the exact SQL string. */
  sql_sha256: string;
  elapsed_us: number;
}

/** One entry of `GET /v1/policies`. */
export interface PolicySummary {
  name: string;
  version: string;
  mode: "enforce" | "shadow" | (string & {});
}

/** Body of `GET /healthz`. */
export interface HealthStatus {
  status: string;
}

/** Result of `GET /readyz`. `ready` is `true` only on HTTP 200 + "ready". */
export interface ReadyStatus {
  ready: boolean;
  status: string;
  policies?: number;
}

/** A positional driver parameter produced from a bind param. */
export type PositionalParam = string | string[];
