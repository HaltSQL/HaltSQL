import type { HaltSQLClient, VerifyOptions } from "./client.js";
import { HaltSQLDeniedError, HaltSQLUsageError } from "./errors.js";
import { bindParamsToPositional } from "./params.js";
import type { Context, Verdict } from "./types.js";

/**
 * The part of a node-postgres `Client`, `PoolClient` or `Pool` this helper
 * uses. Declared structurally so the SDK has no runtime dependency on `pg`.
 */
export interface PgQueryable<R> {
  query(text: string, values?: unknown[]): Promise<R>;
}

export interface GuardedQueryOptions extends VerifyOptions {
  /** Called with every verdict (allowed or denied) before anything runs; use it for audit logs. */
  onVerdict?: (verdict: Verdict) => void;
}

export interface GuardedQueryResult<R> {
  /** Whatever `db.query` returned (a `pg.QueryResult` for node-postgres). */
  result: R;
  /** The allow verdict the query ran under. */
  verdict: Verdict;
}

/**
 * Verifies `sql` with HaltSQL and, only if it is allowed, runs **exactly**
 * that string with node-postgres, binding `verdict.bind_params` as `$1..$n`.
 *
 * - Denied: rejects with {@link HaltSQLDeniedError}; nothing is sent to Postgres.
 * - Any HaltSQL error (timeout, 5xx, bad response): rejects; nothing runs.
 *
 * ```ts
 * const { result } = await guardedQuery(haltsql, pool,
 *   "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 50",
 *   { tenant_id: session.tenantId });
 * ```
 */
export async function guardedQuery<R>(
  haltsql: HaltSQLClient,
  db: PgQueryable<R>,
  sql: string,
  context: Context,
  opts: GuardedQueryOptions = {},
): Promise<GuardedQueryResult<R>> {
  if (db === null || typeof db !== "object" || typeof db.query !== "function") {
    throw new HaltSQLUsageError("db must have a query(text, values) method");
  }
  const { onVerdict, ...verifyOpts } = opts;
  const verdict = await haltsql.verify(sql, context, verifyOpts);
  onVerdict?.(verdict);
  if (verdict.allowed !== true) throw new HaltSQLDeniedError(verdict);
  const values = bindParamsToPositional(verdict);
  // Pass the verified string itself: never a copy that was trimmed or templated.
  const result = await db.query(sql, values);
  return { result, verdict };
}
