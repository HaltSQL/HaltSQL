import type { VerifyOptions } from "./client.js";
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

/** A client checked out of a pool: node-postgres' `PoolClient`. */
export interface PgPoolClient<R> extends PgQueryable<R> {
  /** Returns the client to the pool; a truthy argument destroys it instead. */
  release(err?: Error | boolean): void;
}

/** The part of a node-postgres `Pool` that {@link guardedTransaction} uses. */
export interface PgPool<R> {
  connect(): Promise<PgPoolClient<R>>;
}

/**
 * Anything that verifies SQL: a {@link HaltSQLClient} (sidecar) or a
 * {@link LocalVerifier} (bundled engine; it ignores the per-call options).
 */
export interface SqlVerifier {
  verify(sql: string, context?: Context, opts?: VerifyOptions): Promise<Verdict>;
}

export interface GuardedQueryOptions extends VerifyOptions {
  /** Called with every verdict (allowed or denied) before anything runs; use it for audit logs. */
  onVerdict?: (verdict: Verdict) => void;
  /**
   * Run SQL that a shadow-mode policy would deny (`allowed: true` with
   * `shadow_reasons`). Default `false`: such a verdict is rejected with
   * {@link HaltSQLDeniedError}, so switching a policy to shadow on the server
   * cannot by itself turn enforcement off in this application.
   */
  allowShadow?: boolean;
}

export interface GuardedTransactionOptions extends GuardedQueryOptions {
  /**
   * Extra transaction-local settings, applied with `set_config(name, value,
   * true)` before the query: for example `{ "app.tenant_id": tenantId }` for
   * row-level security, or `{ statement_timeout: "5000" }`. A `search_path`
   * given here has no effect when the verdict reports one: the pin is applied
   * last.
   */
  settings?: Record<string, string>;
}

export interface GuardedQueryResult<R> {
  /** Whatever `db.query` returned (a `pg.QueryResult` for node-postgres). */
  result: R;
  /** The allow verdict the query ran under. */
  verdict: Verdict;
}

/** Verifies, and returns the verdict and its positional values only if the SQL may run. */
async function authorize(
  haltsql: SqlVerifier,
  sql: string,
  context: Context,
  opts: GuardedQueryOptions,
): Promise<{ verdict: Verdict; values: unknown[] }> {
  const { onVerdict, allowShadow, ...verifyOpts } = opts;
  const verdict = await haltsql.verify(sql, context, verifyOpts);
  onVerdict?.(verdict);
  if (verdict.allowed !== true) throw new HaltSQLDeniedError(verdict);
  if (allowShadow !== true && verdict.shadow_reasons.length > 0) {
    throw new HaltSQLDeniedError(verdict);
  }
  const values = bindParamsToPositional(verdict);
  return { verdict, values };
}

/**
 * Low-level form: verifies `sql` with HaltSQL and, only if it is allowed, runs
 * **exactly** that string with one `db.query` call, binding
 * `verdict.bind_params` as `$1..$n`.
 *
 * **This function does not pin the search path.** The verifier resolved
 * unqualified table names against `verdict.policy.search_path`; this function
 * sends one statement on whatever session `db` gives it, so a role or database
 * default (`ALTER ROLE ... SET search_path`) can make a verified `orders` read
 * a different table than the one the policy lists. Use it only when
 *
 * - the session already uses the policy's search path (you set it on the
 *   connection, the role or the database), or
 * - the SQL names every table with its schema.
 *
 * Otherwise use {@link guardedTransaction}, which pins the search path.
 *
 * - Denied: rejects with {@link HaltSQLDeniedError}; nothing is sent to Postgres.
 * - Any HaltSQL error (timeout, 5xx, bad response): rejects; nothing runs.
 *
 * ```ts
 * const { result } = await guardedQuery(haltsql, client,
 *   "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 50",
 *   { tenant_id: session.tenantId });
 * ```
 */
export async function guardedQuery<R>(
  haltsql: SqlVerifier,
  db: PgQueryable<R>,
  sql: string,
  context: Context,
  opts: GuardedQueryOptions = {},
): Promise<GuardedQueryResult<R>> {
  if (db === null || typeof db !== "object" || typeof db.query !== "function") {
    throw new HaltSQLUsageError("db must have a query(text, values) method");
  }
  const { verdict, values } = await authorize(haltsql, sql, context, opts);
  // Pass the verified string itself: never a copy that was trimmed or templated.
  const result = await db.query(sql, values);
  return { result, verdict };
}

const SETTING_NAME = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/;

function settingsList(settings: unknown): [string, string][] {
  if (settings === undefined) return [];
  if (settings === null || typeof settings !== "object" || Array.isArray(settings)) {
    throw new HaltSQLUsageError("settings must be an object of string values");
  }
  const out: [string, string][] = [];
  for (const [name, value] of Object.entries(settings)) {
    if (!SETTING_NAME.test(name)) {
      throw new HaltSQLUsageError(`invalid setting name: ${JSON.stringify(name)}`);
    }
    if (typeof value !== "string") {
      throw new HaltSQLUsageError(`setting ${JSON.stringify(name)} must be a string`);
    }
    out.push([name, value]);
  }
  return out;
}

/**
 * The value that pins a verdict's search path: each schema of
 * `verdict.policy.search_path` double-quoted (embedded quotes doubled), joined
 * with `, `. `undefined` when the engine did not report a search path.
 *
 * {@link guardedTransaction} applies it for you. If you run verified SQL
 * yourself, execute `SELECT set_config('search_path', $1, true)` with this
 * value in the same transaction, before the verified statement.
 */
export function searchPathSetting(verdict: Verdict): string | undefined {
  const sp = verdict.policy.search_path;
  if (sp === undefined) return undefined;
  return sp.map((schema) => '"' + schema.replace(/"/g, '""') + '"').join(", ");
}

/** The transaction failed and so did its ROLLBACK: the session state is unknown. */
class RollbackFailed {
  constructor(
    readonly cause: unknown,
    readonly rollbackError: unknown,
  ) {}
}

/** BEGIN, settings, pin, the verified statement, COMMIT; ROLLBACK on any error. */
async function runPinned<R>(
  client: PgQueryable<R>,
  sql: string,
  verdict: Verdict,
  values: unknown[],
  settings: [string, string][],
): Promise<R> {
  const pin = searchPathSetting(verdict);
  // The pin goes last so that it wins over a search_path in `settings`.
  const all: [string, string][] = pin === undefined ? settings : [...settings, ["search_path", pin]];
  await client.query(verdict.statement_kind === "select" ? "BEGIN READ ONLY" : "BEGIN");
  try {
    for (const [name, value] of all) {
      await client.query("SELECT set_config($1, $2, true)", [name, value]);
    }
    // Pass the verified string itself: never a copy that was trimmed or templated.
    const result = await client.query(sql, values);
    await client.query("COMMIT");
    return result;
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      throw new RollbackFailed(e, rollbackError);
    }
    throw e;
  }
}

/**
 * Verifies `sql` and, only if it is allowed, runs **exactly** that string in a
 * transaction that uses the verdict's search path. Use this form unless you
 * have a reason not to.
 *
 * `pool` is a node-postgres `Pool` (anything whose `connect()` resolves to a
 * client with `query` and `release`). A transaction needs one session and
 * `pool.query` may use a different one for each statement, so this function
 * checks out a client for the transaction and releases it afterwards. To use a
 * client you already hold, call {@link guardedTransactionOnClient}.
 *
 * On the checked-out client it sends, in order:
 *
 * 1. `BEGIN READ ONLY` when `verdict.statement_kind` is `select`, else `BEGIN`;
 * 2. `SELECT set_config(name, value, true)` for each entry of `opts.settings`;
 * 3. `SELECT set_config('search_path', <verdict.policy.search_path>, true)`,
 *    every schema quoted as an identifier. It is transaction-local: the
 *    session's own search path is back after the transaction. Skipped when the
 *    verdict has no `search_path` (an engine older than the field);
 * 4. the verified string, unchanged, with `verdict.bind_params` as `$1..$n`;
 * 5. `COMMIT`. On any error it sends `ROLLBACK` and rethrows the error.
 *
 * Denied, shadow would-deny (without `allowShadow`) or any HaltSQL error:
 * rejects before a client is checked out; nothing is sent to Postgres.
 *
 * ```ts
 * const { result } = await guardedTransaction(haltsql, pool,
 *   "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 50",
 *   { tenant_id: session.tenantId });
 * ```
 */
export async function guardedTransaction<R>(
  haltsql: SqlVerifier,
  pool: PgPool<R>,
  sql: string,
  context: Context,
  opts: GuardedTransactionOptions = {},
): Promise<GuardedQueryResult<R>> {
  if (pool === null || typeof pool !== "object" || typeof pool.connect !== "function") {
    throw new HaltSQLUsageError("pool must have a connect() method (a pg.Pool)");
  }
  const { settings, ...guardOpts } = opts;
  const list = settingsList(settings);
  const { verdict, values } = await authorize(haltsql, sql, context, guardOpts);
  const client = await pool.connect();
  if (
    client === null ||
    typeof client !== "object" ||
    typeof client.query !== "function" ||
    typeof client.release !== "function"
  ) {
    throw new HaltSQLUsageError(
      "pool.connect() must resolve to a client with query() and release(); " +
        "for a single pg.Client use guardedTransactionOnClient",
    );
  }
  let broken: unknown;
  try {
    const result = await runPinned(client, sql, verdict, values, list);
    return { result, verdict };
  } catch (e) {
    if (e instanceof RollbackFailed) {
      // The session may still be inside the failed transaction: do not reuse it.
      broken = e.rollbackError;
      throw e.cause;
    }
    throw e;
  } finally {
    client.release(broken === undefined ? undefined : broken instanceof Error ? broken : true);
  }
}

/**
 * {@link guardedTransaction} on a client you already hold: a connected
 * `pg.Client`, or a `PoolClient` you checked out (and will release) yourself.
 *
 * The client must be idle: not inside a transaction and with no query in
 * flight, because this function sends its own `BEGIN` and `COMMIT`. A
 * `pg.Pool` is refused: its `query()` may run each statement on a different
 * session. If the `ROLLBACK` after a failure fails too, the original error is
 * rethrown and you should discard the client.
 */
export async function guardedTransactionOnClient<R>(
  haltsql: SqlVerifier,
  client: PgQueryable<R>,
  sql: string,
  context: Context,
  opts: GuardedTransactionOptions = {},
): Promise<GuardedQueryResult<R>> {
  if (client === null || typeof client !== "object" || typeof client.query !== "function") {
    throw new HaltSQLUsageError("client must have a query(text, values) method");
  }
  const poolLike = client as { totalCount?: unknown; idleCount?: unknown };
  if (typeof poolLike.totalCount === "number" || typeof poolLike.idleCount === "number") {
    throw new HaltSQLUsageError(
      "a pool cannot run a transaction through query(); pass it to guardedTransaction",
    );
  }
  const { settings, ...guardOpts } = opts;
  const list = settingsList(settings);
  const { verdict, values } = await authorize(haltsql, sql, context, guardOpts);
  try {
    const result = await runPinned(client, sql, verdict, values, list);
    return { result, verdict };
  } catch (e) {
    throw e instanceof RollbackFailed ? e.cause : e;
  }
}
