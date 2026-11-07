/**
 * @haltsql/client: fail-closed client for the HaltSQL sidecar.
 *
 * ```ts
 * import { HaltSQLClient, guardedQuery } from "@haltsql/client";
 * const haltsql = new HaltSQLClient({ baseUrl: "http://127.0.0.1:8080", token: process.env.HALTSQL_TOKEN });
 * const v = await haltsql.verify(sql, { tenant_id: session.tenantId });
 * if (v.allowed) { ... }
 * ```
 */
export { HaltSQLClient, VERSION, constantTimeEqual } from "./client.js";
export type { ClientOptions, VerifyOptions } from "./client.js";
export {
  HaltSQLError,
  HaltSQLHttpError,
  HaltSQLTransportError,
  HaltSQLTimeoutError,
  HaltSQLProtocolError,
  HaltSQLUsageError,
  HaltSQLDeniedError,
} from "./errors.js";
export { bindParamsToPositional, toPgArrayLiteral } from "./params.js";
export { guardedQuery } from "./pg.js";
export type { PgQueryable, GuardedQueryOptions, GuardedQueryResult } from "./pg.js";
export { parseVerdict } from "./validate.js";
export type {
  BindParam,
  Context,
  ContextScalar,
  ContextValue,
  HealthStatus,
  PolicySummary,
  PositionalParam,
  ReadyStatus,
  Reason,
  ReasonCode,
  StatementKind,
  Verdict,
} from "./types.js";
