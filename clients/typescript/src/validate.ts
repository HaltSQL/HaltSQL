import { HaltSQLProtocolError, HaltSQLUsageError } from "./errors.js";
import type {
  BindParam,
  Context,
  PolicySummary,
  Reason,
  Verdict,
} from "./types.js";

const REASON_CODE = /^E_[A-Z_]+$/;
const HEX64 = /^[0-9a-f]{64}$/;

type Json = unknown;

function isObject(v: Json): v is Record<string, Json> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function fail(msg: string, requestId?: string): never {
  throw new HaltSQLProtocolError(msg, requestId);
}

function str(o: Record<string, Json>, k: string, path: string, rid?: string): string {
  const v = o[k];
  if (typeof v !== "string") fail(`${path}.${k} must be a string`, rid);
  return v;
}

function nonNegInt(v: Json): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function strArray(o: Record<string, Json>, k: string, rid?: string): string[] {
  const v = o[k];
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string"))
    fail(`${k} must be an array of strings`, rid);
  return v as string[];
}

function parseReason(v: Json, path: string, rid?: string): Reason {
  if (!isObject(v)) fail(`${path} must be an object`, rid);
  const code = str(v, "code", path, rid);
  if (!REASON_CODE.test(code)) fail(`${path}.code is not a reason code`, rid);
  const r: Reason = {
    code,
    message: str(v, "message", path, rid),
    rule: str(v, "rule", path, rid),
  };
  if (v.loc !== undefined) {
    if (!nonNegInt(v.loc)) fail(`${path}.loc must be a non-negative integer`, rid);
    r.loc = v.loc;
  }
  if (v.hint !== undefined) r.hint = str(v, "hint", path, rid);
  return r;
}

function parseReasons(o: Record<string, Json>, k: string, rid?: string): Reason[] {
  const v = o[k];
  if (!Array.isArray(v)) fail(`${k} must be an array`, rid);
  return v.map((x, i) => parseReason(x, `${k}[${i}]`, rid));
}

function parseBindParam(v: Json, i: number, rid?: string): BindParam {
  const path = `bind_params[${i}]`;
  if (!isObject(v)) fail(`${path} must be an object`, rid);
  const p = v.param;
  if (!nonNegInt(p) || p < 1) fail(`${path}.param must be an integer >= 1`, rid);
  const value = v.value;
  if (typeof value === "string") return { param: p, value };
  if (Array.isArray(value) && value.every((x) => typeof x === "string"))
    return { param: p, value: value as string[] };
  fail(`${path}.value must be a string or an array of strings`, rid);
}

/**
 * Strictly validates a verdict body. Any deviation from the documented shape
 * raises {@link HaltSQLProtocolError} (fail closed). Unknown extra fields are
 * ignored, as the compatibility rules require.
 */
export function parseVerdict(body: Json, requestId?: string): Verdict {
  const rid = requestId;
  if (!isObject(body)) fail("verdict must be a JSON object", rid);
  if (typeof body.allowed !== "boolean") fail("allowed must be a boolean", rid);
  const reasons = parseReasons(body, "reasons", rid);
  const shadow = parseReasons(body, "shadow_reasons", rid);
  const pol = body.policy;
  if (!isObject(pol)) fail("policy must be an object", rid);
  const policy = {
    name: str(pol, "name", "policy", rid),
    version: str(pol, "version", "policy", rid),
  };
  const sk = body.statement_kind;
  if (sk !== null && typeof sk !== "string") fail("statement_kind must be a string or null", rid);
  const bp = body.bind_params;
  if (!Array.isArray(bp)) fail("bind_params must be an array", rid);
  const fp = body.fingerprint;
  if (fp !== null && typeof fp !== "string") fail("fingerprint must be a string or null", rid);
  const sha = str(body, "sql_sha256", "verdict", rid);
  if (!HEX64.test(sha)) fail("sql_sha256 must be 64 lower-case hex digits", rid);
  if (!nonNegInt(body.elapsed_us)) fail("elapsed_us must be a non-negative integer", rid);
  const allowed = body.allowed;
  // In every mode an allow carries no blocking reasons. A body that says
  // otherwise is inconsistent and must not be trusted.
  if (allowed && reasons.length > 0) fail("allowed is true but reasons is not empty", rid);
  return {
    allowed,
    reasons,
    shadow_reasons: shadow,
    policy,
    statement_kind: sk,
    tables: strArray(body, "tables", rid),
    columns: strArray(body, "columns", rid),
    bind_params: bp.map((x, i) => parseBindParam(x, i, rid)),
    fingerprint: fp,
    sql_sha256: sha,
    elapsed_us: body.elapsed_us,
  };
}

/** Validates a `GET /v1/policies` body. */
export function parsePolicies(body: Json, requestId?: string): PolicySummary[] {
  if (!isObject(body) || !Array.isArray(body.policies)) fail("policies must be an array", requestId);
  return body.policies.map((p, i) => {
    if (!isObject(p)) fail(`policies[${i}] must be an object`, requestId);
    const path = `policies[${i}]`;
    return {
      name: str(p, "name", path, requestId),
      version: str(p, "version", path, requestId),
      mode: str(p, "mode", path, requestId),
    };
  });
}

/** Validates a context object before it is sent. */
export function checkContext(ctx: unknown): Context {
  if (ctx === undefined) return {};
  if (!isObject(ctx)) throw new HaltSQLUsageError("context must be a plain object");
  const scalarOk = (v: unknown) =>
    typeof v === "string" || (typeof v === "number" && Number.isSafeInteger(v));
  for (const [k, v] of Object.entries(ctx)) {
    if (scalarOk(v)) continue;
    if (Array.isArray(v) && v.every(scalarOk)) continue;
    throw new HaltSQLUsageError(
      `context.${k} must be a string, a safe integer, or an array of those`,
    );
  }
  return ctx as Context;
}
