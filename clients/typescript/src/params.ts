import { HaltSQLUsageError } from "./errors.js";
import type { PositionalParam, Verdict } from "./types.js";

/**
 * Turns `verdict.bind_params` into the positional parameter array a Postgres
 * driver expects: element `i` is the value of placeholder `$(i+1)`.
 *
 * Fails closed: throws {@link HaltSQLUsageError} if the verdict is not an
 * allow, or if the params are not exactly `$1..$n` with each number present
 * once. A set-valued param stays a `string[]` (node-postgres sends it as a
 * Postgres array, which is what `col = ANY($n)` needs).
 */
export function bindParamsToPositional(verdict: Verdict): PositionalParam[] {
  if (verdict.allowed !== true) {
    throw new HaltSQLUsageError("refusing to build parameters for a denied verdict");
  }
  const n = verdict.bind_params.length;
  const out: (PositionalParam | undefined)[] = new Array(n).fill(undefined);
  for (const bp of verdict.bind_params) {
    if (!Number.isSafeInteger(bp.param) || bp.param < 1 || bp.param > n) {
      throw new HaltSQLUsageError(
        `bind param $${bp.param} is outside $1..$${n}; placeholders must be contiguous`,
      );
    }
    if (out[bp.param - 1] !== undefined) {
      throw new HaltSQLUsageError(`bind param $${bp.param} appears more than once`);
    }
    const v = bp.value;
    if (typeof v === "string") out[bp.param - 1] = v;
    else if (Array.isArray(v) && v.every((x) => typeof x === "string")) out[bp.param - 1] = [...v];
    else throw new HaltSQLUsageError(`bind param $${bp.param} has an invalid value`);
  }
  return out as PositionalParam[];
}

/**
 * Encodes a string array as a Postgres array literal (`{"a","b"}`), for
 * drivers that do not encode JS arrays themselves. Every element is quoted
 * and `"` / `\` are escaped, so the literal is unambiguous.
 */
export function toPgArrayLiteral(values: readonly string[]): string {
  return (
    "{" +
    values.map((v) => '"' + v.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"').join(",") +
    "}"
  );
}
