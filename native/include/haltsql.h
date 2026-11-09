/* libhaltsql: in-process HaltSQL verification through a tiny, stable C ABI.
 *
 * The whole verification engine (the OCaml analyzer, the OCaml runtime and the vendored
 * libpg_query parser) is linked into one self-contained shared library. Language
 * bindings (Python ctypes, Node N-API, ...) dlopen it; no sidecar, no subprocess.
 *
 * Data crosses the boundary as UTF-8 JSON so the ABI never changes when verdicts grow
 * new fields. Every string returned by the library is heap-allocated and must be freed
 * with haltsql_string_free().
 *
 * Fail-closed contract (same as every HaltSQL client):
 *   - haltsql_verify() returns the verdict object exactly as the sidecar's
 *     POST /v1/verify does, or {"error": "..."} for a malformed request. It returns
 *     NULL only if the library could not allocate memory or is unusable; callers MUST
 *     treat NULL, an "error" object and any parse failure as a denial.
 *
 * Threading: every entry point may be called from any thread, concurrently. The OCaml
 * runtime lock means only one thread runs engine code at a time (threads interleave
 * at safepoints), so throughput is about one core: verification is ~10-100us, which
 * is ample for in-process use; run haltsql-server for heavy multi-core throughput.
 * A thread is registered with the runtime on its first call and stays registered (a
 * few hundred bytes per distinct OS thread; thread pools keep this bounded).
 *
 * ABI version: bumped only on incompatible changes. Bindings check
 * haltsql_abi_version() == HALTSQL_ABI_VERSION before use.
 */
#ifndef HALTSQL_H
#define HALTSQL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HALTSQL_ABI_VERSION 1

/* Opaque policy handle. 0 is never a valid handle. */
typedef int64_t haltsql_policy;

/* Returns HALTSQL_ABI_VERSION of the compiled library. Never fails. */
int haltsql_abi_version(void);

/* HaltSQL release version (e.g. "0.1.0"). Caller frees with haltsql_string_free. */
char *haltsql_version(void);

/* Loads a policy file (YAML or JSON, by extension). On success returns a handle > 0
 * and sets *err_out to NULL. On failure returns 0 and, if err_out is non-NULL, sets
 * *err_out to a human-readable message (free with haltsql_string_free). */
haltsql_policy haltsql_policy_load_file(const char *path, char **err_out);

/* Loads a policy from an in-memory document. format is "yaml" or "json". base_dir
 * resolves a relative `catalog:` path (may be NULL). Same return convention as
 * haltsql_policy_load_file. */
haltsql_policy haltsql_policy_load_string(const char *doc, size_t doc_len,
                                          const char *format, const char *base_dir,
                                          char **err_out);

/* {"name": ..., "version": "sha256:...", "mode": "enforce"|"shadow"} for a handle,
 * or NULL for an unknown handle. Caller frees. */
char *haltsql_policy_info(haltsql_policy policy);

/* Releases a policy handle. Unknown handles are ignored. */
void haltsql_policy_free(haltsql_policy policy);

/* Verifies one SQL string. context_json is a JSON object of context fields (may be
 * NULL or empty for no context). Returns verdict JSON (see header comment). The SQL
 * may contain NUL bytes; its length is sql_len. Caller frees. */
char *haltsql_verify(haltsql_policy policy, const char *sql, size_t sql_len,
                     const char *context_json, size_t context_len);

/* Frees a string returned by this library. NULL is ignored. */
void haltsql_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* HALTSQL_H */
