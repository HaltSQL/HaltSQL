/* ABI-level tests for libhaltsql (include/haltsql.h).
 *
 * The library is dlopen()ed exactly as the Python and Node bindings do, so this also
 * checks that the shared object is self-contained and exports the documented symbols.
 * Threads here are plain pthreads the OCaml runtime has never seen, which is the
 * situation a host application creates.
 *
 * usage: test_capi LIBHALTSQL POLICY.yaml */

#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "haltsql.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...)                                    \
  do {                                                      \
    __sync_fetch_and_add(&checks, 1);                       \
    if (!(cond)) {                                          \
      __sync_fetch_and_add(&failures, 1);                   \
      fprintf(stderr, "FAIL %s:%d: %s: ", __FILE__, __LINE__, #cond); \
      fprintf(stderr, __VA_ARGS__);                         \
      fputc('\n', stderr);                                  \
    }                                                       \
  } while (0)

static int (*p_abi)(void);
static char *(*p_version)(void);
static haltsql_policy (*p_load_file)(const char *, char **);
static haltsql_policy (*p_load_string)(const char *, size_t, const char *, const char *,
                                       char **);
static char *(*p_info)(haltsql_policy);
static void (*p_free)(haltsql_policy);
static char *(*p_verify)(haltsql_policy, const char *, size_t, const char *, size_t);
static void (*p_sfree)(char *);

static const char *policy_path;

static void *sym(void *h, const char *name) {
  void *p = dlsym(h, name);
  if (p == NULL) {
    fprintf(stderr, "missing symbol %s: %s\n", name, dlerror());
    exit(2);
  }
  return p;
}

static int contains(const char *s, const char *needle) {
  return s != NULL && strstr(s, needle) != NULL;
}

static char *verify_s(haltsql_policy h, const char *sql, const char *ctx) {
  return p_verify(h, sql, strlen(sql), ctx, ctx ? strlen(ctx) : 0);
}

static const char *ALLOW_SQL = "SELECT id FROM orders WHERE tenant_id = 'acme' LIMIT 10";
static const char *ALLOW_SHA =
    "\"sql_sha256\":\"23764575137d4bdc1b8b7a6d16d3c54f945d405d82b4658ea8e2e10ef594d91d\"";
static const char *CTX = "{\"tenant_id\":\"acme\"}";

static void test_basics(void) {
  CHECK(p_abi() == HALTSQL_ABI_VERSION, "abi %d", p_abi());
  char *v = p_version();
  CHECK(v != NULL && strlen(v) > 0, "version");
  p_sfree(v);
  p_sfree(NULL); /* must be a no-op */
}

static void test_load_errors(void) {
  char *err = (char *)1;
  haltsql_policy h = p_load_file("/nonexistent/policy.yaml", &err);
  CHECK(h == 0, "missing file handle %lld", (long long)h);
  CHECK(contains(err, "not found"), "missing file err: %s", err ? err : "(null)");
  p_sfree(err);

  /* NULL err_out must be accepted on failure and success. */
  CHECK(p_load_file("/nonexistent/policy.yaml", NULL) == 0, "missing file, NULL err");
  CHECK(p_load_file(NULL, NULL) == 0, "NULL path");

  err = NULL;
  const char *bad = "apiVersion: haltsql.dev/v1\nname: x\nbogus_key: 1\n";
  h = p_load_string(bad, strlen(bad), "yaml", NULL, &err);
  CHECK(h == 0, "invalid policy accepted");
  CHECK(contains(err, "cannot load policy"), "invalid policy err: %s", err ? err : "(null)");
  p_sfree(err);

  err = NULL;
  h = p_load_string("{}", 2, "toml", NULL, &err);
  CHECK(h == 0 && contains(err, "format"), "bad format: %s", err ? err : "(null)");
  p_sfree(err);

  err = NULL;
  h = p_load_string("{not json", 9, "json", NULL, &err);
  CHECK(h == 0 && err != NULL, "malformed json policy");
  p_sfree(err);

  CHECK(p_load_string(NULL, 0, "yaml", NULL, NULL) == 0, "NULL doc");
  CHECK(p_load_string("x", 1, NULL, NULL, NULL) == 0, "NULL format");
}

static char *slurp(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = malloc((size_t)n + 1);
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
    fclose(f);
    free(buf);
    return NULL;
  }
  buf[n] = '\0';
  fclose(f);
  *len = (size_t)n;
  return buf;
}

static void test_verify(void) {
  char *err = NULL;
  haltsql_policy h = p_load_file(policy_path, &err);
  CHECK(h > 0 && err == NULL, "load: %s", err ? err : "(null)");
  if (h <= 0) return;

  char *info = p_info(h);
  CHECK(contains(info, "\"name\":\"saas-literal\"") && contains(info, "\"mode\":\"enforce\"") &&
            contains(info, "\"version\":\"sha256:"),
        "info: %s", info ? info : "(null)");
  p_sfree(info);

  char *r = verify_s(h, ALLOW_SQL, CTX);
  CHECK(contains(r, "\"allowed\":true") && contains(r, ALLOW_SHA), "allow: %s", r);
  p_sfree(r);

  /* Same SQL, other tenant: denied. */
  r = verify_s(h, ALLOW_SQL, "{\"tenant_id\":\"globex\"}");
  CHECK(contains(r, "\"allowed\":false"), "other tenant: %s", r);
  p_sfree(r);

  /* No context at all (NULL and empty): the tenancy proof cannot hold. */
  r = verify_s(h, ALLOW_SQL, NULL);
  CHECK(contains(r, "\"allowed\":false") && contains(r, "E_CONTEXT_MISSING"), "NULL ctx: %s", r);
  p_sfree(r);
  r = p_verify(h, ALLOW_SQL, strlen(ALLOW_SQL), "", 0);
  CHECK(contains(r, "\"allowed\":false"), "empty ctx: %s", r);
  p_sfree(r);
  r = verify_s(h, ALLOW_SQL, "null");
  CHECK(contains(r, "\"allowed\":false"), "null ctx: %s", r);
  p_sfree(r);

  /* Malformed / wrongly typed context: an error object, never a verdict. */
  r = verify_s(h, ALLOW_SQL, "{\"tenant_id\":");
  CHECK(contains(r, "\"error\"") && !contains(r, "\"allowed\""), "bad ctx json: %s", r);
  p_sfree(r);
  r = verify_s(h, ALLOW_SQL, "{\"tenant_id\":true}");
  CHECK(contains(r, "\"error\"") && !contains(r, "\"allowed\""), "bad ctx type: %s", r);
  p_sfree(r);
  r = verify_s(h, ALLOW_SQL, "[1,2]");
  CHECK(contains(r, "\"error\""), "ctx array: %s", r);
  p_sfree(r);

  /* An embedded NUL must not truncate the SQL to its allowed prefix. */
  const char nul_sql[] = "SELECT id FROM orders WHERE tenant_id = 'acme' LIMIT 10\0; DROP TABLE orders";
  r = p_verify(h, nul_sql, sizeof(nul_sql) - 1, CTX, strlen(CTX));
  CHECK(contains(r, "\"allowed\":false") && !contains(r, ALLOW_SHA), "NUL sql: %s", r);
  p_sfree(r);

  /* Empty SQL, NULL SQL with length 0, NULL SQL with a length. */
  r = p_verify(h, "", 0, CTX, strlen(CTX));
  CHECK(contains(r, "\"allowed\":false"), "empty sql: %s", r);
  p_sfree(r);
  r = p_verify(h, NULL, 0, CTX, strlen(CTX));
  CHECK(contains(r, "\"allowed\":false"), "NULL sql len 0: %s", r);
  p_sfree(r);
  CHECK(p_verify(h, NULL, 5, CTX, strlen(CTX)) == NULL, "NULL sql with length");

  /* Oversized SQL is denied by the size limit, not crashed on. */
  size_t big = 1 << 20;
  char *huge = malloc(big + 1);
  memset(huge, ' ', big);
  memcpy(huge, ALLOW_SQL, strlen(ALLOW_SQL));
  huge[big] = '\0';
  r = p_verify(h, huge, big, CTX, strlen(CTX));
  CHECK(contains(r, "\"allowed\":false"), "huge sql");
  p_sfree(r);
  free(huge);

  /* Multi-statement and invalid UTF-8 bytes. */
  r = verify_s(h, "SELECT 1; SELECT 2", CTX);
  CHECK(contains(r, "E_MULTI_STATEMENT"), "multi: %s", r);
  p_sfree(r);
  r = verify_s(h, "SELECT \xff\xfe FROM orders", CTX);
  CHECK(contains(r, "\"allowed\":false"), "invalid utf8: %s", r);
  p_sfree(r);

  /* Loading the same document from memory gives the same policy version. */
  size_t len = 0;
  char *doc = slurp(policy_path, &len);
  CHECK(doc != NULL, "read policy");
  if (doc) {
    char *dir = strdup(policy_path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = '\0';
    haltsql_policy h2 = p_load_string(doc, len, "yaml", dir, &err);
    CHECK(h2 > 0 && h2 != h, "load_string: %s", err ? err : "(null)");
    char *i1 = p_info(h), *i2 = p_info(h2);
    CHECK(i1 && i2 && strcmp(i1, i2) == 0, "info differs: %s vs %s", i1, i2);
    p_sfree(i1);
    p_sfree(i2);
    p_free(h2);
    free(dir);
    free(doc);
  }

  p_free(h);
  /* Freed and never-issued handles: info is NULL, verify is an error object. */
  CHECK(p_info(h) == NULL, "info after free");
  r = verify_s(h, ALLOW_SQL, CTX);
  CHECK(contains(r, "\"error\"") && !contains(r, "\"allowed\""), "verify after free: %s", r);
  p_sfree(r);
  r = verify_s(0, ALLOW_SQL, CTX);
  CHECK(contains(r, "\"error\""), "handle 0: %s", r);
  p_sfree(r);
  r = verify_s(-7, ALLOW_SQL, CTX);
  CHECK(contains(r, "\"error\""), "negative handle: %s", r);
  p_sfree(r);
  p_free(h);  /* double free is ignored */
  p_free(0);
  p_free(-1);
}

/* ---- concurrency ---- */

#define THREADS 16
#define ITERS 1500

static haltsql_policy shared_h;

static void *hammer(void *arg) {
  long id = (long)arg;
  for (int i = 0; i < ITERS; i++) {
    int allow = ((i + id) % 2) == 0;
    const char *ctx = allow ? CTX : "{\"tenant_id\":\"globex\"}";
    char *r = verify_s(shared_h, ALLOW_SQL, ctx);
    if (allow)
      CHECK(contains(r, "\"allowed\":true") && contains(r, ALLOW_SHA), "t%ld i%d allow", id, i);
    else
      CHECK(contains(r, "\"allowed\":false"), "t%ld i%d deny", id, i);
    p_sfree(r);
  }
  return NULL;
}

/* Threads that load, use and free their own policies while others verify. */
static void *churn(void *arg) {
  long id = (long)arg;
  for (int i = 0; i < 60; i++) {
    char *err = NULL;
    haltsql_policy h = p_load_file(policy_path, &err);
    CHECK(h > 0, "churn t%ld load: %s", id, err ? err : "(null)");
    p_sfree(err);
    char *r = verify_s(h, ALLOW_SQL, CTX);
    CHECK(contains(r, "\"allowed\":true"), "churn t%ld verify", id);
    p_sfree(r);
    p_free(h);
    r = verify_s(h, ALLOW_SQL, CTX);
    CHECK(contains(r, "\"error\""), "churn t%ld after free", id);
    p_sfree(r);
  }
  return NULL;
}

/* Many short-lived threads, each making a single call: threads stay registered with
 * the runtime after they exit, which must stay harmless. */
static void *one_call(void *arg) {
  (void)arg;
  char *r = verify_s(shared_h, ALLOW_SQL, CTX);
  CHECK(contains(r, "\"allowed\":true"), "short-lived thread");
  p_sfree(r);
  return NULL;
}

static void test_short_lived_threads(void) {
  shared_h = p_load_file(policy_path, NULL);
  CHECK(shared_h > 0, "load for short-lived threads");
  for (int round = 0; round < 50; round++) {
    pthread_t t[8];
    for (int i = 0; i < 8; i++) pthread_create(&t[i], NULL, one_call, NULL);
    for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);
  }
  p_free(shared_h);
}

static void test_threads(void) {
  shared_h = p_load_file(policy_path, NULL);
  CHECK(shared_h > 0, "load shared");
  pthread_t t[THREADS + 4];
  for (long i = 0; i < THREADS; i++) pthread_create(&t[i], NULL, hammer, (void *)i);
  for (long i = 0; i < 4; i++) pthread_create(&t[THREADS + i], NULL, churn, (void *)i);
  for (int i = 0; i < THREADS + 4; i++) pthread_join(t[i], NULL);
  p_free(shared_h);
}

/* First-ever call from a non-main thread must also work (lazy runtime init). This runs
 * in a fresh process via re-exec so the runtime really is uninitialized. */
static void *first_call(void *arg) {
  (void)arg;
  char *r = NULL;
  haltsql_policy h = p_load_file(policy_path, NULL);
  if (h > 0) r = verify_s(h, ALLOW_SQL, CTX);
  CHECK(contains(r, "\"allowed\":true"), "first call from thread: %s", r ? r : "(null)");
  p_sfree(r);
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s LIBHALTSQL POLICY [--thread-first]\n", argv[0]);
    return 2;
  }
  policy_path = argv[2];
  void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (lib == NULL) {
    fprintf(stderr, "dlopen %s: %s\n", argv[1], dlerror());
    return 2;
  }
  p_abi = sym(lib, "haltsql_abi_version");
  p_version = sym(lib, "haltsql_version");
  p_load_file = sym(lib, "haltsql_policy_load_file");
  p_load_string = sym(lib, "haltsql_policy_load_string");
  p_info = sym(lib, "haltsql_policy_info");
  p_free = sym(lib, "haltsql_policy_free");
  p_verify = sym(lib, "haltsql_verify");
  p_sfree = sym(lib, "haltsql_string_free");

  if (argc > 3 && strcmp(argv[3], "--thread-first") == 0) {
    pthread_t t;
    pthread_create(&t, NULL, first_call, NULL);
    pthread_join(t, NULL);
    /* and the main thread afterwards */
    first_call(NULL);
  } else {
    test_basics();
    test_load_errors();
    test_verify();
    test_threads();
    test_short_lived_threads();
  }
  printf("libhaltsql ABI tests: %d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
