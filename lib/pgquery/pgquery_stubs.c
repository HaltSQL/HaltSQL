/* OCaml bindings to libpg_query (vendored, Postgres 17 grammar).
 *
 * Threading model
 * ---------------
 * libpg_query keeps parser state in thread-local memory contexts, so it is
 * thread-safe, but two properties make calling it directly from OCaml unsafe:
 *
 *  1. Its JSON writer and fingerprinter recurse over the parse tree with no
 *     stack-depth check. OCaml domains run on secondary threads, which get
 *     small stacks on macOS (512 KB), so a deep but small input such as
 *     "SELECT 1+1+1+...+1" crashes the process.
 *  2. It creates one pthread key per thread it sees, and the number of keys is
 *     limited (512 on macOS), so it cannot be called from short-lived threads.
 *
 * We therefore run every libpg_query call on a fixed pool of long-lived
 * worker threads with large stacks (PGQ_STACK_BYTES; virtual memory, only
 * touched pages are committed). Callers release the OCaml runtime lock while
 * they wait, so domains still parse in parallel. Pool size defaults to the
 * number of online CPUs and can be set with HALTSQL_PARSER_THREADS (1-64). */

#define CAML_NAME_SPACE
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/threads.h>
#include <caml/signals.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pg_query.h"
#include "src/postgres/include/pg_config.h"


#define PGQ_STACK_BYTES (256u * 1024u * 1024u)
#define PGQ_MAX_WORKERS 64

enum job_kind { JOB_PARSE, JOB_FINGERPRINT };

typedef struct job {
  enum job_kind kind;
  const char *input;
  PgQueryParseResult parse;
  PgQueryFingerprintResult fp;
  int done;
  pthread_cond_t done_cv;
  struct job *next;
} job;

static pthread_mutex_t pool_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pool_cv = PTHREAD_COND_INITIALIZER;
static job *queue_head = NULL, *queue_tail = NULL;
static pthread_once_t pool_once = PTHREAD_ONCE_INIT;
static int pool_workers = 0;

static void run_job(job *j) {
  if (j->kind == JOB_PARSE)
    j->parse = pg_query_parse(j->input);
  else
    j->fp = pg_query_fingerprint(j->input);
}

static void *worker_main(void *arg) {
  (void)arg;
  for (;;) {
    pthread_mutex_lock(&pool_mu);
    while (queue_head == NULL) pthread_cond_wait(&pool_cv, &pool_mu);
    job *j = queue_head;
    queue_head = j->next;
    if (queue_head == NULL) queue_tail = NULL;
    pthread_mutex_unlock(&pool_mu);

    run_job(j);

    pthread_mutex_lock(&pool_mu);
    j->done = 1;
    pthread_cond_signal(&j->done_cv);
    pthread_mutex_unlock(&pool_mu);
  }
  return NULL;
}

static void pool_init(void) {
  long n = sysconf(_SC_NPROCESSORS_ONLN);
  const char *env = getenv("HALTSQL_PARSER_THREADS");
  if (env != NULL) n = strtol(env, NULL, 10);
  if (n < 1) n = 1;
  if (n > PGQ_MAX_WORKERS) n = PGQ_MAX_WORKERS;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, PGQ_STACK_BYTES);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  for (long i = 0; i < n; i++) {
    pthread_t t;
    if (pthread_create(&t, &attr, worker_main, NULL) == 0) pool_workers++;
  }
  pthread_attr_destroy(&attr);
}

/* Runs the job on a big-stack worker; returns 0 on success, -1 if no worker
 * could be started (the caller then fails closed). Must be called WITHOUT the
 * OCaml runtime lock held. */
static int run_on_pool(job *j) {
  pthread_once(&pool_once, pool_init);
  if (pool_workers == 0) return -1;
  j->done = 0;
  j->next = NULL;
  pthread_cond_init(&j->done_cv, NULL);
  pthread_mutex_lock(&pool_mu);
  if (queue_tail) queue_tail->next = j; else queue_head = j;
  queue_tail = j;
  pthread_cond_signal(&pool_cv);
  while (!j->done) pthread_cond_wait(&j->done_cv, &pool_mu);
  pthread_mutex_unlock(&pool_mu);
  pthread_cond_destroy(&j->done_cv);
  return 0;
}

static value ok_string(const char *s) {
  CAMLparam0();
  CAMLlocal2(res, str);
  str = caml_copy_string(s ? s : "");
  res = caml_alloc(1, 0); /* Ok */
  Store_field(res, 0, str);
  CAMLreturn(res);
}

static value error_msg_pos(const char *msg, int pos) {
  CAMLparam0();
  CAMLlocal3(res, tup, str);
  str = caml_copy_string(msg ? msg : "unknown parse error");
  tup = caml_alloc_tuple(2);
  Store_field(tup, 0, str);
  Store_field(tup, 1, Val_int(pos));
  res = caml_alloc(1, 1); /* Error */
  Store_field(res, 0, tup);
  CAMLreturn(res);
}

static value error_msg(const char *msg) {
  CAMLparam0();
  CAMLlocal2(res, str);
  str = caml_copy_string(msg ? msg : "unknown error");
  res = caml_alloc(1, 1); /* Error */
  Store_field(res, 0, str);
  CAMLreturn(res);
}

/* Copy the OCaml string so the GC may move/free it while the lock is released.
 * Returns NULL if the string contains an embedded NUL byte. */
static char *copy_input(value v_sql) {
  mlsize_t len = caml_string_length(v_sql);
  if (memchr(String_val(v_sql), '\0', len) != NULL) return NULL;
  char *buf = malloc(len + 1);
  if (buf == NULL) return NULL;
  memcpy(buf, String_val(v_sql), len);
  buf[len] = '\0';
  return buf;
}

CAMLprim value haltsql_pgq_parse(value v_sql) {
  CAMLparam1(v_sql);
  CAMLlocal1(res);
  if (memchr(String_val(v_sql), '\0', caml_string_length(v_sql)) != NULL)
    CAMLreturn(error_msg_pos("query contains a NUL byte", 0));
  char *input = copy_input(v_sql);
  if (input == NULL) CAMLreturn(error_msg_pos("out of memory", 0));

  job j;
  memset(&j, 0, sizeof j);
  j.kind = JOB_PARSE;
  j.input = input;
  caml_release_runtime_system();
  int rc = run_on_pool(&j);
  caml_acquire_runtime_system();
  free(input);
  if (rc != 0) CAMLreturn(error_msg_pos("parser worker threads unavailable", 0));
  PgQueryParseResult r = j.parse;

  if (r.error != NULL)
    res = error_msg_pos(r.error->message, r.error->cursorpos);
  else
    res = ok_string(r.parse_tree);
  pg_query_free_parse_result(r);
  CAMLreturn(res);
}

CAMLprim value haltsql_pgq_fingerprint(value v_sql) {
  CAMLparam1(v_sql);
  CAMLlocal1(res);
  char *input = copy_input(v_sql);
  if (input == NULL) CAMLreturn(error_msg("query contains a NUL byte or out of memory"));

  job j;
  memset(&j, 0, sizeof j);
  j.kind = JOB_FINGERPRINT;
  j.input = input;
  caml_release_runtime_system();
  int rc = run_on_pool(&j);
  caml_acquire_runtime_system();
  free(input);
  if (rc != 0) CAMLreturn(error_msg("parser worker threads unavailable"));
  PgQueryFingerprintResult r = j.fp;

  if (r.error != NULL)
    res = error_msg(r.error->message);
  else
    res = ok_string(r.fingerprint_str);
  pg_query_free_fingerprint_result(r);
  CAMLreturn(res);
}

CAMLprim value haltsql_pgq_version(value unit) {
  CAMLparam1(unit);
  CAMLreturn(caml_copy_string(PG_VERSION));
}

CAMLprim value haltsql_pgq_version_num(value unit) {
  return Val_int(PG_VERSION_NUM);
}
