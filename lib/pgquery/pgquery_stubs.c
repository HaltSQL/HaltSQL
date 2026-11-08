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
 * number of online CPUs and can be set with HALTSQL_PARSER_THREADS (1-64).
 * The pool is started lazily on first use, and restarted lazily in a child
 * process after fork() (see pool_atfork_child).
 *
 * Memory and runtime-lock rules
 * -----------------------------
 *  - The SQL text is copied to a malloc'd buffer before the runtime lock is
 *    released, because the GC may move or free the OCaml string meanwhile; no
 *    OCaml value is touched while the lock is released.
 *  - Every PgQuery*Result is freed with its pg_query_free_* function on every
 *    path, after its contents have been copied into OCaml values.
 *  - Inputs with an embedded NUL byte are rejected: libpg_query takes C
 *    strings, so a NUL would silently truncate the query and could hide a
 *    second statement from the parser. */

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

/* Pool state. Everything below is protected by [pool_mu]. */
static pthread_mutex_t pool_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pool_cv = PTHREAD_COND_INITIALIZER;
static job *queue_head = NULL, *queue_tail = NULL;
static int pool_started = 0; /* pool_start has run in this process */
static int pool_workers = 0; /* worker threads alive in this process */
static pthread_once_t atfork_once = PTHREAD_ONCE_INIT;

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

    /* After this signal the waiter may return and pop [j] off its stack, so
     * [j] must not be touched once the mutex is released. */
    pthread_mutex_lock(&pool_mu);
    j->done = 1;
    pthread_cond_signal(&j->done_cv);
    pthread_mutex_unlock(&pool_mu);
  }
  return NULL;
}

/* fork() copies only the calling thread, so a child process has no workers,
 * and [pool_mu] may have been copied while held by a thread that no longer
 * exists. Holding [pool_mu] across fork() (prepare/parent handlers) keeps the
 * queue consistent; the child then starts from an empty, unstarted pool and
 * lazily creates its own workers on first use. Without this, a child that
 * parses would enqueue its job and wait forever. Jobs queued by other parent
 * threads are dropped in the child: their waiters do not exist there. */
static void pool_atfork_prepare(void) { pthread_mutex_lock(&pool_mu); }
static void pool_atfork_parent(void) { pthread_mutex_unlock(&pool_mu); }
static void pool_atfork_child(void) {
  pthread_mutex_init(&pool_mu, NULL);
  pthread_cond_init(&pool_cv, NULL);
  queue_head = queue_tail = NULL;
  pool_started = 0;
  pool_workers = 0;
}
static void pool_register_atfork(void) {
  pthread_atfork(pool_atfork_prepare, pool_atfork_parent, pool_atfork_child);
}

/* Starts the workers. Called with [pool_mu] held; new workers block on the
 * mutex until the caller releases it. */
static void pool_start_locked(void) {
  long n = sysconf(_SC_NPROCESSORS_ONLN);
  const char *env = getenv("HALTSQL_PARSER_THREADS");
  if (env != NULL) n = strtol(env, NULL, 10);
  if (n < 1) n = 1;
  if (n > PGQ_MAX_WORKERS) n = PGQ_MAX_WORKERS;

  pthread_attr_t attr;
  if (pthread_attr_init(&attr) != 0) return;
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
  pthread_once(&atfork_once, pool_register_atfork);
  j->done = 0;
  j->next = NULL;
  if (pthread_cond_init(&j->done_cv, NULL) != 0) return -1;
  pthread_mutex_lock(&pool_mu);
  if (!pool_started) {
    pool_started = 1;
    pool_start_locked();
  }
  if (pool_workers == 0) {
    pthread_mutex_unlock(&pool_mu);
    pthread_cond_destroy(&j->done_cv);
    return -1;
  }
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

static int has_nul(value v_sql) {
  return memchr(String_val(v_sql), '\0', caml_string_length(v_sql)) != NULL;
}

/* Copy the OCaml string (length from the OCaml header, never strlen) so the
 * GC may move or free it while the runtime lock is released. Returns NULL on
 * allocation failure. Callers reject embedded NUL bytes first (has_nul). */
static char *copy_input(value v_sql) {
  mlsize_t len = caml_string_length(v_sql);
  char *buf = malloc(len + 1);
  if (buf == NULL) return NULL;
  memcpy(buf, String_val(v_sql), len);
  buf[len] = '\0';
  return buf;
}

CAMLprim value haltsql_pgq_parse(value v_sql) {
  CAMLparam1(v_sql);
  CAMLlocal1(res);
  if (has_nul(v_sql)) CAMLreturn(error_msg_pos("query contains a NUL byte", 0));
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

  /* If copying into the OCaml heap raises Out_of_memory, [r] leaks. The
   * process is out of memory at that point anyway and the caller denies. */
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
  if (has_nul(v_sql)) CAMLreturn(error_msg("query contains a NUL byte"));
  char *input = copy_input(v_sql);
  if (input == NULL) CAMLreturn(error_msg("out of memory"));

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

/* Declared [@@noalloc] on the OCaml side: must not allocate, raise or use the
 * CAMLparam machinery. */
CAMLprim value haltsql_pgq_version_num(value unit) {
  (void)unit;
  return Val_int(PG_VERSION_NUM);
}
