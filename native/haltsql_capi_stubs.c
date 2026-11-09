/* C half of libhaltsql (see include/haltsql.h).
 *
 * The OCaml runtime is started lazily (pthread_once) on the first call from any thread.
 * Each entry point registers the calling thread with the OCaml runtime (systhreads) on
 * its first call and takes the runtime lock while it runs OCaml code, so the library is
 * safe to call from any number of host threads (Python threads, Node worker threads...).
 *
 * Threads are never unregistered: caml_c_thread_unregister cannot run from a pthread
 * TLS destructor (the runtime's own thread-local state is already gone by then, which
 * crashes on macOS), and the bindings cannot tell when a host thread is finished. Each
 * distinct OS thread that ever calls in costs one small runtime record; thread pools
 * (asyncio.to_thread, Node workers) reuse threads, so this stays bounded in practice. */

#define CAML_NAME_SPACE
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/threads.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "haltsql.h"

#if defined(_WIN32)
#define HALTSQL_EXPORT __declspec(dllexport)
#else
#define HALTSQL_EXPORT __attribute__((visibility("default")))
#endif

static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static int init_ok = 0;
static pthread_t init_thread;
/* Set once this thread is known to the OCaml runtime. */
static _Thread_local int thread_registered = 0;

static void do_init(void) {
  static char_os prog[] = "libhaltsql";
  static char_os *argv[] = {prog, NULL};
  init_thread = pthread_self();
  caml_startup(argv);
  /* The starting thread owns the runtime; hand it back so any thread can take it. */
  caml_release_runtime_system();
  init_ok = 1;
}

/* Returns 0 if the runtime is up and the caller now holds the runtime lock. */
static int enter(void) {
  pthread_once(&init_once, do_init);
  if (!init_ok) return -1;
  if (!thread_registered) {
    /* First call from this thread. The thread that ran caml_startup is already known
     * to the runtime. */
    if (!pthread_equal(pthread_self(), init_thread) && !caml_c_thread_register())
      return -1;
    thread_registered = 1;
  }
  caml_acquire_runtime_system();
  return 0;
}

static void leave(void) { caml_release_runtime_system(); }

static const value *cb(const char *name) {
  const value *f = caml_named_value(name);
  return f;
}

/* malloc'd copy of an OCaml string (may contain NULs; result is NUL-terminated). */
static char *dup_ocaml_string(value s) {
  size_t n = caml_string_length(s);
  char *out = malloc(n + 1);
  if (out == NULL) return NULL;
  memcpy(out, String_val(s), n);
  out[n] = '\0';
  return out;
}

static value caml_string_of_buf(const char *p, size_t n) {
  if (p == NULL) return caml_alloc_initialized_string(0, "");
  return caml_alloc_initialized_string(n, p);
}

HALTSQL_EXPORT int haltsql_abi_version(void) { return HALTSQL_ABI_VERSION; }

HALTSQL_EXPORT char *haltsql_version(void) {
  char *out = NULL;
  if (enter() != 0) return NULL;
  {
    CAMLparam0();
    CAMLlocal1(r);
    const value *f = cb("haltsql_version");
    if (f != NULL) {
      r = caml_callback_exn(*f, Val_unit);
      if (!Is_exception_result(r)) out = dup_ocaml_string(r);
    }
    CAMLdrop;
  }
  leave();
  return out;
}

static void set_err(char **err_out, const char *msg) {
  if (err_out != NULL) *err_out = msg ? strdup(msg) : NULL;
}

/* Unpacks the (int * string) result of the load callbacks. */
static haltsql_policy finish_load(value r, char **err_out) {
  if (Is_exception_result(r)) {
    set_err(err_out, "internal error while loading policy");
    return 0;
  }
  haltsql_policy h = (haltsql_policy)Long_val(Field(r, 0));
  if (h == 0) {
    if (err_out != NULL) *err_out = dup_ocaml_string(Field(r, 1));
  } else {
    set_err(err_out, NULL);
  }
  return h;
}

HALTSQL_EXPORT haltsql_policy haltsql_policy_load_file(const char *path, char **err_out) {
  haltsql_policy h = 0;
  if (path == NULL) {
    set_err(err_out, "path is NULL");
    return 0;
  }
  if (enter() != 0) {
    set_err(err_out, "HaltSQL runtime failed to start");
    return 0;
  }
  {
    CAMLparam0();
    CAMLlocal2(p, r);
    const value *f = cb("haltsql_load_file");
    if (f == NULL) {
      set_err(err_out, "HaltSQL runtime is missing haltsql_load_file");
    } else {
      p = caml_copy_string(path);
      r = caml_callback_exn(*f, p);
      h = finish_load(r, err_out);
    }
    CAMLdrop;
  }
  leave();
  return h;
}

HALTSQL_EXPORT haltsql_policy haltsql_policy_load_string(const char *doc, size_t doc_len,
                                                         const char *format,
                                                         const char *base_dir,
                                                         char **err_out) {
  haltsql_policy h = 0;
  if (doc == NULL || format == NULL) {
    set_err(err_out, "doc and format are required");
    return 0;
  }
  if (enter() != 0) {
    set_err(err_out, "HaltSQL runtime failed to start");
    return 0;
  }
  {
    CAMLparam0();
    CAMLlocal4(d, fm, bd, r);
    const value *f = cb("haltsql_load_string");
    if (f == NULL) {
      set_err(err_out, "HaltSQL runtime is missing haltsql_load_string");
    } else {
      d = caml_string_of_buf(doc, doc_len);
      fm = caml_copy_string(format);
      bd = caml_copy_string(base_dir ? base_dir : "");
      r = caml_callback3_exn(*f, d, fm, bd);
      h = finish_load(r, err_out);
    }
    CAMLdrop;
  }
  leave();
  return h;
}

HALTSQL_EXPORT char *haltsql_policy_info(haltsql_policy policy) {
  char *out = NULL;
  if (enter() != 0) return NULL;
  {
    CAMLparam0();
    CAMLlocal1(r);
    const value *f = cb("haltsql_info");
    if (f != NULL) {
      r = caml_callback_exn(*f, Val_long(policy));
      if (!Is_exception_result(r) && caml_string_length(r) > 0) out = dup_ocaml_string(r);
    }
    CAMLdrop;
  }
  leave();
  return out;
}

HALTSQL_EXPORT void haltsql_policy_free(haltsql_policy policy) {
  if (policy <= 0) return;
  if (enter() != 0) return;
  {
    CAMLparam0();
    const value *f = cb("haltsql_free");
    if (f != NULL) (void)caml_callback_exn(*f, Val_long(policy));
    CAMLdrop;
  }
  leave();
}

HALTSQL_EXPORT char *haltsql_verify(haltsql_policy policy, const char *sql, size_t sql_len,
                                    const char *context_json, size_t context_len) {
  char *out = NULL;
  if (sql == NULL && sql_len != 0) return NULL;
  if (enter() != 0) return NULL;
  {
    CAMLparam0();
    CAMLlocal3(s, c, r);
    const value *f = cb("haltsql_verify");
    if (f != NULL) {
      s = caml_string_of_buf(sql, sql_len);
      c = caml_string_of_buf(context_json, context_json ? context_len : 0);
      r = caml_callback3_exn(*f, Val_long(policy), s, c);
      if (!Is_exception_result(r)) out = dup_ocaml_string(r);
    }
    CAMLdrop;
  }
  leave();
  return out;
}

HALTSQL_EXPORT void haltsql_string_free(char *s) { free(s); }
