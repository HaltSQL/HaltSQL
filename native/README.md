# libhaltsql — the engine as a C shared library

`libhaltsql` links the OCaml runtime, the core `haltsql` analyzer and the vendored
libpg_query parser into one self-contained shared library with a six-function C ABI
([`include/haltsql.h`](include/haltsql.h)). The Python wheel loads it with `ctypes`
for in-process verification; the npm platform packages carry it for future use.

```
dune build native/libhaltsql.so            # a Mach-O dylib on macOS despite the name
dune build @native/test/runtest            # ABI tests (C, dlopen, foreign threads)
```

## Layout

| File | Role |
|---|---|
| `include/haltsql.h` | The ABI contract. JSON in, JSON out; `HALTSQL_ABI_VERSION` |
| `haltsql_capi.ml` | OCaml side: policy handle table, load/verify, never raises into C |
| `haltsql_capi_stubs.c` | C side: lazy runtime start, thread registration, string marshalling |
| `test/test_capi.c` | ABI tests: every entry point, error paths, NUL bytes, 16 threads + load/free churn, first call from a non-main thread |
| `scripts/build-manylinux.sh` | Builds the library in a `manylinux_2_28` container for the Linux wheels |

## Design rules

- **No policy logic in C.** The C file only marshals strings and holds the runtime
  lock. New verdict fields, rules or SQL features never touch it.
- **Handles, not pointers.** Policies live in an OCaml table keyed by an `int64`
  handle, so C never holds OCaml values and needs no GC roots. Unknown or freed
  handles produce an error object, never a crash.
- **Fail closed.** `haltsql_verify` returns a verdict, `{"error": ...}` or `NULL`;
  bindings treat everything except a well-formed verdict as a failure.
- **Any thread.** A thread is registered with the OCaml runtime on its first call
  (and stays registered: a small record per distinct OS thread) and holds the runtime lock
  while engine code runs. Threads interleave at OCaml safepoints, so the handle
  table is mutex-guarded; throughput is about one core (~50us per verify).
- **Bump `HALTSQL_ABI_VERSION`** only for incompatible changes; adding a function
  is compatible.

## Known limitations

- **fork():** the OCaml runtime does not survive `fork()` into a child that keeps
  using it. Create verifiers after forking (e.g. gunicorn `post_fork`).
- **Policy loading leaks ~60 KB per load** inside the third-party `yaml` binding
  (`yaml_parser_initialize` buffers are never freed). Verification itself leaks
  nothing (checked with macOS `leaks`). Load policies once, not per request.
