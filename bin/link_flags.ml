(* Emits the link flags for bin/*/dune. Static linking is opt-in via the HALTSQL_STATIC
   environment variable; the default build is dynamic.

   HALTSQL_STATIC=1 (or true/yes) produces fully static executables and is only
   supported against musl (the Alpine builder stage of the Dockerfile): glibc's static
   getaddrinfo/NSS would link with warnings and then fail at run time, and macOS has no
   static libSystem. Anything else fails the build with a clear message instead of
   producing a binary that only looks static. HALTSQL_STATIC=force skips that check.

   The static link needs the archives of every C library the binaries use: libgmp.a
   (zarith; Alpine package gmp-static) and the vendored libpg_query.a (built by
   lib/pgquery/dune). mirage-crypto, digestif and the OCaml runtime stubs are compiled
   from source.

   HALTSQL_STATIC_GMP=DIR links only libgmp statically: DIR must contain libgmp.a and no
   libgmp dylib/so. It is searched before zarith's own -L directory, so the linker picks
   the archive. Used for the macOS binaries shipped in the Python wheel and npm package,
   which must not depend on a Homebrew libgmp.dylib. *)

let is_musl () =
  List.exists
    (fun dir ->
      try
        Array.exists
          (fun f -> String.length f > 7 && String.sub f 0 7 = "ld-musl")
          (Sys.readdir dir)
      with Sys_error _ -> false)
    [ "/lib"; "/usr/lib" ]

let static = "(-ccopt -static)"

let static_gmp () =
  match Sys.getenv_opt "HALTSQL_STATIC_GMP" with
  | None | Some "" -> ""
  | Some dir ->
      if not (Sys.file_exists (Filename.concat dir "libgmp.a")) then (
        prerr_endline ("HALTSQL_STATIC_GMP: no libgmp.a in " ^ dir);
        exit 1);
      Printf.sprintf "-ccopt -L%s" (Filename.quote dir)

let () =
  match Sys.getenv_opt "HALTSQL_STATIC" with
  | Some ("1" | "true" | "yes") ->
      if is_musl () then print_string static
      else (
        prerr_endline
          "HALTSQL_STATIC=1: fully static linking is only supported with musl (build in \
           the Alpine stage of the Dockerfile: docker build --target dist ...). Set \
           HALTSQL_STATIC=force to try anyway.";
        exit 1)
  | Some "force" -> print_string static
  | _ -> print_string ("(" ^ static_gmp () ^ ")")
