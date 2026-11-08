(** Emits the link flags for bin/*/dune. Static linking (musl) is opt-in via the
    HALTSQL_STATIC=1 environment variable; the default build is dynamic. *)
let () =
  match Sys.getenv_opt "HALTSQL_STATIC" with
  | Some ("1" | "true" | "yes") -> print_string "(-ccopt -static)"
  | _ -> print_string "()"
