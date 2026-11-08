(* Test harness: `audit_cli audit verify ...` runs Cmd_audit.cmd exactly as
   `haltsql audit verify ...` does once the command is registered in main.ml. *)

open Cmdliner

let () =
  exit
    (Cmd.eval' ~term_err:2
       (Cmd.group
          (Cmd.info "haltsql" ~doc:"audit command harness")
          [ Audit_cmd.Cmd_audit.cmd ]))
