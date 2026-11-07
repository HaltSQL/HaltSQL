(* Test driver: the schema pull/import and policy draft subcommands, wired the way
   main.ml is expected to register them. *)

open Cmdliner

let () =
  let main =
    Cmd.group (Cmd.info "haltsql")
      [ Cmd.group (Cmd.info "schema") Cmd_schema.cmds; Cmd_policy_draft.cmd ]
  in
  exit
    (match Cmd.eval_value main with
    | Ok (`Ok code) -> code
    | Ok (`Help | `Version) -> 0
    | Error _ -> 2)
