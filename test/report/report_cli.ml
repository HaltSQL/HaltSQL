(* `haltsql report` alone, for the tests: the same Cmd_report.cmd that bin/haltsql
   registers. *)

let () =
  let open Cmdliner in
  let code =
    match Cmd.eval_value (Cmd.group (Cmd.info "haltsql") [ Cmd_report.cmd ]) with
    | Ok (`Ok code) -> code
    | Ok (`Help | `Version) -> 0
    | Error (`Parse | `Term | `Exn) -> 2
  in
  exit code
