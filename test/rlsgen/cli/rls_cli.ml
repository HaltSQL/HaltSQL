(* Stand-alone driver for Cmd_rls.cmd (exit codes as in bin/haltsql/main.ml). *)
let () =
  let code =
    match Cmdliner.Cmd.eval_value Cmd_rls.cmd with
    | Ok (`Ok code) -> code
    | Ok (`Help | `Version) -> 0
    | Error _ -> 2
  in
  exit code
