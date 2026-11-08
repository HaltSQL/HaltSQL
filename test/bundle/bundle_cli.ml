(* Stand-alone [haltsql bundle] for tests: bundle_cli.exe keygen|build|sign|verify|inspect. *)
let () =
  let open Cmdliner in
  let main = Cmd.group (Cmd.info "haltsql") [ Cmd_bundle.cmd ] in
  exit
    (match Cmd.eval_value main with
    | Ok (`Ok code) -> code
    | Ok (`Help | `Version) -> 0
    | Error _ -> 2)
