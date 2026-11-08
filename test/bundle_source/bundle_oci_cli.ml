(* Stand-alone [haltsql bundle push|pull] for tests. *)
let () =
  let open Cmdliner in
  let main =
    Cmd.group (Cmd.info "haltsql") [ Cmd.group (Cmd.info "bundle") Cmd_bundle_oci.cmds ]
  in
  exit
    (match Cmd.eval_value main with
    | Ok (`Ok code) -> code
    | Ok (`Help | `Version) -> 0
    | Error _ -> 2)
