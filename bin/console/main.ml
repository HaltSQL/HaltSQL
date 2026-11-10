(** [haltsql-console]: control-plane API for a HaltSQL deployment.

    Exit codes: 0 after a graceful shutdown, 2 on configuration or startup errors. *)

open Cmdliner

let role_conv =
  let parse s =
    match Haltsql_console.Rbac.role_of_string s with
    | Some r -> Ok r
    | None -> Error (`Msg "role must be one of dev, analyst, owner, audit, admin")
  in
  Arg.conv
    ( parse,
      fun ppf r -> Format.pp_print_string ppf (Haltsql_console.Rbac.role_to_string r) )

let config =
  Arg.(
    required
    & opt (some file) None
    & info [ "c"; "config" ] ~docv:"FILE"
        ~env:(Cmd.Env.info "HALTSQL_CONSOLE_CONFIG")
        ~doc:"Console configuration file (YAML or JSON).")

let listen =
  Arg.(
    value
    & opt (some string) None
    & info [ "listen" ] ~docv:"HOST:PORT" ~doc:"Override $(b,listen).")

let dev =
  Arg.(
    value
    & opt (some role_conv) None
    & info [ "dev" ] ~docv:"ROLE"
        ~doc:
          "Development only: authenticate every request as a local user with $(docv). \
           Disables every other auth method and requires a loopback $(b,listen) address \
           (exit 2 otherwise). Never use in production.")

let run config listen dev =
  try Haltsql_console.Console_server.main ~config_file:config ?listen ?dev () with
  | Failure m | Sys_error m ->
      prerr_endline ("haltsql-console: " ^ m);
      2
  | Unix.Unix_error (e, fn, arg) ->
      (* e.g. bind: Address already in use (0.0.0.0:8090) *)
      prerr_endline
        (Printf.sprintf "haltsql-console: %s: %s%s" fn (Unix.error_message e)
           (if arg = "" then "" else Printf.sprintf " (%s)" arg));
      2

let cmd =
  Cmd.v
    (Cmd.info "haltsql-console" ~version:Haltsql.version
       ~doc:
         "Control-plane API for HaltSQL: signals, records, agents, policies, fleet, data \
          and evidence")
    Term.(const run $ config $ listen $ dev)

let () = exit (Cmd.eval' cmd)
