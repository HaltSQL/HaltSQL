(** [haltsql-console]: control-plane API for a HaltSQL deployment.

    Exit codes: 0 after a graceful shutdown, 2 on configuration or startup errors.
    [--healthcheck] exits 0 when [GET /healthz] answers 200 and 1 otherwise. *)

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
    value
    & opt (some file) None
    & info [ "c"; "config" ] ~docv:"FILE"
        ~env:(Cmd.Env.info "HALTSQL_CONSOLE_CONFIG")
        ~doc:
          "Console configuration file (YAML or JSON). Required unless $(b,--healthcheck).")

let listen =
  Arg.(
    value
    & opt (some string) None
    & info [ "listen" ] ~docv:"HOST:PORT"
        ~env:(Cmd.Env.info "HALTSQL_CONSOLE_LISTEN")
        ~doc:"Override $(b,listen). The container image sets $(b,0.0.0.0:8090).")

let healthcheck =
  Arg.(
    value & flag
    & info [ "healthcheck" ]
        ~doc:
          "Probe $(b,GET /healthz) on the $(b,--listen) port (loopback when it listens \
           on all interfaces) and exit 0 if it answers 200, 1 otherwise. For container \
           HEALTHCHECKs in images without a shell. Does not read the config file.")

let dev =
  Arg.(
    value
    & opt (some role_conv) None
    & info [ "dev" ] ~docv:"ROLE"
        ~doc:
          "Development only: authenticate every request as a local user with $(docv). \
           Disables every other auth method and requires a loopback $(b,listen) address \
           (exit 2 otherwise). Never use in production.")

(* A dependency-free HTTP/1.0 probe: connect, send one request, read the status line. *)
let probe listen =
  let listen = Option.value listen ~default:"127.0.0.1:8090" in
  match String.rindex_opt listen ':' with
  | None -> 1
  | Some i -> (
      let host = String.sub listen 0 i in
      let host =
        match host with
        | "" | "*" | "0.0.0.0" -> "127.0.0.1"
        | "[::]" | "::" -> "::1"
        | h when String.length h > 1 && h.[0] = '[' -> String.sub h 1 (String.length h - 2)
        | h -> h
      in
      let port = String.sub listen (i + 1) (String.length listen - i - 1) in
      try
        match Unix.getaddrinfo host port [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ] with
        | [] -> 1
        | ai :: _ ->
            let sock = Unix.socket ai.Unix.ai_family Unix.SOCK_STREAM 0 in
            Fun.protect
              ~finally:(fun () -> try Unix.close sock with Unix.Unix_error _ -> ())
              (fun () ->
                Unix.setsockopt_float sock Unix.SO_RCVTIMEO 3.0;
                Unix.setsockopt_float sock Unix.SO_SNDTIMEO 3.0;
                Unix.connect sock ai.Unix.ai_addr;
                let req = "GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n" in
                ignore (Unix.write_substring sock req 0 (String.length req));
                let buf = Bytes.create 64 in
                let n = Unix.read sock buf 0 64 in
                let head = Bytes.sub_string buf 0 n in
                match String.split_on_char ' ' head with _ :: "200" :: _ -> 0 | _ -> 1)
      with Unix.Unix_error _ | Not_found | Invalid_argument _ -> 1)

let run config listen dev healthcheck =
  if healthcheck then probe listen
  else
    match config with
    | None ->
        prerr_endline
          "haltsql-console: --config FILE (or HALTSQL_CONSOLE_CONFIG) is required";
        2
    | Some config -> (
        try Haltsql_console.Console_server.main ~config_file:config ?listen ?dev () with
        | Failure m | Sys_error m ->
            prerr_endline ("haltsql-console: " ^ m);
            2
        | Unix.Unix_error (e, fn, arg) ->
            (* e.g. bind: Address already in use (0.0.0.0:8090) *)
            prerr_endline
              (Printf.sprintf "haltsql-console: %s: %s%s" fn (Unix.error_message e)
                 (if arg = "" then "" else Printf.sprintf " (%s)" arg));
            2)

let cmd =
  Cmd.v
    (Cmd.info "haltsql-console" ~version:Haltsql.version
       ~doc:
         "Control-plane API for HaltSQL: signals, records, agents, policies, fleet, data \
          and evidence")
    Term.(const run $ config $ listen $ dev $ healthcheck)

let () = exit (Cmd.eval' cmd)
