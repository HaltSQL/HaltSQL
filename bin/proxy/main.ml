(* haltsql-proxy: PostgreSQL wire-protocol firewall in front of a real database.
   Every statement is verified with Haltsql.verify under the session's policy before it
   reaches the server; bound tenancy parameters are overwritten with the session's
   context. See docs/proxy.md. *)

open Cmdliner
open Haltsql_pgwire

let exit_ok = 0
let exit_invalid = 1
let exit_usage = 2

let print_errors errs =
  List.iter
    (fun e -> prerr_endline ("haltsql-proxy: " ^ Haltsql.Load_error.to_string e))
    errs

let load_config path =
  if not (Sys.file_exists path) then
    Error (exit_usage, Printf.sprintf "%s: no such file" path)
  else
    match Proxy_config.of_file path with
    | Ok c -> Ok c
    | Error errs ->
        print_errors errs;
        Error (exit_invalid, "invalid configuration")

let config_arg =
  Arg.(
    required
    & opt (some string) None
    & info [ "c"; "config" ] ~docv:"FILE" ~doc:"ProxyConfig document (YAML or JSON).")

(* ------------------------------------------------------------------ run *)

let parse_listen s =
  match String.rindex_opt s ':' with
  | Some i -> (
      let h = String.sub s 0 i and p = String.sub s (i + 1) (String.length s - i - 1) in
      match int_of_string_opt p with
      | Some p when p >= 0 && p <= 65535 && h <> "" -> Some (h, p)
      | _ -> None)
  | None -> None

let run config listen log_level =
  match load_config config with
  | Error (code, msg) ->
      prerr_endline ("haltsql-proxy: " ^ msg);
      code
  | Ok cfg -> (
      let cfg =
        match log_level with
        | Some l -> { cfg with Proxy_config.log_level = l }
        | None -> cfg
      in
      match listen with
      | Some l when parse_listen l = None ->
          prerr_endline ("haltsql-proxy: invalid --listen address " ^ l);
          exit_usage
      | _ -> (
          let overrides (cfg : Proxy_config.t) =
            let cfg =
              match log_level with
              | Some l -> { cfg with Proxy_config.log_level = l }
              | None -> cfg
            in
            match Option.bind listen parse_listen with
            | Some (h, p) -> { cfg with Proxy_config.listen_host = h; listen_port = p }
            | None -> cfg
          in
          let cfg = overrides cfg in
          (* SIGHUP / file watch: re-read the same file with the same overrides *)
          let reload () =
            match Proxy_config.of_file config with
            | Ok c -> Ok (overrides c)
            | Error errs -> Error (List.map Haltsql.Load_error.to_string errs)
          in
          (* a client going away mid-write must not kill the process *)
          (try Sys.set_signal Sys.sigpipe Sys.Signal_ignore with _ -> ());
          try
            Lwt_main.run
              (let open Lwt.Syntax in
               let* srv = Server.start ~reload cfg in
               let stop _ = Lwt.async (fun () -> Server.shutdown srv) in
               ignore (Lwt_unix.on_signal Sys.sigterm stop);
               ignore (Lwt_unix.on_signal Sys.sigint stop);
               ignore
                 (Lwt_unix.on_signal Sys.sighup (fun _ ->
                      Lwt.async (fun () ->
                          Lwt.map ignore (Server.reload srv ~trigger:"sighup"))));
               Server.wait srv);
            exit_ok
          with Failure m ->
            prerr_endline ("haltsql-proxy: " ^ m);
            exit_usage))

let run_cmd =
  let listen =
    Arg.(
      value
      & opt (some string) None
      & info [ "listen" ] ~docv:"HOST:PORT" ~doc:"Override the config's listen address.")
  in
  let log_level =
    Arg.(
      value
      & opt
          (some
             (enum
                [
                  ("debug", "debug");
                  ("info", "info");
                  ("warn", "warn");
                  ("error", "error");
                ]))
          None
      & info [ "log-level" ] ~docv:"LEVEL" ~doc:"Override logging.level.")
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Listens for PostgreSQL clients, authenticates them (SCRAM-SHA-256 or a TLS \
         client certificate), connects to the upstream database with the service \
         credentials from the config, and verifies every statement against the session's \
         policy before forwarding it. Denied statements get an ErrorResponse (SQLSTATE \
         deny_sqlstate, default 42501) and the connection stays usable.";
      `P
        "SIGTERM or SIGINT stops accepting connections and drains sessions for \
         shutdown_grace_seconds.";
      `P
        "SIGHUP reloads the config file and its policies (also on file changes with \
         reload.watch). New connections use the new configuration, existing sessions \
         keep theirs; an invalid configuration is logged and the current one stays in \
         force.";
      `P
        "Every statement is audited to the configured sinks (hash-chained JSON lines, \
         see haltsql audit verify). With on_error: fail_closed (the default) a statement \
         whose audit record cannot be written is refused with SQLSTATE 58030.";
      `S "EXAMPLES";
      `Pre
        "  haltsql-proxy run --config proxy.yaml\n\
        \  haltsql-proxy run -c proxy.json --listen 127.0.0.1:6432 --log-level debug\n\
        \  psql 'host=127.0.0.1 port=6432 dbname=app user=agent sslmode=require'";
    ]
  in
  Cmd.v
    (Cmd.info "run" ~doc:"Run the proxy." ~man)
    Term.(const run $ config_arg $ listen $ log_level)

(* ------------------------------------------------------------- validate *)

let validate config json =
  match load_config config with
  | Error (code, msg) ->
      if json then
        print_endline
          (Yojson.Safe.to_string
             (`Assoc [ ("valid", `Bool false); ("error", `String msg) ]))
      else prerr_endline ("haltsql-proxy: " ^ msg);
      code
  | Ok cfg ->
      if json then
        print_endline
          (Yojson.Safe.pretty_to_string
             (`Assoc
                [ ("valid", `Bool true); ("config", Proxy_config.to_json_redacted cfg) ]))
      else Printf.printf "%s: valid ProxyConfig\n" config;
      exit_ok

let validate_cmd =
  let json =
    Arg.(
      value & flag & info [ "json" ] ~doc:"Print the effective (redacted) config as JSON.")
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Loads and validates a ProxyConfig, its policies and TLS material. Exit 0 if \
         valid, 1 if invalid, 2 if the file cannot be read.";
      `S "EXAMPLES";
      `Pre
        "  haltsql-proxy validate --config proxy.yaml\n\
        \  haltsql-proxy validate -c proxy.yaml --json | jq .config.auth";
    ]
  in
  Cmd.v
    (Cmd.info "validate" ~doc:"Validate a ProxyConfig." ~man)
    Term.(const validate $ config_arg $ json)

(* ------------------------------------------------------- scram-verifier *)

let scram_verifier iterations =
  if iterations < 4096 || iterations > 10_000_000 then (
    prerr_endline "haltsql-proxy: --iterations must be between 4096 and 10000000";
    exit_usage)
  else
    match In_channel.input_line stdin with
    | None | Some "" ->
        prerr_endline "haltsql-proxy: expected the password on stdin";
        exit_usage
    | Some line ->
        let pw =
          let n = String.length line in
          if n > 0 && line.[n - 1] = '\r' then String.sub line 0 (n - 1) else line
        in
        if not (String.for_all (fun c -> Char.code c >= 0x20 && Char.code c < 0x7f) pw)
        then (
          prerr_endline "haltsql-proxy: passwords must be printable ASCII";
          exit_invalid)
        else (
          Sec.init_rng ();
          print_endline (Scram.verifier_to_string (Scram.make_verifier ~iterations pw));
          exit_ok)

let scram_cmd =
  let iterations =
    Arg.(
      value & opt int 4096
      & info [ "iterations" ] ~docv:"N" ~doc:"PBKDF2 iteration count.")
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Reads a password from the first line of stdin and prints a SCRAM-SHA-256 \
         verifier in PostgreSQL's stored format, for auth.users[].scram_verifier. The \
         password is never echoed or logged.";
      `S "EXAMPLES";
      `Pre
        "  printf '%s\\n' \"$AGENT_PASSWORD\" | haltsql-proxy scram-verifier\n\
        \  haltsql-proxy scram-verifier --iterations 600000 < password.txt";
    ]
  in
  Cmd.v
    (Cmd.info "scram-verifier" ~doc:"Generate a SCRAM-SHA-256 verifier." ~man)
    Term.(const scram_verifier $ iterations)

let () =
  let man =
    [
      `S Manpage.s_description;
      `P "PostgreSQL wire-protocol firewall powered by HaltSQL. See docs/proxy.md.";
      `S "EXAMPLES";
      `Pre
        "  haltsql-proxy validate --config proxy.yaml\n\
        \  haltsql-proxy run --config proxy.yaml";
    ]
  in
  let info =
    Cmd.info "haltsql-proxy" ~version:Haltsql.version
      ~doc:"PostgreSQL firewall for LLM-generated SQL" ~man
  in
  exit
    (Cmd.eval' ~term_err:exit_usage (Cmd.group info [ run_cmd; validate_cmd; scram_cmd ]))
