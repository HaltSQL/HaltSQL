(** [haltsql-server]: HTTP sidecar for the HaltSQL policy firewall.

    Command-line parsing only: flags are folded into the loaded configuration as overrides
    (flags > [HALTSQL_*] environment > config file > defaults) and the process lifecycle
    is {!Haltsql_server.Server.main}. Exit codes: 0 after a graceful shutdown, 2 on
    configuration, usage or startup errors. *)

open Cmdliner
open Haltsql_server

let audit_conv =
  let parse = function
    | "stdout" -> Ok `Stdout
    | "none" -> Ok `None
    | s when String.length s > 5 && String.sub s 0 5 = "file:" ->
        Ok (`File (String.sub s 5 (String.length s - 5)))
    | s ->
        Error
          (`Msg
             (Printf.sprintf "invalid audit sink %S (expected stdout, none or file:PATH)"
                s))
  in
  let print ppf = function
    | `Stdout -> Format.pp_print_string ppf "stdout"
    | `None -> Format.pp_print_string ppf "none"
    | `File p -> Format.fprintf ppf "file:%s" p
  in
  Arg.conv (parse, print)

let run config policies listen allow_unauth default_policy log_level log_format audit
    log_raw_sql watch max_bytes no_metrics health_listen max_connections request_timeout
    idle_timeout shutdown_timeout =
  let limits =
    let d = Server.default_limits in
    {
      d with
      Server.max_connections = Option.value max_connections ~default:d.max_connections;
      request_timeout = Option.value request_timeout ~default:d.request_timeout;
      idle_timeout = Option.value idle_timeout ~default:d.idle_timeout;
      shutdown_timeout = Option.value shutdown_timeout ~default:d.shutdown_timeout;
    }
  in
  let overrides (c : Haltsql.Config.t) =
    let c = match listen with Some l -> { c with listen = l } | None -> c in
    let c = if allow_unauth then { c with allow_unauthenticated = true } else c in
    let c =
      match default_policy with Some d -> { c with default_policy = Some d } | None -> c
    in
    let c = match log_level with Some l -> { c with log_level = l } | None -> c in
    let c = match log_format with Some f -> { c with log_format = f } | None -> c in
    let c =
      match audit with
      | [] -> c
      | sinks ->
          let kinds =
            List.filter_map
              (function
                | `None -> None
                | `Stdout -> Some Haltsql.Config.Sink_stdout
                | `File p -> Some (Haltsql.Config.Sink_file p))
              sinks
          in
          {
            c with
            audit_sinks =
              List.map
                (function
                  | Haltsql.Config.Sink_file p -> Haltsql.Config.Audit_file p
                  | _ -> Haltsql.Config.Audit_stdout)
                kinds;
            sinks =
              List.map
                (fun k ->
                  { Haltsql.Config.sink = k; on_error = Haltsql.Config.Fail_closed })
                kinds;
          }
    in
    let c = if log_raw_sql then { c with log_raw_sql = true } else c in
    let c = match watch with Some w -> { c with reload_watch = w } | None -> c in
    let c =
      match max_bytes with Some m -> { c with max_request_bytes = m } | None -> c
    in
    let c = if no_metrics then { c with metrics = false } else c in
    c
  in
  if config = None && policies = [] then begin
    prerr_endline "haltsql-server: pass --config FILE or at least one --policy FILE";
    2
  end
  else
    Server.main ?health_listen ~limits
      ~sources:{ State.config_file = config; policy_files = policies; overrides }
      ()

let cmd =
  let config =
    Arg.(
      value
      & opt (some file) None
      & info [ "config" ] ~docv:"FILE"
          ~doc:"Config document (kind: Config, YAML or JSON).")
  in
  let policies =
    Arg.(
      value & opt_all file []
      & info [ "p"; "policy" ] ~docv:"FILE"
          ~doc:
            "Load a policy file (repeatable). Added to the policies from $(b,--config); \
             a policy with the same name replaces the config's.")
  in
  let listen =
    Arg.(
      value
      & opt (some string) None
      & info [ "listen" ] ~docv:"HOST:PORT"
          ~doc:"Listen address (default 127.0.0.1:8080).")
  in
  let allow_unauth =
    Arg.(
      value & flag
      & info [ "allow-unauthenticated" ]
          ~doc:
            "Accept requests without a bearer token (they use the default policy). Local \
             development only.")
  in
  let default_policy =
    Arg.(
      value
      & opt (some string) None
      & info [ "default-policy" ] ~docv:"NAME"
          ~doc:"Policy used by unauthenticated requests.")
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
      & info [ "log-level" ] ~docv:"LEVEL" ~doc:"debug, info, warn or error.")
  in
  let log_format =
    Arg.(
      value
      & opt (some (enum [ ("json", "json"); ("text", "text") ])) None
      & info [ "log-format" ] ~docv:"FORMAT" ~doc:"json or text (logs go to stderr).")
  in
  let audit =
    Arg.(
      value & opt_all audit_conv []
      & info [ "audit" ] ~docv:"SINK"
          ~doc:
            "Audit sink: $(b,stdout), $(b,file:PATH) or $(b,none) (repeatable; replaces \
             the config's sinks).")
  in
  let log_raw_sql =
    Arg.(
      value & flag & info [ "log-raw-sql" ] ~doc:"Include the raw SQL in audit records.")
  in
  let watch =
    Arg.(
      value
      & vflag None
          [
            ( Some true,
              info [ "watch" ]
                ~doc:"Reload when policy/config files change (polled every 2s)." );
            ( Some false,
              info [ "no-watch" ] ~doc:"Do not watch files (SIGHUP still reloads)." );
          ])
  in
  let max_bytes =
    Arg.(
      value
      & opt (some int) None
      & info [ "max-request-bytes" ] ~docv:"N"
          ~doc:"Maximum request body size (413 above).")
  in
  let no_metrics =
    Arg.(value & flag & info [ "no-metrics" ] ~doc:"Disable GET /metrics.")
  in
  let health_listen =
    Arg.(
      value
      & opt (some string) None
      & info [ "health-listen" ] ~docv:"HOST:PORT"
          ~doc:
            "Also serve $(b,/healthz) and $(b,/readyz) (only) over plain HTTP on this \
             address, e.g. for kubelet probes when the main listener uses TLS with \
             required client certificates.")
  in
  let max_connections =
    Arg.(
      value
      & opt (some int) None
      & info [ "max-connections" ] ~docv:"N"
          ~doc:
            (Printf.sprintf
               "Maximum simultaneous client connections on the main listener (default \
                %d). At the limit the server stops accepting, so further clients wait in \
                the listen backlog instead of being refused."
               Server.default_limits.max_connections))
  in
  let seconds name ~default ~doc =
    Arg.(
      value
      & opt (some float) None
      & info [ name ] ~docv:"SECONDS" ~doc:(Printf.sprintf "%s (default %g)." doc default))
  in
  let request_timeout =
    seconds "request-timeout" ~default:Server.default_limits.request_timeout
      ~doc:
        "Time allowed to receive a whole request (head and body) once its first byte has \
         arrived; slower clients are disconnected"
  in
  let idle_timeout =
    seconds "idle-timeout" ~default:Server.default_limits.idle_timeout
      ~doc:
        "How long a keep-alive connection may stay silent between requests, and how long \
         a response write may stall, before the connection is closed"
  in
  let shutdown_timeout =
    seconds "shutdown-timeout" ~default:Server.default_limits.shutdown_timeout
      ~doc:
        "On SIGTERM/SIGINT, how long in-flight requests may take to complete before the \
         remaining connections are closed"
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Serves POST /v1/verify, GET /v1/policies, /healthz, /readyz and /metrics. \
         Settings precedence: command-line flags > HALTSQL_* environment variables > \
         config file > defaults. SIGHUP reloads all policies, auth settings and TLS \
         certificates (atomically; the last good set is kept on error). SIGTERM/SIGINT \
         shut down gracefully: the listeners close, $(b,/readyz) turns 503, idle \
         connections are closed and in-flight requests get $(b,--shutdown-timeout) \
         seconds to finish. Built-in TLS (server.tls, TLS 1.2/1.3) with optional or \
         required client certificates, OIDC/JWT bearer tokens (server.auth.oidc) and \
         mTLS identities (server.auth.mtls) are configured in the config file; see \
         docs/authentication.md.";
      `S Manpage.s_examples;
      `Pre
        "  haltsql-server --policy policy.yaml --listen 127.0.0.1:8080 \
         --allow-unauthenticated";
      `Noblank;
      `Pre "  haltsql-server --config /etc/haltsql/config.yaml";
      `Noblank;
      `Pre
        "  haltsql-server --config /etc/haltsql/config.yaml --health-listen 0.0.0.0:8081";
      `S "LIMITS";
      `P
        "Request bodies above $(b,--max-request-bytes) are refused with 413 before they \
         are read; request heads are limited to 64 KiB. $(b,--request-timeout), \
         $(b,--idle-timeout) and $(b,--max-connections) protect against slow or abusive \
         clients. The $(b,--health-listen) port has its own budget of 64 connections so \
         probes keep working when the main port is saturated.";
    ]
  in
  let exits =
    [
      Cmd.Exit.info 0 ~doc:"after a graceful shutdown (SIGTERM or SIGINT).";
      Cmd.Exit.info 2
        ~doc:
          "on usage errors, or when the configuration cannot be loaded or the listener \
           cannot start.";
    ]
  in
  Cmd.v
    (Cmd.info "haltsql-server" ~version:Haltsql.version
       ~doc:"HTTP sidecar for the HaltSQL policy firewall" ~man ~exits)
    Term.(
      const run $ config $ policies $ listen $ allow_unauth $ default_policy $ log_level
      $ log_format $ audit $ log_raw_sql $ watch $ max_bytes $ no_metrics $ health_listen
      $ max_connections $ request_timeout $ idle_timeout $ shutdown_timeout)

let () =
  exit
    (match Cmd.eval_value cmd with
    | Ok (`Ok code) -> code
    | Ok (`Help | `Version) -> 0
    | Error _ -> 2)
