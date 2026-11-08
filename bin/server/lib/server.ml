(* Listener, signals, hot-reload watcher and lifecycle for haltsql-server. *)

open Lwt.Syntax

exception Startup_error of string

(* "host:port", "[v6]:port", ":port" or "*:port". *)
let parse_listen s =
  match String.rindex_opt s ':' with
  | None -> Error (Printf.sprintf "invalid listen address %S (expected host:port)" s)
  | Some i -> (
      let host = String.sub s 0 i
      and port = String.sub s (i + 1) (String.length s - i - 1) in
      let host =
        if
          String.length host >= 2 && host.[0] = '[' && host.[String.length host - 1] = ']'
        then String.sub host 1 (String.length host - 2)
        else host
      in
      let host = if host = "" || host = "*" then "0.0.0.0" else host in
      match int_of_string_opt port with
      | Some p when p >= 0 && p <= 65535 -> Ok (host, p)
      | _ -> Error (Printf.sprintf "invalid port in listen address %S" s))

(* Binds and listens; returns the socket and the actual port (for port 0). *)
let bind_listen listen =
  match parse_listen listen with
  | Error e -> raise (Startup_error e)
  | Ok (host, port) ->
      let addr =
        match Unix.inet_addr_of_string host with
        | a -> a
        | exception Failure _ -> (
            match Unix.getaddrinfo host "" [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ] with
            | { ai_addr = Unix.ADDR_INET (a, _); _ } :: _ -> a
            | _ ->
                raise
                  (Startup_error (Printf.sprintf "cannot resolve listen host %S" host)))
      in
      let domain = Unix.domain_of_sockaddr (Unix.ADDR_INET (addr, port)) in
      let fd = Lwt_unix.socket domain Unix.SOCK_STREAM 0 in
      let close_quiet () =
        try Unix.close (Lwt_unix.unix_file_descr fd) with Unix.Unix_error _ -> ()
      in
      (try
         Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
         Lwt_unix.set_close_on_exec fd;
         (try Unix.bind (Lwt_unix.unix_file_descr fd) (Unix.ADDR_INET (addr, port))
          with Unix.Unix_error (e, _, _) ->
            raise
              (Startup_error
                 (Printf.sprintf "cannot bind %s: %s" listen (Unix.error_message e))));
         Lwt_unix.listen fd 1024
       with exn ->
         close_quiet ();
         raise exn);
      let actual =
        match Unix.getsockname (Lwt_unix.unix_file_descr fd) with
        | Unix.ADDR_INET (_, p) -> p
        | _ -> port
      in
      (fd, actual)

let check_auth (cfg : Haltsql.Config.t) =
  if cfg.tokens = [] && cfg.oidc = [] && cfg.mtls = [] && not cfg.allow_unauthenticated
  then
    Log.warn
      "no auth tokens, OIDC providers or mTLS identities configured and \
       allow_unauthenticated is false: every authenticated endpoint will return 401"

(* Polls watched files every [interval] seconds and reloads on change. *)
let rec watch_loop (st : State.t) ~interval ~stop =
  let* r =
    Lwt.pick
      [
        (let* () = Lwt_unix.sleep interval in
         Lwt.return `Tick);
        (let* () = stop in
         Lwt.return `Stop);
      ]
  in
  match r with
  | `Stop -> Lwt.return_unit
  | `Tick ->
      let* () =
        if State.changed st then
          let* _ = State.reload_lwt ~reason:"file-change" st in
          Lwt.return_unit
        else Lwt.return_unit
      in
      watch_loop st ~interval ~stop

(* ---- HTTP over plain TCP or TLS ----

   cohttp's server is instantiated over its Unix IO module with our own
   connection type, so handlers see the verified client identity of TLS
   connections. We run our own accept loop: each connection gets the TLS
   configuration current at accept time (certificates reload without a
   restart). *)

module Io = struct
  include (
    Cohttp_lwt_unix.Private.IO :
      module type of Cohttp_lwt_unix.Private.IO with type conn := Conduit_lwt_unix.flow)

  type conn = Conn.t
end

module Srv = Cohttp_lwt.Make_server (Io)

let handshake_timeout = 10.0
let close_quietly fd = Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)

let on_conn_exn = function
  | Unix.Unix_error ((Unix.EPIPE | Unix.ECONNRESET | Unix.EBADF), _, _) -> ()
  | Tls_lwt.Tls_alert _ | Tls_lwt.Tls_failure _ | End_of_file -> ()
  | e -> Log.warn "connection error" ~fields:[ ("error", `String (Printexc.to_string e)) ]

let serve_plain spec fd remote =
  let ic = Lwt_io.of_fd ~close:(fun () -> Lwt.return_unit) ~mode:Lwt_io.input fd in
  let oc = Lwt_io.of_fd ~close:(fun () -> Lwt.return_unit) ~mode:Lwt_io.output fd in
  Lwt.finalize
    (fun () ->
      Srv.callback spec (Conn.plain remote)
        (Cohttp_lwt_unix.Private.Input_channel.create ic)
        oc)
    (fun () ->
      let* () = Lwt.catch (fun () -> Lwt_io.flush oc) (fun _ -> Lwt.return_unit) in
      close_quietly fd)

let serve_tls spec tls_cfg fd remote =
  let* session =
    Lwt.catch
      (fun () ->
        Lwt.pick
          [
            (let* t = Tls_lwt.Unix.server_of_fd tls_cfg fd in
             Lwt.return_ok t);
            (let* () = Lwt_unix.sleep handshake_timeout in
             Lwt.return_error "TLS handshake timed out");
          ])
      (fun e -> Lwt.return_error (Printexc.to_string e))
  in
  match session with
  | Error e ->
      Log.debug "TLS handshake failed"
        ~fields:[ ("remote", `String remote); ("error", `String e) ];
      close_quietly fd
  | Ok t ->
      let peer =
        Option.map Haltsql_auth.Mtls.peer_of_certificate (Tls_setup.peer_certificate t)
      in
      let ic, oc = Tls_lwt.of_t t in
      Lwt.finalize
        (fun () ->
          Srv.callback spec
            { Conn.remote; tls = true; peer }
            (Cohttp_lwt_unix.Private.Input_channel.create ic)
            oc)
        (fun () ->
          let* () = Lwt.catch (fun () -> Lwt_io.close oc) (fun _ -> Lwt.return_unit) in
          let* () = Lwt.catch (fun () -> Lwt_io.close ic) (fun _ -> Lwt.return_unit) in
          close_quietly fd)

(* Accepts connections on [fd] until [stop]; [tls ()] gives the TLS config to
   use for a new connection (None: plain HTTP). *)
let accept_loop ~spec ~tls fd ~stop =
  let stopped = ref false in
  let rec loop () =
    let* r =
      Lwt.pick
        [
          (let* () = stop in
           Lwt.return `Stop);
          Lwt.catch
            (fun () ->
              let* c, addr = Lwt_unix.accept fd in
              Lwt.return (`Conn (c, addr)))
            (fun e -> Lwt.return (`Error e));
        ]
    in
    match r with
    | `Stop ->
        stopped := true;
        Lwt.return_unit
    | `Error Lwt.Canceled when !stopped -> Lwt.return_unit
    | `Error e ->
        Log.warn "accept failed" ~fields:[ ("error", `String (Printexc.to_string e)) ];
        let* () = Lwt_unix.sleep 0.05 in
        loop ()
    | `Conn (c, addr) ->
        (try Lwt_unix.set_close_on_exec c with _ -> ());
        (try Lwt_unix.setsockopt c Unix.TCP_NODELAY true with _ -> ());
        let remote = Conn.string_of_sockaddr addr in
        Lwt.async (fun () ->
            Lwt.catch
              (fun () ->
                match tls () with
                | None -> serve_plain spec c remote
                | Some cfg -> serve_tls spec cfg c remote)
              (fun e ->
                on_conn_exn e;
                close_quietly c));
        loop ()
  in
  Lwt.finalize loop (fun () -> close_quietly fd)

(* Runs the server on an already-bound socket until [stop] resolves.
   [health_fd]: an optional extra plain-HTTP listener serving only /healthz
   and /readyz (e.g. for kubelet probes when the main port requires client
   certificates). *)
let serve ?(watch_interval = 2.0) ?health_fd (st : State.t) fd ~stop =
  let spec = Srv.make ~callback:(Http.callback st) () in
  let watcher =
    if st.cfg.reload_watch then watch_loop st ~interval:watch_interval ~stop
    else Lwt.return_unit
  in
  let health =
    match health_fd with
    | None -> Lwt.return_unit
    | Some hfd ->
        let hspec = Srv.make ~callback:(Http.callback ~health_only:true st) () in
        accept_loop ~spec:hspec ~tls:(fun () -> None) hfd ~stop
  in
  let main = accept_loop ~spec ~tls:(fun () -> st.tls) fd ~stop in
  Lwt.join [ main; health; watcher ]

(* Full process lifecycle. Returns the exit code. *)
let main ?health_listen ~(sources : State.sources) () =
  Integrations.install ();
  Haltsql_auth.Oidc_client.set_logger (fun lvl msg fields ->
      let fields = List.map (fun (k, v) -> (k, `String v)) fields in
      match lvl with `Info -> Log.info msg ~fields | `Warn -> Log.warn msg ~fields);
  let bundle_mode = ref (Bundle_sources.Startup (Hashtbl.create 1)) in
  let pollers = ref [] in
  let loaded =
    match State.load_unchecked sources with
    | Error e -> Error e
    | Ok cfg when cfg.bundle_sources = [] -> (
        match State.check_policy_refs cfg with Ok () -> Ok cfg | Error e -> Error e)
    | Ok cfg -> (
        (* Fetch and verify every remote bundle (or restore it from its cache)
           before the policy references can be checked. *)
        match Lwt_main.run (Bundle_sources.start cfg ~mode:bundle_mode) with
        | Error e -> Error e
        | Ok (srcs, remote) -> (
            pollers := srcs;
            let loaded =
              match State.load ~remote sources with
              | Ok cfg -> Ok cfg
              | Error e -> (
                  (* A fresh bundle the startup checks refuse: start from the cached
                     last good bundles instead, if they pass. *)
                  match Bundle_sources.restored_remote srcs with
                  | None -> Error e
                  | Some (remote', replaced) -> (
                      match State.load ~remote:remote' sources with
                      | Ok cfg ->
                          Bundle_sources.fall_back replaced ~reason:(String.concat "; " e);
                          Ok cfg
                      | Error _ -> Error e))
            in
            match loaded with
            | Ok cfg ->
                Bundle_sources.commit srcs;
                Ok cfg
            | Error e ->
                List.iter Haltsql_bundle_source.stop srcs;
                Error e))
  in
  let remote_at_start () =
    List.filter_map
      (fun src ->
        Option.map
          (fun (u : Haltsql_bundle_source.update) -> (u.source, u.policies))
          (Haltsql_bundle_source.current src))
      !pollers
  in
  match loaded with
  | Error errs ->
      List.iter
        (fun e ->
          Log.error "failed to load configuration" ~fields:[ ("error", `String e) ])
        errs;
      2
  | Ok cfg -> (
      Log.setup ~level:cfg.log_level ~format:cfg.log_format;
      match
        check_auth cfg;
        (match Telemetry.configure cfg.otlp with
        | Ok () -> ()
        | Error e -> raise (Startup_error e));
        let st = State.create ~sources cfg in
        st.remote <- remote_at_start ();
        st.bundle_sources <- !pollers;
        bundle_mode := Bundle_sources.Running st;
        Metrics.set_policies_loaded (List.length st.snap.policies);
        let fd, port = bind_listen cfg.listen in
        let health = Option.map bind_listen health_listen in
        (st, fd, port, health)
      with
      | exception Startup_error e ->
          Log.error e;
          2
      | exception Failure e ->
          Log.error e;
          2
      | exception Unix.Unix_error (e, f, a) ->
          Log.error "startup failed"
            ~fields:
              [
                ("error", `String (Printf.sprintf "%s(%s): %s" f a (Unix.error_message e)));
              ];
          2
      | st, fd, port, health ->
          let stop, stopper = Lwt.wait () in
          let stopping = ref false in
          let shutdown signame _ =
            if not !stopping then begin
              stopping := true;
              Log.info "shutting down" ~fields:[ ("signal", `String signame) ];
              Lwt.wakeup_later stopper ()
            end
          in
          ignore (Lwt_unix.on_signal Sys.sigterm (shutdown "SIGTERM"));
          ignore (Lwt_unix.on_signal Sys.sigint (shutdown "SIGINT"));
          ignore
            (Lwt_unix.on_signal Sys.sighup (fun _ ->
                 Lwt.async (fun () ->
                     let* _ = State.reload_lwt ~reason:"SIGHUP" st in
                     Lwt.return_unit)));
          (try Sys.set_signal Sys.sigpipe Sys.Signal_ignore with _ -> ());
          Log.info "haltsql-server listening"
            ~fields:
              ([
                 ("listen", `String cfg.listen);
                 ("port", `Int port);
                 ("version", `String Haltsql.version);
                 ("policies", `List (List.map (fun (n, _) -> `String n) st.snap.policies));
                 ( "auth",
                   `String
                     (if st.snap.allow_unauthenticated then "optional" else "required") );
                 ("reload_watch", `Bool cfg.reload_watch);
                 ("tls", `Bool (st.tls <> None));
                 ( "client_auth",
                   `String
                     (match cfg.tls with
                     | Some { client_auth = Haltsql.Config.Client_auth_required; _ } ->
                         "required"
                     | Some { client_auth = Haltsql.Config.Client_auth_optional; _ } ->
                         "optional"
                     | _ -> "none") );
                 ("oidc_providers", `Int (List.length cfg.oidc));
                 ("mtls_identities", `Int (List.length cfg.mtls));
                 ( "audit_sinks",
                   `List (List.map (fun (s : Audit.sink) -> `String s.name) st.sinks) );
                 ("bundle_sources", `Int (List.length st.bundle_sources));
                 ("opa", `Bool (st.snap.opa <> None));
                 ("admin_api", `Bool st.snap.admin.admin_enabled);
               ]
              @
              match health with
              | Some (_, hp) -> [ ("health_port", `Int hp) ]
              | None -> []);
          (* Warm the OIDC key caches; failures are logged and retried on demand. *)
          List.iter
            (fun p ->
              Lwt.async (fun () ->
                  let* _ = Haltsql_auth.Oidc_client.refresh p in
                  Lwt.return_unit))
            (Haltsql_auth.Oidc_client.providers st.snap.oidc);
          Lwt_main.run
            (let* () = serve ?health_fd:(Option.map fst health) st fd ~stop in
             (* Give in-flight responses a moment to flush. *)
             let* () = Lwt_unix.sleep 0.2 in
             (* Final flush of batching audit sinks and the OTLP exporter. *)
             let* () =
               Lwt_list.iter_s
                 (fun (s : Audit.sink) ->
                   let* r = Audit.shutdown s in
                   (match r with
                   | Ok () -> ()
                   | Error e ->
                       Log.error "audit sink final flush failed"
                         ~fields:[ ("sink", `String s.name); ("error", `String e) ]);
                   Lwt.return_unit)
                 st.sinks
             in
             Telemetry.shutdown ());
          Bundle_sources.stop st;
          State.close st;
          Log.info "stopped";
          0)
