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
      Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
      Lwt_unix.set_close_on_exec fd;
      (try Unix.bind (Lwt_unix.unix_file_descr fd) (Unix.ADDR_INET (addr, port))
       with Unix.Unix_error (e, _, _) ->
         raise
           (Startup_error
              (Printf.sprintf "cannot bind %s: %s" listen (Unix.error_message e))));
      Lwt_unix.listen fd 1024;
      let actual =
        match Unix.getsockname (Lwt_unix.unix_file_descr fd) with
        | Unix.ADDR_INET (_, p) -> p
        | _ -> port
      in
      (fd, actual)

let check_tls (cfg : Haltsql.Config.t) =
  if cfg.tls_cert <> None || cfg.tls_key <> None then
    raise
      (Startup_error
         "TLS is configured (server.tls), but this build of haltsql-server has no TLS \
          support. Terminate TLS in front of haltsql-server (a sidecar proxy such as \
          Envoy/nginx, or your service mesh, e.g. Istio/Linkerd mTLS), bind \
          haltsql-server to 127.0.0.1 or a pod-local address, and remove server.tls from \
          the config. See deploy/README.md.")

let check_auth (cfg : Haltsql.Config.t) =
  if cfg.tokens = [] && not cfg.allow_unauthenticated then
    Log.warn
      "no auth tokens configured and allow_unauthenticated is false: every authenticated \
       endpoint will return 401"

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
      if State.changed st then ignore (State.reload ~reason:"file-change" st);
      watch_loop st ~interval ~stop

(* Runs the HTTP server on an already-bound socket until [stop] resolves. *)
let serve ?(watch_interval = 2.0) (st : State.t) fd ~stop =
  let callback = Http.callback st in
  let server = Cohttp_lwt_unix.Server.make ~callback () in
  let watcher =
    if st.cfg.reload_watch then watch_loop st ~interval:watch_interval ~stop
    else Lwt.return_unit
  in
  let on_exn e =
    match e with
    | Unix.Unix_error ((Unix.EPIPE | Unix.ECONNRESET), _, _) -> ()
    | e ->
        Log.warn "connection error" ~fields:[ ("error", `String (Printexc.to_string e)) ]
  in
  let* () =
    Cohttp_lwt_unix.Server.create ~stop ~on_exn ~mode:(`TCP (`Socket fd)) server
  in
  let* () = watcher in
  Lwt.return_unit

(* Full process lifecycle. Returns the exit code. *)
let main ~(sources : State.sources) () =
  match State.load sources with
  | Error errs ->
      List.iter
        (fun e ->
          Log.error "failed to load configuration" ~fields:[ ("error", `String e) ])
        errs;
      2
  | Ok cfg -> (
      Log.setup ~level:cfg.log_level ~format:cfg.log_format;
      match
        check_tls cfg;
        check_auth cfg;
        let st = State.create ~sources cfg in
        let fd, port = bind_listen cfg.listen in
        (st, fd, port)
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
      | st, fd, port ->
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
                 ignore (State.reload ~reason:"SIGHUP" st)));
          (try Sys.set_signal Sys.sigpipe Sys.Signal_ignore with _ -> ());
          Log.info "haltsql-server listening"
            ~fields:
              [
                ("listen", `String cfg.listen);
                ("port", `Int port);
                ("version", `String Haltsql.version);
                ("policies", `List (List.map (fun (n, _) -> `String n) st.snap.policies));
                ( "auth",
                  `String (if cfg.allow_unauthenticated then "optional" else "required")
                );
                ("reload_watch", `Bool cfg.reload_watch);
              ];
          Lwt_main.run
            (let* () = serve st fd ~stop in
             (* Give in-flight responses a moment to flush. *)
             let* () = Lwt_unix.sleep 0.2 in
             Lwt.return_unit);
          State.close st;
          Log.info "stopped";
          0)
