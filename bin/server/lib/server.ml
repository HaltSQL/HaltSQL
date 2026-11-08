(** Listener, connection limits, signals, hot-reload watcher and process lifecycle for
    haltsql-server. See server.mli. *)

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

(* ---- connection limits ---- *)

type limits = {
  max_connections : int;
  request_timeout : float;
  idle_timeout : float;
  max_header_bytes : int;
  shutdown_timeout : float;
}

let default_limits =
  {
    max_connections = 1024;
    request_timeout = 30.;
    idle_timeout = 60.;
    max_header_bytes = 65536;
    shutdown_timeout = 15.;
  }

(* The health listener gets its own small connection budget, so probes keep
   working while the main listener is saturated. *)
let health_max_connections = 64

let validate_limits l =
  let check ok msg = if ok then [] else [ msg ] in
  match
    check (l.max_connections >= 1) "max connections must be at least 1"
    @ check (l.request_timeout > 0.) "request timeout must be positive"
    @ check (l.idle_timeout > 0.) "idle timeout must be positive"
    @ check (l.max_header_bytes >= 1024) "max header bytes must be at least 1024"
    @ check (l.shutdown_timeout >= 0.) "shutdown timeout must not be negative"
  with
  | [] -> Ok ()
  | errs -> Error (String.concat "; " errs)

(* ---- HTTP over plain TCP or TLS ----

   cohttp's server is instantiated over its Unix IO module with our own
   connection type, so handlers see the verified client identity of TLS
   connections. We run our own accept loop: each connection gets the TLS
   configuration current at accept time (certificates reload without a
   restart).

   cohttp has no timeouts or size limits of its own, so the byte streams it
   reads from and writes to are wrapped (see [channels]):
   - between requests a connection may stay silent for [idle_timeout];
   - once the first byte of a request arrives, its head and body must arrive
     within [request_timeout], and the head may not exceed [max_header_bytes]
     (slowloris, unbounded headers);
   - a write that makes no progress for [idle_timeout] fails.
   On any of these the connection is closed. *)

module Io = struct
  include (
    Cohttp_lwt_unix.Private.IO :
      module type of Cohttp_lwt_unix.Private.IO with type conn := Conduit_lwt_unix.flow)

  type conn = Conn.t
end

module Srv = Cohttp_lwt.Make_server (Io)

let handshake_timeout = 10.0
let close_quietly fd = Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)

let shutdown_quietly fd =
  try Lwt_unix.shutdown fd Unix.SHUTDOWN_ALL with Unix.Unix_error _ -> ()

let on_conn_exn = function
  | Unix.Unix_error
      ((Unix.EPIPE | Unix.ECONNRESET | Unix.EBADF | Unix.ENOTCONN | Unix.ETIMEDOUT), _, _)
    ->
      ()
  | Tls_lwt.Tls_alert _ | Tls_lwt.Tls_failure _ | End_of_file | Lwt_io.Channel_closed _ ->
      ()
  | e -> Log.warn "connection error" ~fields:[ ("error", `String (Printexc.to_string e)) ]

(* Where a connection is in its request cycle, as seen by its reads. *)
type phase =
  | Idle  (** between requests: waiting for the first byte of the next one *)
  | Reading_head of { deadline : float; mutable bytes : int }
  | In_handler of { deadline : float }  (** the handler runs and may read the body *)
  | Responding  (** the handler returned; the response is being written *)

type tracked = {
  fd : Lwt_unix.file_descr;
  mutable conn : Conn.t;
  mutable phase : phase;
  mutable waiting : bool;
      (** blocked reading for the next request: nothing is in flight, so the connection
          may be closed when draining *)
  mutable oc : Lwt_io.output_channel option;
}

(* The open connections of one listener. *)
type registry = {
  conns : (int, tracked) Hashtbl.t;
  mutable next_id : int;
  changed : unit Lwt_condition.t;  (** broadcast when a connection closes *)
}

let new_registry () =
  { conns = Hashtbl.create 64; next_id = 0; changed = Lwt_condition.create () }

exception Timed_out

let with_timeout secs f =
  if secs <= 0. then Lwt.fail Timed_out
  else
    Lwt.pick
      [
        f ();
        (let* () = Lwt_unix.sleep secs in
         Lwt.fail Timed_out);
      ]

(* Wraps raw [read]/[write] functions into Lwt_io channels that enforce the
   limits for connection [t]. A read that times out or overruns the header cap
   stops input and shuts the socket down, which ends the connection. *)
let channels ~limits (t : tracked) ~read ~write =
  let kill () =
    Conn.discard_input t.conn;
    shutdown_quietly t.fd
  in
  let read_into buf off len =
    if Conn.input_discarded t.conn then Lwt.return 0
    else
      let now = Unix.gettimeofday () in
      let between_requests =
        match t.phase with Idle | Responding -> true | _ -> false
      in
      let timeout =
        match t.phase with
        | Idle | Responding -> limits.idle_timeout
        | Reading_head { deadline; _ } | In_handler { deadline } -> deadline -. now
      in
      t.waiting <- between_requests;
      Lwt.catch
        (fun () ->
          let* n = with_timeout timeout (fun () -> read buf off len) in
          t.waiting <- false;
          (if n > 0 then
             match t.phase with
             | Idle | Responding ->
                 t.phase <-
                   Reading_head
                     {
                       deadline = Unix.gettimeofday () +. limits.request_timeout;
                       bytes = n;
                     }
             | Reading_head h -> h.bytes <- h.bytes + n
             | In_handler _ -> ());
          match t.phase with
          | Reading_head { bytes; _ } when bytes > limits.max_header_bytes ->
              Log.info "request head too large; closing connection"
                ~fields:[ ("remote", `String t.conn.remote) ];
              kill ();
              Lwt.return 0
          | _ -> Lwt.return n)
        (fun e ->
          t.waiting <- false;
          (match e with
          | Timed_out ->
              Log.debug
                (if between_requests then "idle connection timed out"
                 else "request timed out; closing connection")
                ~fields:[ ("remote", `String t.conn.remote) ]
          | _ -> ());
          kill ();
          Lwt.return 0)
  in
  let write_from buf off len =
    Lwt.catch
      (fun () -> with_timeout limits.idle_timeout (fun () -> write buf off len))
      (function
        | Timed_out ->
            kill ();
            Lwt.fail (Unix.Unix_error (Unix.ETIMEDOUT, "write", ""))
        | e -> Lwt.fail e)
  in
  let ic = Lwt_io.make ~mode:Lwt_io.input read_into in
  let oc = Lwt_io.make ~mode:Lwt_io.output write_from in
  t.oc <- Some oc;
  (ic, oc)

(* The cohttp server for connection [t]: marks the request cycle around the
   handler so reads know whether they wait for a new request or read a body. *)
let spec_for ~limits (t : tracked) callback =
  Srv.make
    ~callback:(fun conn req body ->
      t.phase <- In_handler { deadline = Unix.gettimeofday () +. limits.request_timeout };
      Lwt.finalize
        (fun () -> callback conn req body)
        (fun () ->
          t.phase <- Responding;
          Lwt.return_unit))
    ()

let flush_quietly oc =
  Lwt.catch
    (fun () -> with_timeout 1.0 (fun () -> Lwt_io.flush oc))
    (fun _ -> Lwt.return_unit)

let serve_conn ~limits ~callback (t : tracked) ~read ~write =
  let ic, oc = channels ~limits t ~read ~write in
  Lwt.finalize
    (fun () ->
      Srv.callback (spec_for ~limits t callback) t.conn
        (Cohttp_lwt_unix.Private.Input_channel.create ic)
        oc)
    (fun () -> flush_quietly oc)

let serve_plain ~limits ~callback t =
  serve_conn ~limits ~callback t
    ~read:(fun buf off len -> Lwt_bytes.read t.fd buf off len)
    ~write:(fun buf off len -> Lwt_bytes.write t.fd buf off len)

let serve_tls ~limits ~callback tls_cfg (t : tracked) =
  let* session =
    Lwt.catch
      (fun () ->
        Lwt.pick
          [
            (let* s = Tls_lwt.Unix.server_of_fd tls_cfg t.fd in
             Lwt.return_ok s);
            (let* () = Lwt_unix.sleep handshake_timeout in
             Lwt.return_error "TLS handshake timed out");
          ])
      (fun e -> Lwt.return_error (Printexc.to_string e))
  in
  match session with
  | Error e ->
      Log.debug "TLS handshake failed"
        ~fields:[ ("remote", `String t.conn.remote); ("error", `String e) ];
      Lwt.return_unit
  | Ok s ->
      let peer =
        Option.map Haltsql_auth.Mtls.peer_of_certificate (Tls_setup.peer_certificate s)
      in
      t.conn <- Conn.make ~remote:t.conn.remote ~tls:true ~peer;
      Lwt.finalize
        (fun () ->
          serve_conn ~limits ~callback t
            ~read:(fun buf off len -> Tls_lwt.Unix.read_bytes s buf off len)
            ~write:(fun buf off len ->
              let* () = Tls_lwt.Unix.write_bytes s buf off len in
              Lwt.return len))
        (fun () ->
          Lwt.catch
            (fun () -> with_timeout 1.0 (fun () -> Tls_lwt.Unix.close s))
            (fun _ -> Lwt.return_unit))

(* Blocks until [reg] has room for another connection, or [stop]. *)
let rec wait_for_capacity reg ~max ~stop ~warned =
  if Hashtbl.length reg.conns < max then Lwt.return `Ready
  else begin
    if not !warned then begin
      warned := true;
      Log.warn "connection limit reached; new connections wait in the listen backlog"
        ~fields:[ ("max_connections", `Int max) ]
    end;
    let* r =
      Lwt.pick
        [
          (let* () = Lwt_condition.wait reg.changed in
           Lwt.return `Changed);
          (let* () = stop in
           Lwt.return `Stop);
        ]
    in
    match r with
    | `Stop -> Lwt.return `Stop
    | `Changed -> wait_for_capacity reg ~max ~stop ~warned
  end

(* Accepts connections on [fd] until [stop]; [tls ()] gives the TLS config to
   use for a new connection (None: plain HTTP). At most [max] connections are
   open at once: beyond that the loop stops accepting (backpressure through
   the kernel's listen backlog) rather than accepting and refusing. *)
let accept_loop ~limits ~max ~callback ~tls ?(on_change = ignore) reg fd ~stop =
  let stopped = ref false in
  let warned = ref false in
  let register c remote =
    let id = reg.next_id in
    reg.next_id <- id + 1;
    let t =
      { fd = c; conn = Conn.plain remote; phase = Idle; waiting = false; oc = None }
    in
    Hashtbl.replace reg.conns id t;
    on_change (Hashtbl.length reg.conns);
    (id, t)
  in
  let unregister id =
    Hashtbl.remove reg.conns id;
    on_change (Hashtbl.length reg.conns);
    Lwt_condition.broadcast reg.changed ()
  in
  let rec loop () =
    let* cap = wait_for_capacity reg ~max ~stop ~warned in
    match cap with
    | `Stop ->
        stopped := true;
        Lwt.return_unit
    | `Ready -> (
        if Hashtbl.length reg.conns < max / 2 then warned := false;
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
            (* e.g. EMFILE: back off instead of spinning *)
            Log.warn "accept failed" ~fields:[ ("error", `String (Printexc.to_string e)) ];
            let* () = Lwt_unix.sleep 0.05 in
            loop ()
        | `Conn (c, addr) ->
            (try Lwt_unix.set_close_on_exec c with Unix.Unix_error _ -> ());
            (try Lwt_unix.setsockopt c Unix.TCP_NODELAY true
             with Unix.Unix_error _ -> ());
            let id, t = register c (Conn.string_of_sockaddr addr) in
            Lwt.async (fun () ->
                Lwt.finalize
                  (fun () ->
                    Lwt.catch
                      (fun () ->
                        match tls () with
                        | None -> serve_plain ~limits ~callback t
                        | Some cfg -> serve_tls ~limits ~callback cfg t)
                      (fun e ->
                        on_conn_exn e;
                        Lwt.return_unit))
                  (fun () ->
                    let* () = close_quietly c in
                    unregister id;
                    Lwt.return_unit));
            loop ())
  in
  Lwt.finalize loop (fun () -> close_quietly fd)

(* Closes connections that have nothing in flight (blocked waiting for their
   next request). Their last response is flushed first. *)
let close_idle reg =
  Hashtbl.iter
    (fun _ t ->
      if t.waiting then begin
        t.waiting <- false;
        Conn.discard_input t.conn;
        Lwt.async (fun () ->
            let* () =
              match t.oc with Some oc -> flush_quietly oc | None -> Lwt.return_unit
            in
            shutdown_quietly t.fd;
            Lwt.return_unit)
      end)
    reg.conns

(* Graceful drain after the listeners closed: idle keep-alive connections are
   closed now; in-flight requests get up to [timeout] seconds to complete (their
   responses carry "connection: close", so their connections end afterwards);
   whatever is left is then closed forcibly. *)
let drain reg ~timeout =
  let rec wait_empty () =
    close_idle reg;
    if Hashtbl.length reg.conns = 0 then Lwt.return_unit
    else
      let* () = Lwt_condition.wait reg.changed in
      wait_empty ()
  in
  let n = Hashtbl.length reg.conns in
  if n = 0 then Lwt.return_unit
  else begin
    Log.info "draining connections"
      ~fields:[ ("open_connections", `Int n); ("timeout_s", `Float timeout) ];
    let* () =
      Lwt.pick
        [
          wait_empty ();
          (let* () = Lwt_unix.sleep timeout in
           Lwt.return_unit);
        ]
    in
    let left = Hashtbl.length reg.conns in
    if left = 0 then Lwt.return_unit
    else begin
      Log.warn "shutdown timeout reached; closing remaining connections"
        ~fields:[ ("open_connections", `Int left) ];
      Hashtbl.iter
        (fun _ t ->
          Conn.discard_input t.conn;
          shutdown_quietly t.fd)
        reg.conns;
      Lwt.pick
        [
          wait_empty ();
          (let* () = Lwt_unix.sleep 1.0 in
           Lwt.return_unit);
        ]
    end
  end

(* Runs the server on an already-bound socket until [stop] resolves, then
   drains. [health_fd]: an optional extra plain-HTTP listener serving only
   /healthz and /readyz (e.g. for kubelet probes when the main port requires
   client certificates). *)
let serve ?(watch_interval = 2.0) ?health_fd ?(limits = default_limits) (st : State.t) fd
    ~stop =
  let reg = new_registry () in
  let health_reg = new_registry () in
  let watcher =
    if st.cfg.reload_watch then watch_loop st ~interval:watch_interval ~stop
    else Lwt.return_unit
  in
  let health =
    match health_fd with
    | None -> Lwt.return_unit
    | Some hfd ->
        accept_loop ~limits ~max:health_max_connections
          ~callback:(Http.callback ~health_only:true st)
          ~tls:(fun () -> None)
          health_reg hfd ~stop
  in
  let main =
    accept_loop ~limits ~max:limits.max_connections ~callback:(Http.callback st)
      ~tls:(fun () -> st.tls)
      ~on_change:Metrics.set_open_connections reg fd ~stop
  in
  let draining =
    let* () = stop in
    (* Readiness turns 503 and responses carry "connection: close" from now on. *)
    st.draining <- true;
    Lwt.return_unit
  in
  let* () = Lwt.join [ main; health; watcher; draining ] in
  Lwt.join
    [
      drain reg ~timeout:limits.shutdown_timeout;
      drain health_reg ~timeout:(Float.min 1.0 limits.shutdown_timeout);
    ]

(* Full process lifecycle. Returns the exit code. *)
let main ?health_listen ?(limits = default_limits) ~(sources : State.sources) () =
  Integrations.install ();
  Haltsql_auth.Oidc_client.set_logger (fun lvl msg fields ->
      let fields = List.map (fun (k, v) -> (k, `String v)) fields in
      match lvl with `Info -> Log.info msg ~fields | `Warn -> Log.warn msg ~fields);
  match validate_limits limits with
  | Error e ->
      Log.error "invalid connection limits" ~fields:[ ("error", `String e) ];
      2
  | Ok () -> (
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
                              Bundle_sources.fall_back replaced
                                ~reason:(String.concat "; " e);
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
                    ( "error",
                      `String (Printf.sprintf "%s(%s): %s" f a (Unix.error_message e)) );
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
              (* A bug in one connection's handler must never take the process
             down: log it and carry on. *)
              (Lwt.async_exception_hook :=
                 fun e ->
                   Log.error "unhandled exception"
                     ~fields:[ ("error", `String (Printexc.to_string e)) ]);
              Log.info "haltsql-server listening"
                ~fields:
                  ([
                     ("listen", `String cfg.listen);
                     ("port", `Int port);
                     ("version", `String Haltsql.version);
                     ( "policies",
                       `List (List.map (fun (n, _) -> `String n) st.snap.policies) );
                     ( "auth",
                       `String
                         (if st.snap.allow_unauthenticated then "optional" else "required")
                     );
                     ("reload_watch", `Bool cfg.reload_watch);
                     ("tls", `Bool (st.tls <> None));
                     ( "client_auth",
                       `String
                         (match cfg.tls with
                         | Some { client_auth = Haltsql.Config.Client_auth_required; _ }
                           ->
                             "required"
                         | Some { client_auth = Haltsql.Config.Client_auth_optional; _ }
                           ->
                             "optional"
                         | _ -> "none") );
                     ("oidc_providers", `Int (List.length cfg.oidc));
                     ("mtls_identities", `Int (List.length cfg.mtls));
                     ("max_connections", `Int limits.max_connections);
                     ("max_request_bytes", `Int cfg.max_request_bytes);
                     ( "audit_sinks",
                       `List (List.map (fun (s : Audit.sink) -> `String s.name) st.sinks)
                     );
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
                (let* () = serve ?health_fd:(Option.map fst health) ~limits st fd ~stop in
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
              0))
