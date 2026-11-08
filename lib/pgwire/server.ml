(* Listener; see server.mli. *)

open Lwt.Syntax
open Proxy_config

type fingerprint = (float * int * int) option
(** mtime, size, inode; None: missing *)

type t = {
  mutable gen : Session.shared;  (** what new connections get *)
  sock : Lwt_unix.file_descr;
  bound_port : int;
  conns : (int, Lwt_unix.file_descr) Hashtbl.t;
  mutable next_conn : int;
  mutable stopping : bool;
  stopped : unit Lwt.t;
  wake_stopped : unit Lwt.u;
  idle : unit Lwt_condition.t;
  loader : (unit -> (Proxy_config.t, string list) result) option;
  reload_lock : Lwt_mutex.t;
  mutable reloads : int;
  mutable reload_failures : int;
  mutable last_reload_error : string option;
  mutable watched : (string * fingerprint) list;
}

let port t = t.bound_port
let generation t = t.gen.generation
let config t = t.gen.cfg
let active t = Hashtbl.length t.conns
let time () = Some (Ptime_clock.now ())

let tls_server_config (c : client_tls) =
  let authenticator =
    match c.client_auth with
    | Client_cert_none -> None
    | Client_cert_require -> Some (X509.Authenticator.chain_of_trust ~time c.client_ca)
    | Client_cert_optional ->
        let a = X509.Authenticator.chain_of_trust ~time c.client_ca in
        Some (fun ?ip ~host chain -> if chain = [] then Ok None else a ?ip ~host chain)
  in
  match Tls.Config.server ~certificates:(`Single c.certificates) ?authenticator () with
  | Ok cfg -> cfg
  | Error (`Msg m) -> failwith ("invalid TLS configuration: " ^ m)

let too_many fd =
  let io = Io.of_fd fd in
  let* () =
    Lwt.catch
      (fun () ->
        Io.write io
          (Wire.error_response
             [
               ('S', "FATAL");
               ('V', "FATAL");
               ('C', "53300");
               ( 'M',
                 "sorry, too many clients already (haltsql-proxy limits.max_connections)"
               );
             ]))
      (fun _ -> Lwt.return_unit)
  in
  Io.close io

let rec accept_loop t =
  if t.stopping then Lwt.return_unit
  else
    let* r =
      Lwt.catch
        (fun () ->
          let* fd, _ = Lwt_unix.accept t.sock in
          Lwt.return (Some fd))
        (function
          | Unix.Unix_error ((Unix.EBADF | Unix.EINVAL), _, _) -> Lwt.return None
          | Unix.Unix_error (e, _, _) ->
              Plog.log Plog.Warn "accept failed"
                [ ("error", `String (Unix.error_message e)) ];
              let* () = Lwt_unix.sleep 0.05 in
              Lwt.return None
          | Lwt.Canceled -> Lwt.return None
          | e -> Lwt.fail e)
    in
    match r with
    | None -> accept_loop t
    | Some fd ->
        if t.stopping then (
          Lwt.async (fun () -> too_many fd);
          Lwt.return_unit)
        else if Hashtbl.length t.conns >= t.gen.cfg.limits.max_connections then (
          Plog.log Plog.Warn "connection limit reached"
            [ ("max_connections", `Int t.gen.cfg.limits.max_connections) ];
          Lwt.async (fun () -> too_many fd);
          accept_loop t)
        else begin
          let n = t.next_conn in
          t.next_conn <- n + 1;
          Hashtbl.replace t.conns n fd;
          let id = Sec.random_hex 6 in
          (* the session keeps this snapshot for its whole life *)
          let shared = t.gen in
          Lwt.async (fun () ->
              Lwt.finalize
                (fun () -> Session.handle shared ~id fd)
                (fun () ->
                  Hashtbl.remove t.conns n;
                  Lwt_condition.broadcast t.idle ();
                  Lwt.return_unit));
          accept_loop t
        end

let fingerprint path : fingerprint =
  match Unix.stat path with
  | st -> Some (st.Unix.st_mtime, st.Unix.st_size, st.Unix.st_ino)
  | exception Unix.Unix_error _ -> None

let fingerprints files = List.map (fun f -> (f, fingerprint f)) files

let reload_fields t =
  [
    ("generation", `Int t.gen.generation);
    ("reloads", `Int t.reloads);
    ("reload_failures", `Int t.reload_failures);
  ]

let reload_failed t ~trigger errs =
  t.reload_failures <- t.reload_failures + 1;
  t.last_reload_error <- Some (String.concat "; " errs);
  Plog.log Plog.Error "config reload failed; keeping the current configuration"
    ([
       ("trigger", `String trigger); ("errors", `List (List.map (fun e -> `String e) errs));
     ]
    @ reload_fields t);
  Error errs

let apply_reload t ~trigger (cfg : Proxy_config.t) =
  let old = t.gen.cfg in
  match Option.map tls_server_config cfg.tls with
  | exception Failure m -> reload_failed t ~trigger [ m ]
  | tls_server ->
      let cfg =
        if (cfg.listen_host, cfg.listen_port) <> (old.listen_host, old.listen_port) then (
          Plog.log Plog.Warn
            "listen address changes need a restart; keeping the current one"
            [
              ("listening", `String (Printf.sprintf "%s:%d" old.listen_host t.bound_port));
              ( "configured",
                `String (Printf.sprintf "%s:%d" cfg.listen_host cfg.listen_port) );
            ];
          { cfg with listen_host = old.listen_host; listen_port = old.listen_port })
        else cfg
      in
      (* Sinks are process-wide: two sinks on one file or prefix would fork the chain,
         so a changed sink list only takes effect after a restart. *)
      let cfg =
        if cfg.audit_sinks <> Paudit.spec t.gen.audit then (
          Plog.log Plog.Warn
            "audit sink changes need a restart; keeping the current audit sinks" [];
          { cfg with audit_sinks = old.audit_sinks; audit = old.audit })
        else cfg
      in
      Plog.set_level cfg.log_level;
      t.gen <- { t.gen with cfg; generation = t.gen.generation + 1; tls_server };
      t.reloads <- t.reloads + 1;
      t.last_reload_error <- None;
      t.watched <- fingerprints cfg.source_files;
      Plog.log Plog.Info "config reloaded"
        ([
           ("trigger", `String trigger);
           ("policies", `List (List.map (fun (n, _) -> `String n) cfg.policies));
         ]
        @ reload_fields t);
      Ok ()

let reload t ~trigger =
  match t.loader with
  | None -> Lwt.return (Error [ "reload is not available" ])
  | Some load ->
      Lwt_mutex.with_lock t.reload_lock (fun () ->
          if t.stopping then Lwt.return (Error [ "shutting down" ])
          else
            Lwt.return
              (match load () with
              | Error errs -> reload_failed t ~trigger errs
              | Ok cfg -> apply_reload t ~trigger cfg
              | exception e -> reload_failed t ~trigger [ Printexc.to_string e ]))

let reload_stats t : Yojson.Safe.t =
  `Assoc
    (reload_fields t
    @
    match t.last_reload_error with
    | Some e -> [ ("last_reload_error", `String e) ]
    | None -> [])

(* Polls the config and every file it pulled in; a change triggers a reload. A failed
   reload is retried only after the files change again. *)
let rec watch_loop t =
  let cfg = t.gen.cfg in
  let* () = Lwt_unix.sleep (if cfg.reload.watch then cfg.reload.poll_interval else 1.) in
  if t.stopping then Lwt.return_unit
  else if not t.gen.cfg.reload.watch then watch_loop t
  else
    let now = fingerprints (List.map fst t.watched) in
    if now = t.watched then watch_loop t
    else (
      t.watched <- now;
      let* _ = reload t ~trigger:"watch" in
      watch_loop t)

let start ?reload cfg =
  Sec.init_rng ();
  Plog.set_level cfg.log_level;
  (* a bug in one session must never take the whole proxy down *)
  (Lwt.async_exception_hook :=
     fun e ->
       Plog.log Plog.Error "unhandled exception"
         [ ("error", `String (Printexc.to_string e)) ]);
  let tls_server = Option.map tls_server_config cfg.tls in
  let audit = Paudit.open_ cfg.audit_sinks in
  let* addrs =
    Lwt_unix.getaddrinfo cfg.listen_host
      (string_of_int cfg.listen_port)
      [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM; Unix.AI_PASSIVE ]
  in
  let ai =
    match addrs with
    | [] -> failwith ("cannot resolve listen host " ^ cfg.listen_host)
    | a :: _ -> a
  in
  let sock = Lwt_unix.socket ai.Unix.ai_family Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt sock Unix.SO_REUSEADDR true;
  let* () =
    Lwt.catch
      (fun () -> Lwt_unix.bind sock ai.Unix.ai_addr)
      (fun e ->
        let* () = Lwt_unix.close sock in
        match e with
        | Unix.Unix_error (err, _, _) ->
            Lwt.fail
              (Failure
                 (Printf.sprintf "cannot listen on %s:%d: %s" cfg.listen_host
                    cfg.listen_port (Unix.error_message err)))
        | e -> Lwt.fail e)
  in
  Lwt_unix.listen sock 128;
  let bound_port =
    match Lwt_unix.getsockname sock with
    | Unix.ADDR_INET (_, p) -> p
    | _ -> cfg.listen_port
  in
  let stopped, wake_stopped = Lwt.wait () in
  let t =
    {
      gen =
        {
          Session.cfg;
          generation = 1;
          tls_server;
          audit;
          mock_secret = Sec.random 32;
          cancel_table = Hashtbl.create 64;
        };
      sock;
      bound_port;
      conns = Hashtbl.create 64;
      next_conn = 0;
      stopping = false;
      stopped;
      wake_stopped;
      idle = Lwt_condition.create ();
      loader = reload;
      reload_lock = Lwt_mutex.create ();
      reloads = 0;
      reload_failures = 0;
      last_reload_error = None;
      watched = fingerprints cfg.source_files;
    }
  in
  Plog.log Plog.Info "listening"
    [
      ("address", `String (Printf.sprintf "%s:%d" cfg.listen_host bound_port));
      ("tls", `Bool (cfg.tls <> None));
      ( "upstream",
        `String
          (Printf.sprintf "%s:%d/%s" cfg.upstream.host cfg.upstream.port
             cfg.upstream.database) );
      ("policies", `List (List.map (fun (n, _) -> `String n) cfg.policies));
      ( "audit_sinks",
        `List
          (List.map
             (fun (s : Proxy_config.audit_sink_spec) ->
               `String (Proxy_config.sink_name s.sink))
             cfg.audit_sinks) );
      ("reload_watch", `Bool cfg.reload.watch);
    ];
  Lwt.async (fun () -> accept_loop t);
  if t.loader <> None then Lwt.async (fun () -> watch_loop t);
  Lwt.return t

let shutdown t =
  if t.stopping then t.stopped
  else begin
    t.stopping <- true;
    Plog.log Plog.Info "shutting down" [ ("active_connections", `Int (active t)) ];
    let* () = Lwt.catch (fun () -> Lwt_unix.close t.sock) (fun _ -> Lwt.return_unit) in
    let rec drain () =
      if Hashtbl.length t.conns = 0 then Lwt.return_unit
      else
        let* () = Lwt_condition.wait t.idle in
        drain ()
    in
    let* () = Lwt.pick [ drain (); Lwt_unix.sleep t.gen.cfg.shutdown_grace ] in
    (* force-close what is left; sessions then finish on I/O errors *)
    Hashtbl.iter
      (fun _ fd -> try Lwt_unix.shutdown fd Unix.SHUTDOWN_ALL with _ -> ())
      t.conns;
    let* () = Lwt.pick [ drain (); Lwt_unix.sleep 2. ] in
    let* () = Paudit.close t.gen.audit in
    Plog.log Plog.Info "stopped"
      [ ("audit", Paudit.stats_json t.gen.audit); ("reload", reload_stats t) ];
    Lwt.wakeup_later t.wake_stopped ();
    Lwt.return_unit
  end

let wait t = t.stopped
