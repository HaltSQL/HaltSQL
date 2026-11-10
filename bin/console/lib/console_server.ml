(* Listener, request dispatch, supervised background loops, static frontend, graceful
   shutdown. *)

open Lwt.Syntax
module S = Cohttp_lwt_unix.Server

let log level fmt =
  Printf.ksprintf
    (fun m ->
      Printf.eprintf "{\"ts\":%S,\"level\":%S,\"msg\":%s}\n%!"
        (Api.iso8601 (Unix.gettimeofday ()))
        level
        (Yojson.Safe.to_string (`String m)))
    fmt

(* ---- limits ---- *)

let default_request_timeout = 30.
let default_max_in_flight = 512
let default_drain_timeout = 10.
let default_max_connections = 1024
let default_idle_timeout = 15.
let default_probe_interval = 30.
let default_initial_backoff = 1.
let max_backoff = 60.

(* ---- static frontend ---- *)

let content_type path =
  match String.lowercase_ascii (Filename.extension path) with
  | ".html" -> "text/html; charset=utf-8"
  | ".js" | ".mjs" -> "text/javascript; charset=utf-8"
  | ".css" -> "text/css; charset=utf-8"
  | ".json" | ".map" -> "application/json"
  | ".svg" -> "image/svg+xml"
  | ".png" -> "image/png"
  | ".ico" -> "image/x-icon"
  | ".woff2" -> "font/woff2"
  | ".txt" -> "text/plain; charset=utf-8"
  | _ -> "application/octet-stream"

let safe_relative path =
  let segs = String.split_on_char '/' path |> List.filter (( <> ) "") in
  if
    List.exists
      (fun s -> s = ".." || s = "." || String.contains s '\\' || String.contains s '\000')
      segs
  then None
  else Some segs

let csp =
  "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
   frame-ancestors 'none'"

(* The frontend directory is immutable while the console runs, so it is enumerated once
   at startup into the set of servable files: regular files whose real path is inside the
   frontend directory (a symlink resolving outside it is skipped), with no dot segment in
   their path. A request is served from that set only: an unknown path costs a table
   lookup, no filesystem call, and nothing is cached for it. Contents are read on first
   use (with Lwt_io) and kept in memory. Strict-Transport-Security is not sent: the
   console listens on plain TCP and can't tell whether a request reached a TLS
   terminator first. *)
type static_file = { real : string; mutable contents : string option }

type frontend = {
  files : (string, static_file) Hashtbl.t;  (** rel path ("a/b.js") -> file *)
}

let max_frontend_files = 10_000
let max_frontend_depth = 16

let inside root p =
  let r = if String.ends_with ~suffix:"/" root then root else root ^ "/" in
  String.starts_with ~prefix:r p

let is_dot_name n = String.length n > 0 && n.[0] = '.'

let frontend_of_dir dir =
  let files = Hashtbl.create 64 in
  (match Unix.realpath dir with
  | exception Unix.Unix_error _ -> log "warn" "frontend_dir %s does not exist" dir
  | root ->
      (* [visited] holds the real paths of directories already walked (symlink loops). *)
      let visited = Hashtbl.create 16 in
      let rec walk depth real_dir rel_dir =
        if depth <= max_frontend_depth && not (Hashtbl.mem visited real_dir) then begin
          Hashtbl.replace visited real_dir ();
          let entries = try Sys.readdir real_dir with Sys_error _ -> [||] in
          Array.sort compare entries;
          Array.iter
            (fun name ->
              if (not (is_dot_name name)) && Hashtbl.length files < max_frontend_files
              then
                let rel = if rel_dir = "" then name else rel_dir ^ "/" ^ name in
                match Unix.realpath (Filename.concat real_dir name) with
                | exception Unix.Unix_error _ -> ()
                | real when not (inside root real) -> ()
                | real -> (
                    match (Unix.stat real).Unix.st_kind with
                    | Unix.S_REG -> Hashtbl.replace files rel { real; contents = None }
                    | Unix.S_DIR -> walk (depth + 1) real rel
                    | _ -> ()
                    | exception Unix.Unix_error _ -> ()))
            entries
        end
      in
      walk 0 root "";
      if Hashtbl.length files >= max_frontend_files then
        log "warn" "frontend_dir %s: serving only the first %d files" dir
          max_frontend_files);
  { files }

let read_static fe rel =
  match Hashtbl.find_opt fe.files rel with
  | None -> Lwt.return_none
  | Some { contents = Some s; _ } -> Lwt.return_some s
  | Some f ->
      Lwt.catch
        (fun () ->
          let* s =
            Lwt_io.with_file ~mode:Lwt_io.input f.real (fun ic -> Lwt_io.read ic)
          in
          f.contents <- Some s;
          Lwt.return_some s)
        (fun _ -> Lwt.return_none)

let static fe path =
  match safe_relative path with
  | None -> Api.error `Not_found "NOT_FOUND" "not found"
  | Some segs when List.exists is_dot_name segs ->
      Api.error `Not_found "NOT_FOUND" "not found"
  | Some segs -> (
      let rel = String.concat "/" segs in
      let send name body =
        Api.bytes ~content_type:(content_type name)
          ~headers:[ ("content-security-policy", csp) ]
          body
      in
      let* found = if rel = "" then Lwt.return_none else read_static fe rel in
      match found with
      | Some body -> send rel body
      | None -> (
          (* Single-page app fallback for extensionless paths only: a missing /app.js
             is a 404, not index.html served as JavaScript. *)
          let last = match List.rev segs with s :: _ -> s | [] -> "" in
          if Filename.extension last <> "" then
            Api.error `Not_found "NOT_FOUND" "not found"
          else
            let* index = read_static fe "index.html" in
            match index with
            | Some body -> send "index.html" body
            | None -> Api.error `Not_found "NOT_FOUND" "frontend is not built"))

(* ---- background loop supervision ---- *)

type loop_state = Running | Done | Crashed

type loop_status = {
  name : string;
  mutable state : loop_state;
  mutable last_error : string option;
  mutable restarts : int;
  mutable promise : unit Lwt.t option;
}

let loop_state_to_string = function
  | Running -> "running"
  | Done -> "done"
  | Crashed -> "crashed"

let loop_status_to_json (l : loop_status) =
  `Assoc
    [
      ("name", `String l.name);
      ("state", `String (loop_state_to_string l.state));
      ("restarts", `Int l.restarts);
      ("last_error", Api.opt_string l.last_error);
    ]

(** Runs [run] under supervision. An exception marks the loop [Crashed] and restarts it
    after a backoff ([initial_backoff] doubling up to 60 s, reset after a run longer than
    60 s). Returning normally means the loop has nothing (more) to do: [Done], no restart.
*)
let supervise ~initial_backoff (st : loop_status) (run : unit -> unit Lwt.t) =
  let rec go delay =
    st.state <- Running;
    let started = Unix.gettimeofday () in
    let* r =
      Lwt.catch
        (fun () ->
          let* () = run () in
          Lwt.return_ok ())
        (function Lwt.Canceled -> Lwt.fail Lwt.Canceled | e -> Lwt.return_error e)
    in
    match r with
    | Ok () ->
        st.state <- Done;
        Lwt.return_unit
    | Error e ->
        let delay =
          if Unix.gettimeofday () -. started > max_backoff then initial_backoff else delay
        in
        st.state <- Crashed;
        st.last_error <- Some (Printexc.to_string e);
        log "error" "background task %s crashed (restart in %.1fs): %s" st.name delay
          (Printexc.to_string e);
        let* () = Lwt_unix.sleep delay in
        st.restarts <- st.restarts + 1;
        go (Float.min max_backoff (delay *. 2.))
  in
  go initial_backoff

(* ---- dispatch ---- *)

type t = {
  ctx : Ctx.t;
  auth : Console_auth.t;
  routes : Router.route list;
  background : (string * (Ctx.t -> unit Lwt.t)) list;
  loops : loop_status list;
  frontend : frontend option;
  max_body_bytes : int;
  request_timeout : float;
  max_in_flight : int;
  max_connections : int;
  idle_timeout : float;
  mutable connections : int;  (** open client connections *)
  initial_backoff : float;
  probe_interval : float;
  mutable in_flight : int;
  idle : unit Lwt_condition.t;  (** broadcast whenever [in_flight] drops *)
  mutable writable : bool option;  (** cached state_dir probe; None = not probed yet *)
  mutable writable_checked : float option;
  mutable probe : unit Lwt.t option;
}

let create ?fetch ?(routes = Routes.all) ?(background = Routes.background)
    ?(max_body_bytes = Api.max_body_bytes) ?(request_timeout = default_request_timeout)
    ?(max_in_flight = default_max_in_flight) ?(max_connections = default_max_connections)
    ?(idle_timeout = default_idle_timeout) ?(initial_backoff = default_initial_backoff)
    ?(probe_interval = default_probe_interval) (ctx : Ctx.t) =
  {
    ctx;
    auth = Console_auth.create ?fetch ctx.config.auth;
    routes;
    background;
    loops =
      List.map
        (fun (name, _) ->
          { name; state = Running; last_error = None; restarts = 0; promise = None })
        background;
    frontend = Option.map frontend_of_dir ctx.config.frontend_dir;
    max_body_bytes;
    request_timeout;
    max_in_flight;
    max_connections;
    idle_timeout;
    connections = 0;
    initial_backoff;
    probe_interval;
    in_flight = 0;
    idle = Lwt_condition.create ();
    writable = None;
    writable_checked = None;
    probe = None;
  }

(** Per-loop status (also in /readyz). *)
let loop_statuses t = t.loops

let check_writable t =
  let* ok =
    Lwt.catch
      (fun () -> Store.writable t.ctx.store)
      (function Lwt.Canceled -> Lwt.fail Lwt.Canceled | _ -> Lwt.return_false)
  in
  t.writable <- Some ok;
  t.writable_checked <- Some (Unix.gettimeofday ());
  if not ok then log "error" "state_dir %s is not writable" t.ctx.config.state_dir;
  Lwt.return_unit

(** Checks state_dir now, then starts the supervised background loops and the state_dir
    probe (every [probe_interval] seconds; /readyz only reads the cached result). *)
let start t =
  let* () = check_writable t in
  t.probe <-
    Some
      (let rec probe () =
         let* () = Lwt_unix.sleep t.probe_interval in
         let* () = check_writable t in
         probe ()
       in
       probe ());
  List.iter2
    (fun (_, run) st ->
      let p = supervise ~initial_backoff:t.initial_backoff st (fun () -> run t.ctx) in
      st.promise <- Some p;
      Lwt.async (fun () -> Lwt.catch (fun () -> p) (fun _ -> Lwt.return_unit)))
    t.background t.loops;
  Lwt.return_unit

let stop_background t =
  Option.iter Lwt.cancel t.probe;
  List.iter (fun st -> Option.iter Lwt.cancel st.promise) t.loops

let readiness t =
  let crashed = List.filter (fun l -> l.state = Crashed) t.loops in
  let reasons =
    (match t.writable with
      | Some true -> []
      | Some false -> [ "state_dir is not writable" ]
      | None -> [ "state_dir not checked yet" ])
    @ List.map (fun l -> Printf.sprintf "background task %s crashed" l.name) crashed
  in
  let ready = reasons = [] in
  let body =
    `Assoc
      ([ ("status", `String (if ready then "ready" else "not_ready")) ]
      @ (match reasons with [] -> [] | r :: _ -> [ ("reason", `String r) ])
      @ [
          ("reasons", Api.strings reasons);
          ("state_dir_writable", match t.writable with Some b -> `Bool b | None -> `Null);
          ("state_dir_checked", Api.opt_time t.writable_checked);
          ("loops", `List (List.map loop_status_to_json t.loops));
        ])
  in
  if ready then Api.json body else Api.json ~status:`Service_unavailable body

let header req name = Cohttp.Header.get (Cohttp.Request.headers req) name

(* host and port of a Host header; [default_port] when it has none. *)
let host_port ~default_port authority =
  let a = String.lowercase_ascii (String.trim authority) in
  let split_port h rest =
    if String.length rest > 1 && rest.[0] = ':' then
      (h, int_of_string_opt (String.sub rest 1 (String.length rest - 1)))
    else if rest = "" then (h, Some default_port)
    else (h, None)
  in
  let host, port =
    if String.length a > 0 && a.[0] = '[' then
      match String.index_opt a ']' with
      | Some i ->
          split_port
            (String.sub a 0 (i + 1))
            (String.sub a (i + 1) (String.length a - i - 1))
      | None -> (a, None)
    else
      match String.rindex_opt a ':' with
      | Some i -> split_port (String.sub a 0 i) (String.sub a i (String.length a - i))
      | None -> (a, Some default_port)
  in
  (host, port)

(* A present Origin must be one of [allowed] when that is non-empty (public_url /
   allowed_origins: the Host header, which a reverse proxy may rewrite, is not used);
   otherwise it must name the same host and port as Host. "null", malformed origins and a
   missing Host fail. *)
let origin_allowed ~(allowed : Console_config.origin list) req =
  match header req "origin" with
  | None -> true
  | Some o -> (
      match Console_config.parse_origin o with
      | None -> false
      | Some origin when allowed <> [] -> List.mem origin allowed
      | Some origin -> (
          match header req "host" with
          | None -> false
          | Some host_hdr ->
              let default_port = if origin.o_scheme = "https" then 443 else 80 in
              host_port ~default_port host_hdr = (origin.o_host, Some origin.o_port)))

(** CSRF and media-type checks for state-changing /api requests: a present [Origin] must
    be allowed (see {!origin_allowed}), [Sec-Fetch-Site: cross-site] is refused, and a
    non-empty body must be [application/json]. *)
let check_unsafe_request ~allowed req =
  let fetch_site_ok =
    match header req "sec-fetch-site" with
    | Some s -> String.lowercase_ascii (String.trim s) <> "cross-site"
    | None -> true
  in
  if not (origin_allowed ~allowed req && fetch_site_ok) then
    Api.fail `Forbidden "CSRF" "cross-site request refused";
  if Api.request_has_body req && not (Api.is_json_content_type req) then
    Api.fail `Unsupported_media_type "UNSUPPORTED_MEDIA_TYPE"
      "request body must be application/json"

(** Dev mode signs every request in, so a page on another site must not reach it through
    DNS rebinding: the Host header must be a loopback name or address (localhost,
    127.0.0.0/8, [::1]; any port). *)
let check_dev_host req =
  let ok =
    match header req "host" with
    | None -> false
    | Some h -> (
        match host_port ~default_port:80 h with
        | host, Some _ -> Console_config.is_loopback_host host
        | _, None -> false)
  in
  if not ok then
    Api.fail `Forbidden "HOST_NOT_ALLOWED"
      "dev mode only answers requests addressed to a loopback host"

let too_large max =
  Api.fail `Request_entity_too_large "TOO_LARGE" "request body exceeds %d bytes" max

(* Wraps [body] so that reading past [max] bytes raises TOO_LARGE. Nothing is buffered:
   chunks are passed through as they arrive. *)
let limit_body ~max body =
  let src = Cohttp_lwt.Body.to_stream body in
  let seen = ref 0 in
  Cohttp_lwt.Body.of_stream
    (Lwt_stream.from (fun () ->
         let* c = Lwt_stream.get src in
         match c with
         | None -> Lwt.return_none
         | Some s ->
             seen := !seen + String.length s;
             if !seen > max then too_large max else Lwt.return_some s))

let api t ?peer (req : Cohttp.Request.t) body =
  let path = Uri.path (Cohttp.Request.uri req) in
  let meth = Cohttp.Request.meth req in
  (match header req "content-length" with
  | Some l -> (
      match Int64.of_string_opt (String.trim l) with
      | Some n when n > Int64.of_int t.max_body_bytes -> too_large t.max_body_bytes
      | Some n when n >= 0L -> ()
      | _ -> Api.bad_request "invalid content-length")
  | None -> ());
  if t.ctx.config.auth.dev <> None then check_dev_host req;
  (match meth with
  | `GET | `HEAD | `OPTIONS -> ()
  | _ -> check_unsafe_request ~allowed:t.ctx.config.allowed_origins req);
  (* Authenticate before routing, so unauthenticated callers can't probe which endpoints
     exist. *)
  let* a = Console_auth.authenticate t.auth ?peer req in
  match a with
  | Console_auth.Unauthenticated m -> Api.error `Unauthorized "UNAUTHENTICATED" m
  | Console_auth.Authenticated principal -> (
      match Router.lookup t.routes meth path with
      | Router.No_route -> Api.error `Not_found "NOT_FOUND" "no such endpoint"
      | Router.Method_not_allowed ->
          Api.error `Method_not_allowed "METHOD_NOT_ALLOWED" "method not allowed"
      | Router.Found (route, params) ->
          (* Router.lookup percent-decodes captures; an encoded '/' or a dot segment must
             not reach a handler that might use it as a name. *)
          if not (List.for_all (fun (_, v) -> Router.safe_param v) params) then
            Api.bad_request "invalid path parameter";
          let body = limit_body ~max:t.max_body_bytes body in
          route.handler t.ctx principal { Router.http = req; body; params })

let handle t ?peer (req : Cohttp.Request.t) body : Api.response Lwt.t =
  let path = Uri.path (Cohttp.Request.uri req) in
  let meth = Cohttp.Request.meth req in
  match (meth, path) with
  | (`GET | `HEAD), "/healthz" -> Api.json (`Assoc [ ("status", `String "ok") ])
  | (`GET | `HEAD), "/readyz" -> readiness t
  | _ when String.starts_with ~prefix:"/api/" path || path = "/api" ->
      Lwt.catch
        (fun () -> api t ?peer req body)
        (function
          | Api.Error (status, code, msg) -> Api.error status code msg
          | Lwt.Canceled -> Lwt.fail Lwt.Canceled
          | exn ->
              log "error" "%s %s: %s"
                (Cohttp.Code.string_of_method meth)
                path (Printexc.to_string exn);
              Api.error `Internal_server_error "INTERNAL" "internal error")
  | (`GET | `HEAD), _ -> (
      match t.frontend with
      | Some fe -> static fe path
      | None -> Api.error `Not_found "NOT_FOUND" "no frontend configured (frontend_dir)")
  | _ -> Api.error `Not_found "NOT_FOUND" "not found"

(* The TCP peer address as text (IPv4-mapped IPv6 addresses as IPv4). *)
let peer_of_conn ((flow, _) : S.conn) =
  match flow with
  | Conduit_lwt_unix.TCP { ip; _ } ->
      let ip =
        match ip with
        | Ipaddr.V6 v6 -> (
            match Ipaddr.v4_of_v6 v6 with Some v4 -> Ipaddr.V4 v4 | None -> ip)
        | Ipaddr.V4 _ -> ip
      in
      Some (Ipaddr.to_string ip)
  | _ -> None

let is_probe req =
  match Uri.path (Cohttp.Request.uri req) with
  | "/healthz" | "/readyz" -> true
  | _ -> false

let callback t conn req body =
  let peer = peer_of_conn conn in
  if is_probe req then handle t ?peer req body
  else if t.in_flight >= t.max_in_flight then
    Api.error `Service_unavailable "OVERLOADED" "too many requests in flight"
  else begin
    t.in_flight <- t.in_flight + 1;
    Lwt.finalize
      (fun () ->
        Lwt.catch
          (fun () ->
            Lwt.pick
              [
                handle t ?peer req body;
                (let* () = Lwt_unix.sleep t.request_timeout in
                 log "error" "%s %s timed out after %gs"
                   (Cohttp.Code.string_of_method (Cohttp.Request.meth req))
                   (Uri.path (Cohttp.Request.uri req))
                   t.request_timeout;
                 Api.error `Service_unavailable "TIMEOUT" "request timed out");
              ])
          (fun exn ->
            log "error" "unhandled: %s" (Printexc.to_string exn);
            Api.error `Internal_server_error "INTERNAL" "internal error"))
      (fun () ->
        t.in_flight <- t.in_flight - 1;
        Lwt_condition.broadcast t.idle ();
        Lwt.return_unit)
  end

(* ---- connections ---- *)

(* cohttp applies [callback] only once a request's headers are parsed, so the request
   timeout and the in-flight cap don't cover a client that opens a connection and sends
   its headers slowly, or keeps an idle keep-alive connection. Each connection therefore
   has a watchdog: while no request is being handled on it, it is closed [idle_timeout]
   seconds after it was opened or after its last response was produced. That bounds
   header reading and keep-alive idling (and a slow reader of a response). At most
   [max_connections] connections are open at once; one over the cap is closed at once. *)
type conn_state = { mutable active : int; mutable last : float }

let rec watchdog t cs =
  let wait =
    if cs.active > 0 then t.idle_timeout
    else cs.last +. t.idle_timeout -. Unix.gettimeofday ()
  in
  if cs.active = 0 && wait <= 0. then Lwt.return_unit
  else
    let* () = Lwt_unix.sleep (Float.max wait 0.01) in
    watchdog t cs

(* When a refusal was last logged, so a flood of connections can't flood the log. *)
let last_refusal_log = ref 0.

let connection t flow ic oc =
  if t.connections >= t.max_connections then begin
    let now = Unix.gettimeofday () in
    if now -. !last_refusal_log > 10. then begin
      last_refusal_log := now;
      log "warn" "refusing connections: %d connections open (max %d)" t.connections
        t.max_connections
    end;
    Lwt.return_unit (* conduit closes the socket *)
  end
  else begin
    t.connections <- t.connections + 1;
    let cs = { active = 0; last = Unix.gettimeofday () } in
    let tracked conn req body =
      cs.active <- cs.active + 1;
      Lwt.finalize
        (fun () -> callback t conn req body)
        (fun () ->
          cs.active <- cs.active - 1;
          cs.last <- Unix.gettimeofday ();
          Lwt.return_unit)
    in
    let spec = S.make ~callback:tracked () in
    Lwt.finalize
      (fun () ->
        Lwt.pick
          [
            S.callback spec flow (Cohttp_lwt_unix.Private.Input_channel.create ic) oc;
            watchdog t cs;
          ])
      (fun () ->
        t.connections <- t.connections - 1;
        Lwt.return_unit)
  end

let on_connection_exn = function
  | Unix.Unix_error _ -> () (* the client went away *)
  | e -> log "error" "connection: %s" (Printexc.to_string e)

(* Waits until no request is in flight, at most [timeout] seconds. *)
let drain t ~timeout =
  let rec wait () =
    if t.in_flight <= 0 then Lwt.return_unit
    else
      let* () = Lwt_condition.wait t.idle in
      wait ()
  in
  Lwt.pick [ wait (); Lwt_unix.sleep timeout ]

(* ---- listening ---- *)

let parse_listen s =
  match String.rindex_opt s ':' with
  | None -> Error (Printf.sprintf "invalid listen address %S (expected host:port)" s)
  | Some i -> (
      let host = String.sub s 0 i
      and port = String.sub s (i + 1) (String.length s - i - 1) in
      let host = if host = "" || host = "*" then "0.0.0.0" else host in
      let host =
        if String.length host > 1 && host.[0] = '[' then
          String.sub host 1 (String.length host - 2)
        else host
      in
      match int_of_string_opt port with
      | Some p when p >= 0 && p < 65536 -> Ok (host, p)
      | _ -> Error (Printf.sprintf "invalid port in %S" s))

(** Binds the listener, starts the supervised background loops and returns the bound port
    and a promise that serves until [stop] resolves; it then cancels the loops and lets
    in-flight requests finish (at most [drain_timeout] seconds) before resolving.

    [routes] and [background] default to {!Routes.all} and {!Routes.background}; the
    limits default to the constants above. [on_create] receives the server state before it
    starts (tests use it to read loop statuses). *)
let serve ?fetch ?(stop = fst (Lwt.wait ())) ?routes ?background ?max_body_bytes
    ?request_timeout ?max_in_flight ?max_connections ?idle_timeout ?initial_backoff
    ?probe_interval ?(drain_timeout = default_drain_timeout) ?on_create (ctx : Ctx.t) =
  match (Console_config.validate_dev ctx.config, parse_listen ctx.config.listen) with
  | Error m, _ -> Lwt.fail_with ("refusing to serve: " ^ m)
  | _, Error m -> Lwt.fail_with m
  | Ok (), Ok (host, port) ->
      let t =
        create ?fetch ?routes ?background ?max_body_bytes ?request_timeout ?max_in_flight
          ?max_connections ?idle_timeout ?initial_backoff ?probe_interval ctx
      in
      Option.iter (fun f -> f t) on_create;
      let* addrs =
        Lwt_unix.getaddrinfo host (string_of_int port)
          [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
      in
      let addr =
        match addrs with
        | a :: _ -> a.Unix.ai_addr
        | [] -> Unix.ADDR_INET (Unix.inet_addr_of_string host, port)
      in
      let fd = Lwt_unix.socket (Unix.domain_of_sockaddr addr) Unix.SOCK_STREAM 0 in
      Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
      let* () = Lwt_unix.bind fd addr in
      Lwt_unix.listen fd 256;
      let bound =
        match Lwt_unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> port
      in
      let* () = start t in
      log "info" "haltsql-console listening on %s:%d" host bound;
      let serving =
        let* () =
          Conduit_lwt_unix.serve ~stop ~on_exn:on_connection_exn
            ~ctx:(Lazy.force Conduit_lwt_unix.default_ctx)
            ~mode:(`TCP (`Socket fd))
            (connection t)
        in
        log "info" "shutting down: %d request(s) in flight" t.in_flight;
        stop_background t;
        drain t ~timeout:drain_timeout
      in
      Lwt.return (bound, serving)

(** Applies [--listen] and [--dev ROLE] to a loaded config. Dev mode replaces every other
    auth method. The result must pass {!Console_config.validate_dev} (dev mode only on a
    loopback address), whichever of the two overrides is given. *)
let apply_overrides ?listen ?dev (config : Console_config.t) =
  let config =
    match listen with Some l -> { config with listen = l } | None -> config
  in
  match dev with
  | None -> (
      match Console_config.validate_dev config with
      | Error m when listen <> None -> Error ("--listen: " ^ m)
      | Error m -> Error m
      | Ok () -> Ok config)
  | Some role -> (
      let config =
        {
          config with
          auth =
            {
              config.auth with
              oidc = [];
              proxy = None;
              tokens = [];
              dev = Some { dev_user = "developer@localhost"; dev_role = role };
            };
        }
      in
      match Console_config.validate_dev config with
      | Error m -> Error ("--dev: " ^ m)
      | Ok () ->
          log "warn"
            "dev mode: every request is authenticated as developer@localhost with role \
             %s; never use this in production"
            (Rbac.role_to_string role);
          Ok config)

let main ~config_file ?listen ?dev () =
  let run =
    let* r =
      Lwt.catch
        (fun () -> Console_config.load config_file)
        (function Console_config.Invalid m -> Lwt.return (Error m) | e -> Lwt.fail e)
    in
    match r with
    | Error m ->
        log "error" "config %s: %s" config_file m;
        Lwt.return 2
    | Ok config -> (
        match apply_overrides ?listen ?dev config with
        | Error m ->
            log "error" "%s" m;
            prerr_endline ("haltsql-console: " ^ m);
            Lwt.return 2
        | Ok config ->
            let store = Store.create config.state_dir in
            (* Load the activity log now so a damaged log shows up at startup. *)
            Activity.init store;
            let index =
              Index.create ~max_records:config.audit.max_records
                ~retention_seconds:(float_of_int config.audit.retention_hours *. 3600.)
                ()
            in
            let ctx = Ctx.create ~config ~store ~index in
            let stop, wake = Lwt.wait () in
            let on_signal _ = if Lwt.is_sleeping stop then Lwt.wakeup_later wake () in
            ignore (Lwt_unix.on_signal Sys.sigterm on_signal);
            ignore (Lwt_unix.on_signal Sys.sigint on_signal);
            let* _port, serving = serve ~stop ctx in
            let* () = serving in
            log "info" "haltsql-console stopped";
            Lwt.return 0)
  in
  Lwt_main.run run
