(* Listener, request dispatch, background loops, static frontend, graceful shutdown. *)

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

(* ---- static frontend ---- *)

let content_type path =
  match String.lowercase_ascii (Filename.extension path) with
  | ".html" -> "text/html; charset=utf-8"
  | ".js" | ".mjs" -> "text/javascript; charset=utf-8"
  | ".css" -> "text/css; charset=utf-8"
  | ".json" -> "application/json"
  | ".svg" -> "image/svg+xml"
  | ".png" -> "image/png"
  | ".ico" -> "image/x-icon"
  | ".woff2" -> "font/woff2"
  | ".txt" -> "text/plain; charset=utf-8"
  | _ -> "application/octet-stream"

let safe_relative path =
  let segs = String.split_on_char '/' path |> List.filter (( <> ) "") in
  if List.exists (fun s -> s = ".." || s = "." || String.contains s '\\') segs then None
  else Some (String.concat "/" segs)

let static dir path =
  match safe_relative path with
  | None -> Api.error `Not_found "NOT_FOUND" "not found"
  | Some rel ->
      let file = Filename.concat dir rel in
      let file =
        if rel <> "" && Sys.file_exists file && not (Sys.is_directory file) then file
        else Filename.concat dir "index.html" (* single-page app fallback *)
      in
      if Sys.file_exists file then
        let body = In_channel.with_open_bin file In_channel.input_all in
        Api.bytes ~content_type:(content_type file)
          ~headers:
            [
              ( "content-security-policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' \
                 'unsafe-inline'; frame-ancestors 'none'" );
            ]
          body
      else Api.error `Not_found "NOT_FOUND" "frontend is not built"

(* ---- dispatch ---- *)

type t = { ctx : Ctx.t; auth : Console_auth.t; routes : Router.route list }

let create ?fetch (ctx : Ctx.t) =
  { ctx; auth = Console_auth.create ?fetch ctx.config.auth; routes = Routes.all }

let handle t (req : Cohttp.Request.t) body : Api.response Lwt.t =
  let path = Uri.path (Cohttp.Request.uri req) in
  let meth = Cohttp.Request.meth req in
  match (meth, path) with
  | (`GET | `HEAD), "/healthz" -> Api.json (`Assoc [ ("status", `String "ok") ])
  | (`GET | `HEAD), "/readyz" ->
      if Store.writable t.ctx.store then Api.json (`Assoc [ ("status", `String "ready") ])
      else
        Api.json ~status:`Service_unavailable
          (`Assoc
             [
               ("status", `String "not_ready");
               ("reason", `String "state_dir is not writable");
             ])
  | _ when String.starts_with ~prefix:"/api/" path -> (
      match Router.lookup t.routes meth path with
      | Router.No_route -> Api.error `Not_found "NOT_FOUND" "no such endpoint"
      | Router.Method_not_allowed ->
          Api.error `Method_not_allowed "METHOD_NOT_ALLOWED" "method not allowed"
      | Router.Found (route, params) -> (
          let* a = Console_auth.authenticate t.auth req in
          match a with
          | Console_auth.Unauthenticated m -> Api.error `Unauthorized "UNAUTHENTICATED" m
          | Console_auth.Ok principal ->
              Lwt.catch
                (fun () ->
                  route.handler t.ctx principal { Router.http = req; body; params })
                (function
                  | Api.Error (status, code, msg) -> Api.error status code msg
                  | exn ->
                      log "error" "%s %s: %s"
                        (Cohttp.Code.string_of_method meth)
                        path (Printexc.to_string exn);
                      Api.error `Internal_server_error "INTERNAL" "internal error")))
  | (`GET | `HEAD), _ -> (
      match t.ctx.config.frontend_dir with
      | Some dir -> static dir path
      | None -> Api.error `Not_found "NOT_FOUND" "no frontend configured (frontend_dir)")
  | _ -> Api.error `Not_found "NOT_FOUND" "not found"

let callback t _conn req body =
  Lwt.catch
    (fun () -> handle t req body)
    (fun exn ->
      log "error" "unhandled: %s" (Printexc.to_string exn);
      Api.error `Internal_server_error "INTERNAL" "internal error")

(* ---- background loops ---- *)

let start_background (ctx : Ctx.t) =
  List.iter
    (fun (name, start) ->
      Lwt.async (fun () ->
          Lwt.catch
            (fun () -> start ctx)
            (fun exn ->
              log "error" "background task %s stopped: %s" name (Printexc.to_string exn);
              Lwt.return_unit)))
    Routes.background

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

(** Binds the listener and returns the bound port and a promise that serves until [stop]
    resolves. *)
let serve ?fetch ?(stop = fst (Lwt.wait ())) (ctx : Ctx.t) =
  match parse_listen ctx.config.listen with
  | Error m -> Lwt.fail_with m
  | Ok (host, port) ->
      let t = create ?fetch ctx in
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
      start_background ctx;
      let server = S.make ~callback:(callback t) () in
      log "info" "haltsql-console listening on %s:%d" host bound;
      let serving = S.create ~stop ~mode:(`TCP (`Socket fd)) server in
      Lwt.return (bound, serving)

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
    | Ok config ->
        let config =
          match listen with Some l -> { config with listen = l } | None -> config
        in
        let config =
          match dev with
          | Some role ->
              log "warn" "dev mode: every request is authenticated as %s"
                (Rbac.role_to_string role);
              {
                config with
                auth =
                  {
                    config.auth with
                    dev = Some { dev_user = "developer@localhost"; dev_role = role };
                  };
              }
          | None -> config
        in
        let store = Store.create config.state_dir in
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
        Lwt.return 0
  in
  Lwt_main.run run
