(* Shared helpers for console tests: an in-process console on an ephemeral port with a
   fresh state dir, HTTP calls, and audit-record builders. *)

open Lwt.Syntax
module Console = Haltsql_console

let temp_dir prefix =
  let d =
    Filename.concat
      (Filename.get_temp_dir_name ())
      (Printf.sprintf "%s-%d-%06d" prefix (Unix.getpid ()) (Random.int 1_000_000))
  in
  Unix.mkdir d 0o700;
  d

(** A config document with dev auth as [role] (default admin) plus [extra] top-level keys.
    [listen] is forced to 127.0.0.1:0 and [state_dir] to a fresh directory. *)
let config ?(role = "admin") ?(extra = []) () =
  let state = temp_dir "console-state" in
  let base =
    [
      ("listen", `String "127.0.0.1:0");
      ("state_dir", `String state);
      ("environment", `Assoc [ ("org", `String "Acme Corp"); ("name", `String "Test") ]);
      ( "auth",
        `Assoc
          [
            ( "dev",
              `Assoc [ ("user", `String "tester@acme.test"); ("role", `String role) ] );
          ] );
    ]
  in
  let merged =
    List.fold_left (fun acc (k, v) -> (k, v) :: List.remove_assoc k acc) base extra
  in
  Console.Console_config.of_json (`Assoc merged)

type running = { ctx : Console.Ctx.t; port : int; stop : unit Lwt.u }

(** Starts a console for [cfg]. Background loops run unless [~background:false]. *)
let start ?(background = true) ?fetch (cfg : Console.Console_config.t) =
  let store = Console.Store.create cfg.state_dir in
  let index = Console.Index.create () in
  let ctx = Console.Ctx.create ~config:cfg ~store ~index in
  let stop_p, stop = Lwt.wait () in
  if background then Console.Console_server.start_background ctx;
  let t = Console.Console_server.create ?fetch ctx in
  let* addrs =
    Lwt_unix.getaddrinfo "127.0.0.1" "0" [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
  in
  let addr = (List.hd addrs).Unix.ai_addr in
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
  let* () = Lwt_unix.bind fd addr in
  Lwt_unix.listen fd 64;
  let port =
    match Lwt_unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> assert false
  in
  let server =
    Cohttp_lwt_unix.Server.make ~callback:(Console.Console_server.callback t) ()
  in
  Lwt.async (fun () ->
      Cohttp_lwt_unix.Server.create ~stop:stop_p ~mode:(`TCP (`Socket fd)) server);
  Lwt.return { ctx; port; stop }

let stop r = Lwt.wakeup_later r.stop ()

(** [with_console cfg f]: starts, runs [f], stops (also on failure). Runs [Lwt_main.run].
*)
let with_console ?background ?fetch cfg f =
  Lwt_main.run
    (let* r = start ?background ?fetch cfg in
     Lwt.finalize
       (fun () -> f r)
       (fun () ->
         stop r;
         Lwt.return_unit))

let uri r path = Uri.of_string (Printf.sprintf "http://127.0.0.1:%d%s" r.port path)

let headers_of ?token ?reason extra =
  let h = Cohttp.Header.of_list extra in
  let h =
    match token with
    | Some t -> Cohttp.Header.add h "authorization" ("Bearer " ^ t)
    | None -> h
  in
  match reason with Some x -> Cohttp.Header.add h "x-haltsql-reason" x | None -> h

let body_json body =
  let* s = Cohttp_lwt.Body.to_string body in
  Lwt.return (try Yojson.Safe.from_string s with _ -> `String s)

(** GET; returns (status code, JSON body). *)
let get ?token ?reason ?(headers = []) r path =
  let* resp, body =
    Cohttp_lwt_unix.Client.get ~headers:(headers_of ?token ?reason headers) (uri r path)
  in
  let* j = body_json body in
  Lwt.return (Cohttp.Code.code_of_status (Cohttp.Response.status resp), j)

let send meth ?token ?reason ?(headers = []) r path (json : Yojson.Safe.t) =
  let headers =
    headers_of ?token ?reason (("content-type", "application/json") :: headers)
  in
  let body = Cohttp_lwt.Body.of_string (Yojson.Safe.to_string json) in
  let* resp, body = Cohttp_lwt_unix.Client.call ~headers ~body meth (uri r path) in
  let* j = body_json body in
  Lwt.return (Cohttp.Code.code_of_status (Cohttp.Response.status resp), j)

let post ?token ?reason ?headers r path json =
  send `POST ?token ?reason ?headers r path json

let patch ?token ?reason ?headers r path json =
  send `PATCH ?token ?reason ?headers r path json

let member path (j : Yojson.Safe.t) =
  List.fold_left
    (fun j k ->
      match j with
      | `Assoc l -> Option.value (List.assoc_opt k l) ~default:`Null
      | _ -> `Null)
    j
    (String.split_on_char '.' path)

(* ---- audit records ---- *)

(** A haltsql-server audit record. [codes] non-empty and [allowed=false] = a denial. *)
let server_record ?(request_id = Printf.sprintf "req-%06d" (Random.int 1_000_000))
    ?(ts = Unix.gettimeofday ()) ?(caller = "token:agent") ?(caller_type = "token")
    ?(policy = "analytics") ?(policy_version = "sha256:abc") ?(allowed = true)
    ?(shadow = false) ?(codes = []) ?(fingerprint = "6c1e0b7f3a2d9e41")
    ?(elapsed_us = 240) ?sql ?(prev_hash = "0") ?(hash = "1") () : Yojson.Safe.t =
  `Assoc
    ([
       ("ts", `String (Console.Api.iso8601 ts));
       ("request_id", `String request_id);
       ("caller", `String caller);
       ("caller_type", `String caller_type);
       ("policy", `String policy);
       ("policy_version", `String policy_version);
       ("allowed", `Bool allowed);
       ("shadow", `Bool shadow);
       ("codes", `List (List.map (fun c -> `String c) codes));
       ("sql_sha256", `String (Haltsql.sha256_hex (Option.value sql ~default:request_id)));
       ("fingerprint", `String fingerprint);
       ("elapsed_us", `Int elapsed_us);
       ("prev_hash", `String prev_hash);
       ("hash", `String hash);
     ]
    @ match sql with Some s -> [ ("sql", `String s) ] | None -> [])

(** Adds records to a running console's index as if ingested from [verifier]. *)
let load_records ?(verifier = "haltsql-1") (r : running) records =
  List.iteri
    (fun i j ->
      match
        Console.Index.entry_of_json ~verifier
          ~location:(Printf.sprintf "test.jsonl#L%d" (i + 1))
          ~seq:i ~now:(Unix.gettimeofday ()) j
      with
      | Some e -> Console.Index.add r.ctx.index e
      | None -> Alcotest.failf "not an audit record: %s" (Yojson.Safe.to_string j))
    records

let check_status msg expected (got, body) =
  if got <> expected then
    Alcotest.failf "%s: expected HTTP %d, got %d: %s" msg expected got
      (Yojson.Safe.to_string body)
