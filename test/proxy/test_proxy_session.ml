(* The proxy engine (Server + Session) in-process against Fake_pg: session startup,
   enforcement and audit behaviour that needs a live connection but no real PostgreSQL.
   test_proxy_integration / test_proxy_audit cover the same paths against the lab
   database. *)

open Haltsql_pgwire
open Lwt.Syntax

let check_str = Alcotest.(check string)
let check_bool = Alcotest.(check bool)

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let password = "agent-password"

let verifier =
  lazy (Scram.verifier_to_string (Scram.make_verifier ~iterations:4096 password))

let q_ok = "SELECT code FROM app.currencies ORDER BY code LIMIT 10"

let user_json ?(name = "agent") ?(policy = "proxy-test") ?(tenant = "acme")
    ?(verifier = Lazy.force verifier) () : Yojson.Safe.t =
  `Assoc
    [
      ("name", `String name);
      ("scram_verifier", `String verifier);
      ("policy", `String policy);
      ("context", `Assoc [ ("tenant_id", `String tenant) ]);
    ]

let config ~up_port ~audit_file ?(policy = "fixtures/policy.yaml")
    ?(users = [ user_json () ]) ?(limits = []) ?(upstream = []) ?(extra = []) () :
    Yojson.Safe.t =
  `Assoc
    ([
       ("apiVersion", `String "haltsql.dev/v1");
       ("kind", `String "ProxyConfig");
       ("listen", `String "127.0.0.1:0");
       ( "upstream",
         `Assoc
           ([
              ("host", `String "127.0.0.1");
              ("port", `Int up_port);
              ("database", `String "app");
              ("user", `String "svc");
              ("connect_timeout_seconds", `Float 2.);
            ]
           @ upstream) );
       ("policies", `List [ `Assoc [ ("path", `String policy) ] ]);
       ("auth", `Assoc [ ("method", `String "scram"); ("users", `List users) ]);
       ("audit", `Assoc [ ("type", `String "file"); ("path", `String audit_file) ]);
       ("logging", `Assoc [ ("level", `String "error") ]);
       ("shutdown_grace_seconds", `Float 0.2);
     ]
    @ (if limits = [] then [] else [ ("limits", `Assoc limits) ])
    @ extra)

let load j =
  match Proxy_config.of_json ~base_dir:(Sys.getcwd ()) j with
  | Ok c -> c
  | Error es ->
      Alcotest.failf "config: %s"
        (String.concat "; " (List.map Haltsql.Load_error.to_string es))

(* ------------------------------------------------------------- client *)

let connect port =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let* () = Lwt_unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, port)) in
  Lwt.return (Io.of_fd fd)

let fields payload = try Wire.decode_fields payload with Wire.Malformed _ -> []
let field k payload = Option.value ~default:"" (List.assoc_opt k (fields payload))
let is_fatal (tag, payload) = tag = 'E' && field 'S' payload = "FATAL"

(* Messages up to and including ReadyForQuery, a FATAL error or the end of the stream
   (reported as tag '!'). *)
let read_until_ready io =
  let rec go acc =
    let* m =
      Lwt.catch
        (fun () -> Io.read_message io ~max:(1 lsl 24))
        (fun _ -> Lwt.return ('!', ""))
    in
    let acc = m :: acc in
    if fst m = 'Z' || fst m = '!' || is_fatal m then Lwt.return (List.rev acc) else go acc
  in
  Lwt_unix.with_timeout 10. (fun () -> go [])

let tags ms = String.concat "" (List.map (fun (t, _) -> String.make 1 t) ms)
let errors ms = List.filter (fun (t, _) -> t = 'E') ms

let sqlstate ms =
  match errors ms with (_, p) :: _ -> field 'C' p | [] -> "<no error: " ^ tags ms ^ ">"

let message ms = match errors ms with (_, p) :: _ -> field 'M' p | [] -> ""

let scram io ~password =
  let read () = Io.read_message io ~max:65536 in
  let* tag, p = read () in
  match (tag, if tag = 'R' then Wire.decode_auth p else Wire.Auth_other (-1)) with
  | 'R', Wire.Auth_sasl _ -> (
      let st, first = Scram.Client.first ~nonce:(Sec.b64_encode (Sec.random 18)) () in
      let* () =
        Io.write io (Wire.sasl_initial_response ~mechanism:Scram.mechanism first)
      in
      let* _, p = read () in
      match Wire.decode_auth p with
      | Wire.Auth_sasl_continue data -> (
          match Scram.Client.final st ~password data with
          | Error m -> Alcotest.failf "scram: %s" m
          | Ok (_, final) -> Io.write io (Wire.sasl_response final))
      | _ -> Alcotest.fail "expected SASLContinue")
  | _ -> Alcotest.failf "expected AuthenticationSASL, got %C" tag

(* Startup + SCRAM; returns the connection and everything up to ReadyForQuery (or the
   FATAL error that ended the attempt). *)
let login ?(user = "agent") ?(password = password) port =
  let* io = connect port in
  let* () = Io.write io (Wire.encode_startup [ ("user", user); ("database", "app") ]) in
  let* () = scram io ~password in
  let* ms = read_until_ready io in
  Lwt.return (io, ms)

let login_ok ?user ?password port =
  let* io, ms = login ?user ?password port in
  if errors ms <> [] then Alcotest.failf "login failed: %s %s" (sqlstate ms) (message ms);
  Lwt.return io

let simple io sql =
  let* () = Io.write io (Wire.frame 'Q' (sql ^ "\000")) in
  read_until_ready io

(* ---------------------------------------------------------------- env *)

type env = { pg : Fake_pg.t; srv : Server.t; port : int; audit_file : string }

let with_env ?(prepare = fun (_ : Fake_pg.t) -> ()) ?reload ?(cfg = fun c -> c)
    (f : env -> unit Lwt.t) =
  Lwt_main.run
    (let* pg = Fake_pg.start () in
     prepare pg;
     let audit_file = Filename.temp_file "haltsql_proxy_session" ".jsonl" in
     Sys.remove audit_file;
     let initial = load (cfg (config ~up_port:pg.port ~audit_file ())) in
     let reload = Option.map (fun r () -> r ~up_port:pg.port ~audit_file) reload in
     let* srv = Server.start ?reload initial in
     Lwt.finalize
       (fun () -> f { pg; srv; port = Server.port srv; audit_file })
       (fun () ->
         let* () = Server.shutdown srv in
         let* () = Fake_pg.stop pg in
         (try Sys.remove audit_file with _ -> ());
         Lwt.return_unit))

let wait_until ?(timeout = 5.) what f =
  let t0 = Unix.gettimeofday () in
  let rec go () =
    if f () then Lwt.return_unit
    else if Unix.gettimeofday () -. t0 > timeout then
      Alcotest.failf "timed out waiting for %s" what
    else
      let* () = Lwt_unix.sleep 0.02 in
      go ()
  in
  go ()

(* --------------------------------------------------------- search_path *)

let test_search_path_helpers () =
  let p = Upstream.parse_search_path in
  let some = Alcotest.(check (option (list string))) in
  some "quoted" (Some [ "app"; "pg_temp" ]) (p {|"app", "pg_temp"|});
  some "bare, folded" (Some [ "app"; "public" ]) (p "App,PUBLIC");
  some "whitespace" (Some [ "a"; "b" ]) (p "  a ,\tb  ");
  some "quoted keeps case, quotes and commas"
    (Some [ {|We"ird, one|}; "x" ])
    (p {|"We""ird, one", x|});
  some "empty" (Some []) (p "");
  some "empty quoted name" (Some [ "" ]) (p {|""|});
  some "$user" (Some [ "$user"; "public" ]) (p {|"$user", public|});
  some "unterminated quote" None (p {|"app|});
  some "missing separator" None (p "a b");
  some "empty element" None (p "a,,b");
  some "trailing separator" None (p "a,");
  Alcotest.(check (list string))
    "pg_temp appended last" [ "app"; "pg_temp" ]
    (Upstream.pinned_search_path [ "app" ]);
  Alcotest.(check (list string))
    "explicit pg_temp position kept" [ "pg_temp"; "app" ]
    (Upstream.pinned_search_path [ "pg_temp"; "app" ]);
  Alcotest.(check (list string))
    "empty policy path" [ "pg_temp" ]
    (Upstream.pinned_search_path []);
  check_str "value is quoted" {|"app", "Sales ""EU""", "pg_temp"|}
    (Result.get_ok (Upstream.search_path_value [ "app"; {|Sales "EU"|}; "pg_temp" ]));
  check_bool "NUL refused" true
    (Result.is_error (Upstream.search_path_value [ "a\000b" ]));
  (* the value round-trips through the server-side parser *)
  let weird = [ "app"; {|a"b|}; "MiXed"; "with space"; "x,y"; "pg_temp" ] in
  check_bool "round trip" true
    (Upstream.search_path_matches ~expected:weird
       (Result.get_ok (Upstream.search_path_value weird)));
  check_bool "order matters" false
    (Upstream.search_path_matches ~expected:[ "app"; "pg_temp" ] "pg_temp, app");
  check_bool "extra schema" false
    (Upstream.search_path_matches ~expected:[ "app"; "pg_temp" ] "app, public, pg_temp");
  check_bool "case of a quoted name" false
    (Upstream.search_path_matches ~expected:[ "app" ] {|"APP"|})

(* The startup packet pins search_path to the bound policy's, and the proxy confirms it
   with SHOW before the client sees ReadyForQuery. *)
let test_search_path_pinned () =
  with_env (fun e ->
      let* io = login_ok e.port in
      check_str "startup parameter" {|"app", "pg_temp"|}
        (Option.value ~default:"<unset>"
           (List.assoc_opt "search_path" (Fake_pg.startup_params e.pg)));
      Alcotest.(check (list string))
        "confirmed before anything else" [ "SHOW search_path" ] (Fake_pg.queries e.pg);
      let* ms = simple io q_ok in
      check_str "statement relayed" "CZ" (tags ms);
      Alcotest.(check (list string))
        "then the client statement" [ "SHOW search_path"; q_ok ] (Fake_pg.queries e.pg);
      Io.close io)

let refused_search_path prepare () =
  with_env ~prepare (fun e ->
      let* io, ms = login e.port in
      check_str "session refused" "08006" (sqlstate ms);
      check_bool "FATAL" true (List.exists is_fatal ms);
      check_bool "names the cause" true (contains (message ms) "search_path");
      check_bool "no ReadyForQuery reached the client" false
        (String.contains (tags ms) 'Z');
      (* a statement sent anyway is never forwarded *)
      let* () =
        Lwt.catch
          (fun () -> Io.write io (Wire.frame 'Q' (q_ok ^ "\000")))
          (fun _ -> Lwt.return_unit)
      in
      let* () = wait_until "upstream closed" (fun () -> e.pg.closed = 1) in
      check_bool "client statement never forwarded" false
        (List.mem q_ok (Fake_pg.queries e.pg));
      Io.close io)

(* A server (or pooler, or login trigger) that ends up with another search_path. *)
let test_search_path_mismatch =
  refused_search_path (fun pg -> pg.show_search_path <- Some {|"$user", public|})

let test_search_path_garbage =
  refused_search_path (fun pg -> pg.show_search_path <- Some {|"app|})

(* PostgreSQL 18+ reports search_path as a ParameterStatus. *)
let test_search_path_reported_mismatch =
  refused_search_path (fun pg -> pg.report_search_path <- Some "public, app")

let test_search_path_equivalent () =
  with_env
    ~prepare:(fun pg ->
      pg.show_search_path <- Some "app,pg_temp";
      pg.report_search_path <- Some "app, pg_temp")
    (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io q_ok in
      check_str "equivalent spelling accepted" "CZ" (tags ms);
      Io.close io)

let () =
  Sec.init_rng ();
  Alcotest.run "proxy-session"
    [
      ( "search_path",
        [
          Alcotest.test_case "quoting and parsing" `Quick test_search_path_helpers;
          Alcotest.test_case "pinned at startup and confirmed" `Quick
            test_search_path_pinned;
          Alcotest.test_case "mismatch refuses the session" `Quick
            test_search_path_mismatch;
          Alcotest.test_case "unparsable value refuses the session" `Quick
            test_search_path_garbage;
          Alcotest.test_case "ParameterStatus mismatch refuses the session" `Quick
            test_search_path_reported_mismatch;
          Alcotest.test_case "equivalent spelling accepted" `Quick
            test_search_path_equivalent;
        ] );
    ]
