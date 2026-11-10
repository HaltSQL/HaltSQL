(* The proxy engine (Server + Session) in-process against Fake_pg: session startup,
   enforcement and audit behaviour that needs a live connection but no real PostgreSQL.
   test_proxy_integration / test_proxy_audit cover the same paths against the lab
   database. *)

open Haltsql_pgwire
open Lwt.Syntax

let check_str = Alcotest.(check string)
let check_bool = Alcotest.(check bool)
let check_int = Alcotest.(check int)

module Chain = Haltsql_cloud.Audit_chain

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let password = "agent-password"

let verifier =
  lazy (Scram.verifier_to_string (Scram.make_verifier ~iterations:4096 password))

let q_ok = "SELECT code FROM app.currencies ORDER BY code LIMIT 10"
let q_denied = "SELECT email FROM app.users LIMIT 1"

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

let parse ?(name = "") q =
  Wire.encode_parse { Wire.stmt = name; query = q; param_types = [] }

let bind ?(portal = "") ?(stmt = "") params =
  Wire.encode_bind
    {
      Wire.portal;
      bstmt = stmt;
      param_formats = [];
      params = List.map Option.some params;
      result_formats = [];
    }

let execute ?(portal = "") () = Wire.frame 'E' (portal ^ "\000\000\000\000\000")
let sync = Wire.frame 'S' ""

(* ---------------------------------------------------------------- env *)

type env = { pg : Fake_pg.t; srv : Server.t; port : int; audit_file : string }

let audit_lines e =
  In_channel.with_open_bin e.audit_file In_channel.input_all
  |> String.split_on_char '\n'
  |> List.filter (fun l -> String.trim l <> "")

let audit_records e = List.map Yojson.Safe.from_string (audit_lines e)

let jfield k (j : Yojson.Safe.t) =
  match j with `Assoc kvs -> List.assoc_opt k kvs | _ -> None

let jstr k j =
  match jfield k j with
  | Some (`String s) -> s
  | Some j -> Yojson.Safe.to_string j
  | None -> "<missing>"

let events e name = List.filter (fun r -> jstr "event" r = name) (audit_records e)

let fresh_audit_file () =
  let f = Filename.temp_file "haltsql_proxy_session" ".jsonl" in
  Sys.remove f;
  f

(* [make] builds the configuration; it is called again on every [reload], so a test
   changes what it returns and then reloads. *)
let with_env ?(prepare = fun (_ : Fake_pg.t) -> ())
    ?(make = fun ~up_port ~audit_file -> config ~up_port ~audit_file ())
    ?(audit_file = fresh_audit_file ()) (f : env -> unit Lwt.t) =
  Lwt_main.run
    (let* pg = Fake_pg.start () in
     prepare pg;
     let build () = make ~up_port:pg.port ~audit_file in
     let reload () =
       match Proxy_config.of_json ~base_dir:(Sys.getcwd ()) (build ()) with
       | Ok c -> Ok c
       | Error es -> Error (List.map Haltsql.Load_error.to_string es)
     in
     let* srv = Server.start ~reload (load (build ())) in
     Lwt.finalize
       (fun () -> f { pg; srv; port = Server.port srv; audit_file })
       (fun () ->
         let* () = Server.shutdown srv in
         let* () = Fake_pg.stop pg in
         (try Sys.remove audit_file with _ -> ());
         Lwt.return_unit))

let reload e =
  let* r = Server.reload e.srv ~trigger:"test" in
  match r with
  | Ok () -> Lwt.return_unit
  | Error es -> Alcotest.failf "reload: %s" (String.concat "; " es)

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

(* ------------------------------------------------------------- offload *)

(* Blocking work handed to the pool does not stop the event loop, and the pool never
   runs more jobs at once than its bound. *)
let test_offload () =
  let before = Offload.threads () in
  Lwt_main.run
    (Offload.configure ~threads:2;
     let running = Atomic.make 0 and peak = Atomic.make 0 in
     let job () =
       let n = Atomic.fetch_and_add running 1 + 1 in
       let rec raise_peak () =
         let p = Atomic.get peak in
         if n > p && not (Atomic.compare_and_set peak p n) then raise_peak ()
       in
       raise_peak ();
       Unix.sleepf 0.15;
       Atomic.decr running;
       Thread.id (Thread.self ())
     in
     let main = Thread.id (Thread.self ()) in
     let jobs = List.init 6 (fun _ -> Offload.run job) in
     let ticks = ref 0 in
     let rec tick () =
       if List.for_all (fun j -> Lwt.state j <> Lwt.Sleep) jobs then Lwt.return_unit
       else
         let* () = Lwt_unix.sleep 0.01 in
         incr ticks;
         tick ()
     in
     let* () = tick () in
     let* ids = Lwt.all jobs in
     check_bool "jobs ran off the main thread" false (List.mem main ids);
     check_int "never more than the bound at once" 2 (Atomic.get peak);
     (* 6 jobs of 150 ms on 2 threads take about 450 ms; a blocked loop would not tick *)
     check_bool
       (Printf.sprintf "event loop kept running (%d ticks)" !ticks)
       true (!ticks >= 20);
     let* r =
       Lwt.catch
         (fun () -> Offload.run (fun () -> failwith "boom"))
         (function Failure m -> Lwt.return m | e -> Lwt.return (Printexc.to_string e))
     in
     check_str "an exception rejects the promise" "boom" r;
     Lwt.return_unit);
  Offload.configure ~threads:before

(* ---------------------------------------------------------- ordering *)

let chain_ok e n =
  Alcotest.(check (result int (pair int string)))
    "audit chain verifies" (Ok n)
    (Chain.verify_lines (audit_lines e))

(* A pipeline written in one burst (verification now runs off the event loop): the
   upstream sees the messages in the client's order, the denied statement is replaced in
   place, and audit records follow the same order. *)
let test_pipeline_order () =
  with_env (fun e ->
      let* io = login_ok e.port in
      let seg name q = parse ~name q ^ bind ~stmt:name [] ^ execute () ^ sync in
      let* () =
        Io.write io
          (seg "s1" q_ok ^ seg "bad" q_denied ^ seg "s2" q_ok
          ^ Wire.frame 'Q' (q_ok ^ "\000")
          ^ seg "s3" q_ok)
      in
      let* r1 = read_until_ready io in
      let* r2 = read_until_ready io in
      let* r3 = read_until_ready io in
      let* r4 = read_until_ready io in
      let* r5 = read_until_ready io in
      check_str "segment 1" "12CZ" (tags r1);
      check_str "segment 2 denied in place" "EZ" (tags r2);
      check_str "denial sqlstate" "42501" (sqlstate r2);
      check_str "segment 3" "12CZ" (tags r3);
      check_str "simple query" "CZ" (tags r4);
      check_str "segment 5" "12CZ" (tags r5);
      let upstream =
        List.filter_map
          (function
            | 'P', p ->
                let p = Wire.decode_parse p in
                Some ("P:" ^ if Fake_pg.is_sentinel p.query then "<denied>" else p.stmt)
            | 'Q', p ->
                let q = Wire.decode_query p in
                if q = "SHOW search_path" then None else Some "Q"
            | 'B', p -> Some ("B:" ^ (Wire.decode_bind p).bstmt)
            | t, _ -> Some (String.make 1 t))
          (Fake_pg.received e.pg)
      in
      Alcotest.(check (list string))
        "upstream order"
        [
          "P:s1";
          "B:s1";
          "E";
          "S";
          "P:<denied>";
          "S";
          "P:s2";
          "B:s2";
          "E";
          "S";
          "Q";
          "P:s3";
          "B:s3";
          "E";
          "S";
        ]
        upstream;
      let stmts = events e "statement" in
      Alcotest.(check (list string))
        "audit order"
        [ "s1/true"; "bad/false"; "s2/true"; "<missing>/true"; "s3/true" ]
        (List.map (fun r -> jstr "statement" r ^ "/" ^ jstr "allowed" r) stmts);
      chain_ok e (List.length (audit_lines e));
      Io.close io)

(* Many sessions verifying and auditing at once: every statement is answered and the
   single audit chain stays intact. *)
let test_concurrent_sessions () =
  with_env (fun e ->
      let sessions = 8 and per = 15 in
      let one _ =
        let* io = login_ok e.port in
        let rec go i =
          if i = per then Io.close io
          else
            let* ms = simple io (if i mod 3 = 2 then q_denied else q_ok) in
            check_str "answered" (if i mod 3 = 2 then "EZ" else "CZ") (tags ms);
            go (i + 1)
        in
        go 0
      in
      let* () = Lwt.join (List.init sessions one) in
      check_int "one record per statement" (sessions * per)
        (List.length (events e "statement"));
      chain_ok e (sessions * per);
      Lwt.return_unit)

(* The default audit mode is still fail closed now that the write happens on a worker
   thread: no audit record, no statement. *)
let test_audit_fail_closed () =
  let fifo = fresh_audit_file () in
  Unix.mkfifo fifo 0o600;
  let reader = Unix.openfile fifo [ Unix.O_RDONLY; Unix.O_NONBLOCK ] 0 in
  Fun.protect
    ~finally:(fun () -> try Unix.close reader with _ -> ())
    (fun () ->
      with_env ~audit_file:fifo (fun e ->
          let* io = login_ok e.port in
          let* ms = simple io q_ok in
          check_str "audited statement passes" "CZ" (tags ms);
          (* the reader goes away: writes fail with EPIPE *)
          Unix.close reader;
          let* ms = simple io q_ok in
          check_str "refused in-band" "EZ" (tags ms);
          check_str "io_error" "58030" (sqlstate ms);
          let* ms = simple io q_denied in
          check_str "denials are refused the same way" "58030" (sqlstate ms);
          let* () = Io.write io (parse q_ok ^ bind [] ^ execute () ^ sync) in
          let* ms = read_until_ready io in
          check_str "extended protocol refused too" "58030" (sqlstate ms);
          check_int "only the audited statement reached the upstream" 1
            (List.length (List.filter (fun q -> q = q_ok) (Fake_pg.queries e.pg)));
          check_int "no Parse reached the upstream as sent" 0
            (List.length
               (List.filter
                  (function
                    | 'P', p -> not (Fake_pg.is_sentinel (Wire.decode_parse p).query)
                    | _ -> false)
                  (Fake_pg.received e.pg)));
          Io.close io))

(* ------------------------------------------------- lifetime and reload *)

let limits kvs ~up_port ~audit_file = config ~up_port ~audit_file ~limits:kvs ()

let expect_terminated ?(within = 5.) name io =
  let t0 = Unix.gettimeofday () in
  let* ms = read_until_ready io in
  let dt = Unix.gettimeofday () -. t0 in
  check_str (name ^ ": admin_shutdown") "57P01" (sqlstate ms);
  check_bool (name ^ ": FATAL") true (List.exists is_fatal ms);
  check_bool (Printf.sprintf "%s: in time (%.2fs)" name dt) true (dt < within);
  let* rest = read_until_ready io in
  check_str (name ^ ": connection closed") "!" (tags rest);
  Lwt.return (message ms)

let still_alive name io =
  let* ms = simple io "ROLLBACK" in
  check_str (name ^ ": still served") "CZ" (tags ms);
  Lwt.return_unit

(* An idle session is ended when its lifetime is over; pools reconnect on 57P01. *)
let test_lifetime_idle () =
  with_env
    ~make:(limits [ ("max_session_lifetime_seconds", `Float 0.4) ])
    (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io q_ok in
      check_str "served before the limit" "CZ" (tags ms);
      let* m = expect_terminated "lifetime" io in
      check_bool "names the limit" true (contains m "max_session_lifetime_seconds");
      let* () = wait_until "upstream connection closed" (fun () -> e.pg.closed = 1) in
      (* a new connection gets a fresh lifetime *)
      let* io2 = login_ok e.port in
      let* ms = simple io2 q_ok in
      check_str "reconnect works" "CZ" (tags ms);
      let* () = Io.close io2 in
      Io.close io)

(* Inside a transaction the session lives on until the transaction ends. *)
let test_lifetime_transaction () =
  with_env
    ~make:
      (limits
         [
           ("max_session_lifetime_seconds", `Float 0.3);
           ("termination_grace_seconds", `Float 20.);
         ])
    (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io "BEGIN" in
      check_str "BEGIN" "CZ" (tags ms);
      let* () = Lwt_unix.sleep 0.6 in
      let* ms = simple io q_ok in
      check_str "statement inside the transaction, past the limit" "CZ" (tags ms);
      let* () = Io.write io (Wire.frame 'Q' "COMMIT\000") in
      let* ms = read_until_ready io in
      check_str "COMMIT answered first" "CZ" (tags ms);
      let* _ = expect_terminated "after the transaction" io in
      check_bool "COMMIT reached the upstream" true
        (List.mem "COMMIT" (Fake_pg.queries e.pg));
      Io.close io)

(* A client that never ends its transaction is closed after the grace period. *)
let test_lifetime_grace () =
  with_env
    ~make:
      (limits
         [
           ("max_session_lifetime_seconds", `Float 0.2);
           ("termination_grace_seconds", `Float 0.3);
         ])
    (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io "BEGIN" in
      check_str "BEGIN" "CZ" (tags ms);
      let t0 = Unix.gettimeofday () in
      let* _ = expect_terminated "grace" io in
      let dt = Unix.gettimeofday () -. t0 in
      check_bool (Printf.sprintf "not before lifetime + grace (%.2fs)" dt) true (dt >= 0.4);
      let* () = wait_until "upstream connection closed" (fun () -> e.pg.closed = 1) in
      Io.close io)

let test_lifetime_disabled () =
  with_env
    ~make:(limits [ ("max_session_lifetime_seconds", `Int 0) ])
    (fun e ->
      let* io = login_ok e.port in
      let* () = Lwt_unix.sleep 0.5 in
      let* ms = simple io q_ok in
      check_str "no limit" "CZ" (tags ms);
      Io.close io)

(* The fixture policy without app.currencies: q_ok is denied under it. *)
let policy_b =
  lazy
    (let text = In_channel.with_open_bin "fixtures/policy.yaml" In_channel.input_all in
     let cut = "  app.currencies:\n    columns: \"*\"\n" in
     if not (contains text cut) then Alcotest.fail "fixture policy changed";
     let i =
       let m = String.length cut in
       let rec go i = if String.sub text i m = cut then i else go (i + 1) in
       go 0
     in
     let text =
       String.sub text 0 i
       ^ String.sub text
           (i + String.length cut)
           (String.length text - i - String.length cut)
     in
     let f = Filename.temp_file "haltsql_policy_b" ".yaml" in
     Out_channel.with_open_bin f (fun oc -> Out_channel.output_string oc text);
     f)

let other_verifier =
  lazy
    (Scram.verifier_to_string (Scram.make_verifier ~iterations:4096 "rotated-password"))

(* Each case: two users log in, the configuration is changed and reloaded, and "agent"
   must be ended (or not) while "other" is never touched. *)
let reload_case ?(expect_end = true) ?(reload_extra = []) change () =
  let changed = ref false in
  let make ~up_port ~audit_file =
    let policy, agent =
      if !changed then change () else ("fixtures/policy.yaml", Some (user_json ()))
    in
    config ~up_port ~audit_file ~policy
      ~users:(Option.to_list agent @ [ user_json ~name:"other" () ])
      ~extra:(if reload_extra = [] then [] else [ ("reload", `Assoc reload_extra) ])
      ()
  in
  with_env ~make (fun e ->
      let* agent = login_ok e.port in
      let* other = login_ok ~user:"other" e.port in
      changed := true;
      let* () = reload e in
      let* () =
        if expect_end then (
          let* m = expect_terminated "changed session" agent in
          check_bool "says why" true (contains m "configuration");
          Lwt.return_unit)
        else still_alive "session" agent
      in
      let* () = Io.close agent in
      Io.close other)

let same_policy = "fixtures/policy.yaml"

let test_reload_policy_changed =
  reload_case (fun () -> (Lazy.force policy_b, Some (user_json ())))

let test_reload_credentials_changed =
  reload_case (fun () ->
      (same_policy, Some (user_json ~verifier:(Lazy.force other_verifier) ())))

let test_reload_user_removed = reload_case (fun () -> (same_policy, None))

let test_reload_context_changed =
  reload_case (fun () -> (same_policy, Some (user_json ~tenant:"globex" ())))

let test_reload_opt_out =
  reload_case ~expect_end:false
    ~reload_extra:[ ("terminate_changed_sessions", `Bool false) ]
    (fun () -> (Lazy.force policy_b, Some (user_json ())))

(* The other half of every case above, spelled out once: a reload that changes one
   user leaves the others alone, new sessions get the new policy, and rotated
   credentials are what authenticates from then on. *)
let test_reload_scope () =
  let stage = ref 0 in
  let make ~up_port ~audit_file =
    let agent =
      if !stage = 0 then user_json ()
      else user_json ~verifier:(Lazy.force other_verifier) ()
    in
    config ~up_port ~audit_file
      ~policy:(if !stage = 2 then Lazy.force policy_b else same_policy)
      ~users:[ agent; user_json ~name:"other" () ]
      ()
  in
  with_env ~make (fun e ->
      let* agent = login_ok e.port in
      let* other = login_ok ~user:"other" e.port in
      stage := 1;
      let* () = reload e in
      let* _ = expect_terminated "rotated user" agent in
      let* ms = simple other q_ok in
      check_str "the other user's session is untouched" "CZ" (tags ms);
      let* io, ms = login e.port in
      check_str "the old password no longer works" "28P01" (sqlstate ms);
      let* () = Io.close io in
      let* agent2 = login_ok ~password:"rotated-password" e.port in
      (* an unrelated reload (same content) ends nobody *)
      let* () = reload e in
      let* ms = simple agent2 q_ok in
      check_str "unchanged session survives a reload" "CZ" (tags ms);
      (* the policy changes for everyone *)
      stage := 2;
      let* () = reload e in
      let* _ = expect_terminated "policy change (agent)" agent2 in
      let* _ = expect_terminated "policy change (other)" other in
      let* fresh = login_ok ~user:"other" e.port in
      let* ms = simple fresh q_ok in
      check_str "new sessions run under the new policy" "42501" (sqlstate ms);
      let* () = Lwt_list.iter_s Io.close [ agent; other; agent2; fresh ] in
      Lwt.return_unit)

(* A session inside a transaction keeps its policy (it is never rebound) and is ended
   when the transaction is. *)
let test_reload_in_transaction () =
  let changed = ref false in
  let make ~up_port ~audit_file =
    config ~up_port ~audit_file
      ~policy:(if !changed then Lazy.force policy_b else same_policy)
      ()
  in
  with_env ~make (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io "BEGIN" in
      check_str "BEGIN" "CZ" (tags ms);
      changed := true;
      let* () = reload e in
      let* ms = simple io q_ok in
      check_str "still verified under the policy it started with" "CZ" (tags ms);
      let* () = Io.write io (Wire.frame 'Q' "COMMIT\000") in
      let* ms = read_until_ready io in
      check_str "COMMIT answered" "CZ" (tags ms);
      let* _ = expect_terminated "after COMMIT" io in
      let versions =
        List.sort_uniq compare (List.map (jstr "policy_version") (events e "statement"))
      in
      check_int "every statement of the session has one policy version" 1
        (List.length versions);
      Io.close io)

let () =
  Sec.init_rng ();
  (try Sys.set_signal Sys.sigpipe Sys.Signal_ignore with _ -> ());
  Alcotest.run "proxy-session"
    [
      ( "offload",
        [ Alcotest.test_case "bounded pool, loop stays responsive" `Quick test_offload ]
      );
      ( "ordering",
        [
          Alcotest.test_case "pipelined messages keep their order" `Quick
            test_pipeline_order;
          Alcotest.test_case "concurrent sessions, one intact chain" `Quick
            test_concurrent_sessions;
          Alcotest.test_case "audit failure still refuses the statement" `Quick
            test_audit_fail_closed;
        ] );
      ( "lifetime",
        [
          Alcotest.test_case "idle session ended at the limit (57P01)" `Quick
            test_lifetime_idle;
          Alcotest.test_case "ended at the transaction boundary" `Quick
            test_lifetime_transaction;
          Alcotest.test_case "grace period bounds an open transaction" `Quick
            test_lifetime_grace;
          Alcotest.test_case "0 disables the limit" `Quick test_lifetime_disabled;
        ] );
      ( "reload",
        [
          Alcotest.test_case "policy changed: session ended" `Quick
            test_reload_policy_changed;
          Alcotest.test_case "credentials changed: session ended" `Quick
            test_reload_credentials_changed;
          Alcotest.test_case "user removed: session ended" `Quick test_reload_user_removed;
          Alcotest.test_case "context changed: session ended" `Quick
            test_reload_context_changed;
          Alcotest.test_case "terminate_changed_sessions: false" `Quick
            test_reload_opt_out;
          Alcotest.test_case "only changed sessions, new sessions get the new policy"
            `Quick test_reload_scope;
          Alcotest.test_case "in a transaction: old policy until it ends" `Quick
            test_reload_in_transaction;
        ] );
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
