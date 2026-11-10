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
let q_tenant = "SELECT id FROM app.orders WHERE tenant_id = $1 ORDER BY id LIMIT 10"

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
    ?(users = [ user_json () ]) ?auth ?(audit = []) ?(limits = []) ?(upstream = [])
    ?(extra = []) () : Yojson.Safe.t =
  let auth =
    match auth with
    | Some a -> a
    | None -> `Assoc [ ("method", `String "scram"); ("users", `List users) ]
  in
  `Assoc
    ([
       ("apiVersion", `String "haltsql.dev/v1");
       ("kind", `String "ProxyConfig");
       ("listen", `String "127.0.0.1:0");
       ( "upstream",
         `Assoc
           (List.filter
              (fun (k, _) -> not (List.mem_assoc k upstream))
              [
                ("host", `String "127.0.0.1");
                ("port", `Int up_port);
                ("database", `String "app");
                ("user", `String "svc");
                ("connect_timeout_seconds", `Float 2.);
              ]
           @ upstream) );
       ("policies", `List [ `Assoc [ ("path", `String policy) ] ]);
       ("auth", auth);
       ( "audit",
         `Assoc ([ ("type", `String "file"); ("path", `String audit_file) ] @ audit) );
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

let scram ?(before_response = fun () -> Lwt.return_unit) io ~password =
  let read () = Io.read_message io ~max:65536 in
  let* tag, p = read () in
  match (tag, if tag = 'R' then Wire.decode_auth p else Wire.Auth_other (-1)) with
  | 'R', Wire.Auth_sasl _ -> (
      (* the proxy has asked for SCRAM and is waiting for the client's first message *)
      let* () = before_response () in
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
let login ?(user = "agent") ?(password = password) ?(params = []) ?before_response port =
  let* io = connect port in
  let* () =
    Io.write io (Wire.encode_startup ([ ("user", user); ("database", "app") ] @ params))
  in
  let* () = scram ?before_response io ~password in
  let* ms = read_until_ready io in
  Lwt.return (io, ms)

(* Sends only the startup packet and reports what comes back first. *)
let login_startup_only port =
  let* io = connect port in
  let* () =
    Lwt.catch
      (fun () ->
        Io.write io (Wire.encode_startup [ ("user", "agent"); ("database", "app") ]))
      (fun _ -> Lwt.return_unit)
  in
  let* m =
    Lwt.catch (fun () -> Io.read_message io ~max:65536) (fun _ -> Lwt.return ('!', ""))
  in
  Lwt.return (io, [ m ])

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

let execute ?(portal = "") ?(max_rows = 0) () =
  let b = Buffer.create 16 in
  Wire.add_cstring b portal;
  Wire.add_int32 b max_rows;
  Wire.frame 'E' (Buffer.contents b)

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

(* ------------------------------------------------------ execute audit *)

let execute_records e =
  List.map
    (fun r ->
      Printf.sprintf "%s|%s|%s" (jstr "portal" r) (jstr "statement" r) (jstr "max_rows" r))
    (events e "execute")

(* Prepared once, executed five times: one statement record, five execute records. The
   parameter the client sent is in none of them. *)
let test_execute_audited () =
  with_env (fun e ->
      let* io = login_ok e.port in
      let* () = Io.write io (parse ~name:"s1" q_tenant ^ sync) in
      let* ms = read_until_ready io in
      check_str "prepared" "1Z" (tags ms);
      let secret = "CLIENT-SUPPLIED-PARAMETER-9c1f" in
      let rec run i =
        if i = 5 then Lwt.return_unit
        else
          let* () = Io.write io (bind ~stmt:"s1" [ secret ] ^ execute () ^ sync) in
          let* ms = read_until_ready io in
          check_str "executed" "2CZ" (tags ms);
          run (i + 1)
      in
      let* () = run 0 in
      let stmts = events e "statement" and execs = events e "execute" in
      check_int "one statement record" 1 (List.length stmts);
      check_int "one execute record per Execute" 5 (List.length execs);
      check_int "and five Execute messages upstream" 5 (Fake_pg.count_tag e.pg 'E');
      let stmt = List.hd stmts in
      List.iter
        (fun r ->
          check_str "names the statement" "s1" (jstr "statement" r);
          check_str "same SQL hash as its statement record" (jstr "sql_sha256" stmt)
            (jstr "sql_sha256" r);
          check_str "same fingerprint" (jstr "fingerprint" stmt) (jstr "fingerprint" r);
          check_str "policy version" (jstr "policy_version" stmt)
            (jstr "policy_version" r);
          check_str "session" (jstr "session" stmt) (jstr "session" r);
          check_str "user" "agent" (jstr "user" r);
          check_bool "no values field" true (jfield "params" r = None))
        execs;
      let raw = String.concat "\n" (audit_lines e) in
      check_bool "the client's parameter is not in the audit log" false
        (contains raw secret);
      check_bool "nor the bound tenant value" false (contains raw "acme");
      chain_ok e 6;
      Io.close io)

(* Named portals, row limits, several Executes of one portal, a portal that was closed,
   and a portal the proxy never saw being bound. *)
let test_execute_portals () =
  with_env (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io "BEGIN" in
      check_str "BEGIN" "CZ" (tags ms);
      let close_portal name = Wire.frame 'C' ("P" ^ name ^ "\000") in
      let* () =
        Io.write io
          (parse ~name:"a" q_ok ^ parse ~name:"b" q_ok
          ^ bind ~portal:"pa" ~stmt:"a" []
          ^ bind ~portal:"pb" ~stmt:"b" []
          ^ execute ~portal:"pa" ~max_rows:2 ()
          ^ execute ~portal:"pb" ()
          ^ execute ~portal:"pa" ~max_rows:2 ()
          ^ close_portal "pb"
          ^ execute ~portal:"cursor_from_sql" ()
          ^ sync)
      in
      let* ms = read_until_ready io in
      check_str "relayed" "1122CCC3CZ" (tags ms);
      Alcotest.(check (list string))
        "records, in order"
        [ "pa|a|2"; "pb|b|0"; "pa|a|2"; "cursor_from_sql|null|0" ]
        (execute_records e);
      (* the transaction ends: its portals are gone, a reused name is not mislabelled *)
      let* ms = simple io "COMMIT" in
      check_str "COMMIT" "CZ" (tags ms);
      let* () = Io.write io (execute ~portal:"pa" () ^ sync) in
      let* _ = read_until_ready io in
      Alcotest.(check (list string))
        "a portal does not outlive its transaction" [ "pa|null|0" ]
        (List.filteri (fun i _ -> i >= 4) (execute_records e));
      Io.close io)

(* No audit record, no Execute: the refusal reaches the client and the Execute never
   reaches the database. *)
let test_execute_fail_closed () =
  let fifo = fresh_audit_file () in
  Unix.mkfifo fifo 0o600;
  let reader = Unix.openfile fifo [ Unix.O_RDONLY; Unix.O_NONBLOCK ] 0 in
  Fun.protect
    ~finally:(fun () -> try Unix.close reader with _ -> ())
    (fun () ->
      with_env ~audit_file:fifo (fun e ->
          let* io = login_ok e.port in
          let* () = Io.write io (parse ~name:"s1" q_ok ^ sync) in
          let* ms = read_until_ready io in
          check_str "prepared while the sink works" "1Z" (tags ms);
          Unix.close reader;
          let* () = Io.write io (bind ~stmt:"s1" [] ^ execute () ^ sync) in
          let* ms = read_until_ready io in
          check_str "Bind passes, Execute is refused" "2EZ" (tags ms);
          check_str "io_error" "58030" (sqlstate ms);
          check_int "no Execute reached the upstream" 0 (Fake_pg.count_tag e.pg 'E');
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

(* ----------------------------------------------- pre-auth connections *)

let refused_at_accept io =
  let* ms = read_until_ready io in
  Lwt.return (sqlstate ms, message ms)

(* One address cannot fill the proxy with connections that never authenticate. *)
let test_preauth_cap () =
  with_env
    ~make:
      (limits [ ("max_unauthenticated_per_ip", `Int 3); ("max_connections", `Int 50) ])
    (fun e ->
      (* authenticated sessions do not count: more of them than the cap *)
      let* sessions = Lwt_list.map_s (fun _ -> login_ok e.port) [ 1; 2; 3; 4; 5 ] in
      check_int "nothing pending" 0 (Server.unauthenticated e.srv);
      (* three connections that say nothing *)
      let* idle = Lwt_list.map_s (fun _ -> connect e.port) [ 1; 2; 3 ] in
      let* () = wait_until "three pending" (fun () -> Server.unauthenticated e.srv = 3) in
      let* extra = connect e.port in
      let* code, msg = refused_at_accept extra in
      check_str "the fourth is refused" "53300" code;
      check_bool "says which limit" true (contains msg "max_unauthenticated_per_ip");
      let* () = Io.close extra in
      (* a real client is refused too while the address is over its share *)
      let* io, ms = login_startup_only e.port in
      check_str "also a well-behaved one" "53300" (sqlstate ms);
      let* () = Io.close io in
      (* established sessions are unaffected *)
      let* ms = simple (List.hd sessions) q_ok in
      check_str "existing sessions keep working" "CZ" (tags ms);
      (* one of the silent connections goes away: the slot is free again *)
      let* () = Io.close (List.hd idle) in
      let* () = wait_until "slot released" (fun () -> Server.unauthenticated e.srv = 2) in
      let* again = login_ok e.port in
      let* () =
        wait_until "authentication released its slot" (fun () ->
            Server.unauthenticated e.srv = 2)
      in
      Lwt_list.iter_s Io.close ((again :: idle) @ sessions))

let test_preauth_cap_disabled () =
  with_env
    ~make:(limits [ ("max_unauthenticated_per_ip", `Int 0) ])
    (fun e ->
      let* idle = Lwt_list.map_s (fun _ -> connect e.port) (List.init 30 Fun.id) in
      let* () = wait_until "all pending" (fun () -> Server.unauthenticated e.srv = 30) in
      let* io = login_ok e.port in
      Lwt_list.iter_s Io.close (io :: idle))

(* ---------------------------------------------------- upstream transport *)

let upstream_of ?(allow = false) (pg : Fake_pg.t) : Proxy_config.upstream =
  {
    host = "127.0.0.1";
    port = pg.port;
    database = "app";
    user = "svc";
    password = Some "upstream-password";
    tls_mode = Proxy_config.Tls_disable;
    tls_ca = [];
    connect_timeout = 2.;
    allow_insecure_auth = allow;
  }

(* MD5 over a plaintext upstream connection: refused before anything derived from the
   password is sent, unless explicitly allowed. *)
let test_md5_plaintext () =
  Lwt_main.run
    (let* pg = Fake_pg.start () in
     pg.auth <- Fake_pg.Md5 "upstream-password";
     let attempt u =
       Lwt.catch
         (fun () ->
           let* io = Upstream.connect u ~application_name:None in
           let* () = Io.close io in
           Lwt.return "connected")
         (function
           | Upstream.Upstream_error m -> Lwt.return m
           | e -> Lwt.return (Printexc.to_string e))
     in
     let* r = attempt (upstream_of pg) in
     check_bool ("refused: " ^ r) true (contains r "MD5" && contains r "unencrypted");
     check_bool "the error names the ways out" true
       (contains r "allow_insecure_auth" && contains r "scram-sha-256");
     check_int "no password message was sent" 0 pg.passwords;
     let* r = attempt (upstream_of ~allow:true pg) in
     check_str "explicit opt-in" "connected" r;
     check_int "the MD5 response was sent" 1 pg.passwords;
     (* cleartext stays refused whatever the opt-in says *)
     pg.auth <- Fake_pg.Cleartext "upstream-password";
     let* r = attempt (upstream_of ~allow:true pg) in
     check_bool ("cleartext refused: " ^ r) true (contains r "cleartext");
     check_int "no cleartext password was sent" 1 pg.passwords;
     Fake_pg.stop pg)

(* Seen from a client: the session is refused, with the reason in the proxy log only. *)
let test_md5_session () =
  let make allow ~up_port ~audit_file =
    config ~up_port ~audit_file
      ~upstream:
        ([ ("password", `String "upstream-password") ]
        @ if allow then [ ("allow_insecure_auth", `Bool true) ] else [])
      ()
  in
  let prepare (pg : Fake_pg.t) = pg.auth <- Fake_pg.Md5 "upstream-password" in
  with_env ~prepare ~make:(make false) (fun e ->
      let* io, ms = login e.port in
      check_str "upstream connection failure" "08006" (sqlstate ms);
      check_bool "nothing about the upstream's auth leaks to the client" false
        (contains (message ms) "MD5");
      check_int "no password message reached the upstream" 0 e.pg.passwords;
      Io.close io);
  with_env ~prepare ~make:(make true) (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io q_ok in
      check_str "served with the opt-in" "CZ" (tags ms);
      Io.close io)

let test_transport_notes () =
  let notes ?(tls = []) ?(extra = []) host =
    let c =
      load
        (config ~up_port:5432 ~audit_file:"unused.jsonl"
           ~upstream:
             ([ ("host", `String host) ]
             @ (if tls = [] then [] else [ ("tls", `Assoc tls) ])
             @ extra)
           ())
    in
    List.map
      (function
        | Proxy_config.Transport_warning m -> "W:" ^ m
        | Proxy_config.Transport_info m -> "I:" ^ m)
      (Proxy_config.transport_notes c)
  in
  let none name l = Alcotest.(check (list string)) name [] l in
  none "loopback IPv4, TLS off" (notes "127.0.0.1");
  none "127.0.0.0/8" (notes "127.8.9.10");
  none "localhost" (notes "LocalHost");
  none "::1" (notes "::1");
  (match notes "db.internal" with
  | [ w ] ->
      check_bool "warning" true (String.length w > 2 && String.sub w 0 2 = "W:");
      check_bool "names the host" true (contains w "db.internal");
      check_bool "says what to set" true (contains w "verify-full")
  | l -> Alcotest.failf "expected one warning, got %d" (List.length l));
  check_int "a non-loopback address" 1 (List.length (notes "10.1.2.3"));
  (match notes ~tls:[ ("mode", `String "require") ] "db.internal" with
  | [ i ] ->
      check_bool "a note, not a warning" true (String.sub i 0 2 = "I:");
      check_bool "says the certificate is not verified" true (contains i "not verified")
  | l -> Alcotest.failf "require: expected one note, got %d" (List.length l));
  none "require on loopback" (notes ~tls:[ ("mode", `String "require") ] "127.0.0.1");
  check_int "allow_insecure_auth without TLS, even on loopback" 1
    (List.length (notes ~extra:[ ("allow_insecure_auth", `Bool true) ] "127.0.0.1"));
  check_int "both" 2
    (List.length (notes ~extra:[ ("allow_insecure_auth", `Bool true) ] "db.internal"));
  check_bool "loopback detection does not resolve names" false
    (Proxy_config.is_loopback "localhost.example.com")

(* ------------------------------------------------------ startup packet *)

(* What the upstream session is opened with is decided by the proxy alone: the service
   account, the policy's search_path and a vetted application_name. Run-time parameters
   in the client's startup packet ([options], GUCs such as [role] or [search_path]) are
   not passed on, or a client could change how its statements are resolved and run. *)
let test_startup_parameters_not_forwarded () =
  with_env (fun e ->
      let* io, ms =
        login
          ~params:
            [
              ("options", "-c search_path=evil -c role=postgres");
              ("search_path", "evil");
              ("role", "postgres");
              ("session_authorization", "postgres");
              ("application_name", "psql");
            ]
          e.port
      in
      check_str "logged in" "" (message ms);
      let up = Fake_pg.startup_params e.pg in
      Alcotest.(check (list string))
        "only what the proxy sets"
        [ "application_name"; "client_encoding"; "database"; "search_path"; "user" ]
        (List.sort compare (List.map fst up));
      check_str "the service account" "svc" (List.assoc "user" up);
      check_str "the policy's search_path" {|"app", "pg_temp"|}
        (List.assoc "search_path" up);
      check_str "application_name passed on" "psql" (List.assoc "application_name" up);
      Io.close io)

(* application_name ends up in the database's log lines and pg_stat_activity: a value
   with control characters or over PostgreSQL's 63 bytes is dropped, not forwarded. *)
let test_application_name_vetted () =
  let upstream_app name =
    let seen = ref None in
    with_env (fun e ->
        let* io, ms = login ~params:[ ("application_name", name) ] e.port in
        check_str "logged in" "" (message ms);
        seen := List.assoc_opt "application_name" (Fake_pg.startup_params e.pg);
        Io.close io);
    !seen
  in
  let chk = Alcotest.(check (option string)) in
  chk "plain" (Some "my app 1.0") (upstream_app "my app 1.0");
  chk "63 bytes" (Some (String.make 63 'a')) (upstream_app (String.make 63 'a'));
  chk "64 bytes dropped" None (upstream_app (String.make 64 'a'));
  chk "newline dropped" None (upstream_app "x\nLOG:  forged line");
  chk "escape dropped" None (upstream_app "x\027[2J");
  chk "non-ASCII dropped" None (upstream_app "caf\xc3\xa9")

(* ------------------------------------------------- transaction control *)

let upstream_saw e sql =
  List.mem sql (Fake_pg.queries e.pg)
  || List.exists
       (function 'P', p -> (Wire.decode_parse p).query = sql | _ -> false)
       (Fake_pg.received e.pg)

(* allow_transaction_control: false sends BEGIN/COMMIT through the policy like any other
   statement (the test policy allows SELECT only), in both protocols. *)
let test_transaction_control_off () =
  with_env
    ~make:(fun ~up_port ~audit_file ->
      config ~up_port ~audit_file ~extra:[ ("allow_transaction_control", `Bool false) ] ())
    (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io "BEGIN" in
      check_str "simple BEGIN denied" "EZ" (tags ms);
      check_str "by the policy" "42501" (sqlstate ms);
      let* () = Io.write io (parse "BEGIN" ^ sync) in
      let* ms = read_until_ready io in
      check_str "extended BEGIN denied" "EZ" (tags ms);
      check_str "by the policy" "42501" (sqlstate ms);
      let* ms = simple io "COMMIT" in
      check_str "COMMIT denied" "EZ" (tags ms);
      check_bool "BEGIN never reached the upstream" false (upstream_saw e "BEGIN");
      check_bool "COMMIT never reached the upstream" false (upstream_saw e "COMMIT");
      Alcotest.(check (list string))
        "all three audited as denied" [ "false"; "false"; "false" ]
        (List.map (jstr "allowed") (events e "statement"));
      let* ms = simple io q_ok in
      check_str "queries still served" "CZ" (tags ms);
      Io.close io);
  (* the default: plain transaction control passes *)
  with_env (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io "BEGIN" in
      check_str "BEGIN allowed by default" "CZ" (tags ms);
      let* () = Io.write io (parse "COMMIT" ^ bind [] ^ execute () ^ sync) in
      let* ms = read_until_ready io in
      check_str "extended COMMIT allowed by default" "12CZ" (tags ms);
      check_bool "reached the upstream" true (upstream_saw e "BEGIN");
      Io.close io)

(* ------------------------------------------------ statement bookkeeping *)

let upstream_tags e =
  String.concat ""
    (List.filter_map
       (function
         | 'Q', p when Wire.decode_query p = "SHOW search_path" -> None
         | 'P', p when Fake_pg.is_sentinel (Wire.decode_parse p).query -> Some "!"
         | t, _ -> Some (String.make 1 t))
       (Fake_pg.received e.pg))

let reasons r = jstr "reasons" r

(* Denials the proxy makes itself (not the policy): the client gets the error, the
   upstream never sees the message, and the audit log has a record of it. *)
let test_proxy_level_denials () =
  with_env (fun e ->
      let* io = login_ok e.port in
      (* Bind to a statement that was never prepared *)
      let* () = Io.write io (bind ~stmt:"nope" [] ^ execute () ^ sync) in
      let* ms = read_until_ready io in
      check_str "unknown statement" "EZ" (tags ms);
      check_str "invalid_sql_statement_name" "26000" (sqlstate ms);
      check_str "replaced by a failing Parse, rest of the batch dropped" "!S"
        (upstream_tags e);
      (* a second Parse under a name that is taken *)
      let* () = Io.write io (parse ~name:"s" q_ok ^ sync) in
      let* ms = read_until_ready io in
      check_str "prepared" "1Z" (tags ms);
      let* () = Io.write io (parse ~name:"s" q_tenant ^ sync) in
      let* ms = read_until_ready io in
      check_str "name taken" "EZ" (tags ms);
      check_str "duplicate_prepared_statement" "42P05" (sqlstate ms);
      check_bool "the second statement never reached the upstream" false
        (upstream_saw e q_tenant);
      (* the statement keeps its first verdict: no tenancy parameter is expected *)
      let* () = Io.write io (bind ~stmt:"s" [] ^ execute () ^ sync) in
      let* ms = read_until_ready io in
      check_str "first statement still usable" "2CZ" (tags ms);
      (* the fast-path function call protocol *)
      let* () = Io.write io (Wire.frame 'F' "\000\000\004\210\000\000\000\000\000\000") in
      let* ms = read_until_ready io in
      check_str "function call" "EZ" (tags ms);
      check_str "denied" "42501" (sqlstate ms);
      check_int "no FunctionCall reached the upstream" 0 (Fake_pg.count_tag e.pg 'F');
      (* one audit record per denial, with the proxy's reason *)
      let denial ev =
        List.map
          (fun r -> jstr "allowed" r ^ " " ^ reasons r ^ " " ^ jstr "statement" r)
          (events e ev)
      in
      Alcotest.(check (list string))
        "bind audited"
        [ {|false ["PROXY_STATEMENT_UNKNOWN"] nope|} ]
        (denial "bind");
      Alcotest.(check (list string))
        "parse audited"
        [ {|false ["PROXY_STATEMENT_EXISTS"] s|} ]
        (denial "parse");
      Alcotest.(check (list string))
        "function call audited"
        [ {|false ["PROXY_FUNCTION_CALL"] <missing>|} ]
        (denial "function_call");
      chain_ok e (List.length (audit_lines e));
      Io.close io)

(* A simple query destroys the unnamed prepared statement in PostgreSQL; the proxy
   forgets its verdict at the same moment, so a later Bind to it is refused here rather
   than forwarded with a verdict that belongs to nothing. *)
let test_unnamed_statement_after_simple_query () =
  with_env (fun e ->
      let* io = login_ok e.port in
      let* () = Io.write io (parse q_ok ^ sync) in
      let* ms = read_until_ready io in
      check_str "unnamed statement prepared" "1Z" (tags ms);
      let* () = Io.write io (bind [] ^ execute () ^ sync) in
      let* ms = read_until_ready io in
      check_str "usable" "2CZ" (tags ms);
      let* ms = simple io q_ok in
      check_str "simple query" "CZ" (tags ms);
      let* () = Io.write io (bind [] ^ execute () ^ sync) in
      let* ms = read_until_ready io in
      check_str "unnamed statement is gone" "EZ" (tags ms);
      check_str "invalid_sql_statement_name" "26000" (sqlstate ms);
      check_int "only the first Bind reached the upstream" 1 (Fake_pg.count_tag e.pg 'B');
      Io.close io)

(* -------------------------------------------- a misbehaving upstream *)

(* The upstream answers one statement with [reply]: the session must end with a FATAL
   error instead of relaying it. *)
let upstream_violation ?(sqlstate_ = "08P01") ~reply ~never_relayed () =
  with_env
    ~prepare:(fun pg -> pg.on_query <- (fun q -> if q = q_ok then Some reply else None))
    (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io q_ok in
      check_bool "session ended with FATAL" true (List.exists is_fatal ms);
      check_str "sqlstate" sqlstate_ (sqlstate ms);
      List.iter
        (fun t ->
          check_bool
            (Printf.sprintf "%C not relayed to the client" t)
            false
            (String.contains (tags ms) t))
        never_relayed;
      let* rest = read_until_ready io in
      check_str "connection closed" "!" (tags rest);
      let* () = wait_until "upstream connection closed" (fun () -> e.pg.closed = 1) in
      Io.close io)

let copy_response tag = Wire.frame tag "\000\000\000"

(* COPY is not relayed: the proxy cannot verify what flows through it. *)
let test_upstream_copy_out =
  upstream_violation ~reply:(copy_response 'H') ~never_relayed:[ 'H'; 'Z' ]

let test_upstream_copy_in =
  upstream_violation ~reply:(copy_response 'G') ~never_relayed:[ 'G'; 'Z' ]

(* An authentication request in the middle of a session is not something a server
   sends; it must not reach the client (which would answer it with a password). *)
let test_upstream_auth_request =
  upstream_violation ~reply:(Fake_pg.auth_request 3 "") ~never_relayed:[ 'R'; 'Z' ]

(* The verifier reads SQL the way a UTF-8, standard_conforming_strings=on session does;
   if the upstream session stops being one, statements would be verified as one thing
   and run as another. *)
let test_upstream_scs_off =
  upstream_violation
    ~reply:
      (Wire.parameter_status "standard_conforming_strings" "off"
      ^ Fake_pg.complete "SELECT 0" ^ Wire.ready_for_query 'I')
    ~never_relayed:[ 'C'; 'Z' ]

let test_upstream_encoding_changed =
  upstream_violation
    ~reply:
      (Wire.parameter_status "client_encoding" "SQL_ASCII"
      ^ Fake_pg.complete "SELECT 0" ^ Wire.ready_for_query 'I')
    ~never_relayed:[ 'C'; 'Z' ]

(* The search_path cannot be confirmed: no session. *)
let unconfirmed_search_path ~reply ~sqlstate_ () =
  with_env
    ~prepare:(fun pg ->
      pg.on_query <- (fun q -> if q = "SHOW search_path" then Some reply else None))
    (fun e ->
      let* io, ms = login e.port in
      check_bool "FATAL" true (List.exists is_fatal ms);
      check_str "sqlstate" sqlstate_ (sqlstate ms);
      check_bool "names the cause" true (contains (message ms) "search_path");
      check_bool "no ReadyForQuery reached the client" false
        (String.contains (tags ms) 'Z');
      let* () =
        Lwt.catch
          (fun () -> Io.write io (Wire.frame 'Q' (q_ok ^ "\000")))
          (fun _ -> Lwt.return_unit)
      in
      let* () = wait_until "upstream closed" (fun () -> e.pg.closed = 1) in
      check_bool "client statement never forwarded" false
        (List.mem q_ok (Fake_pg.queries e.pg));
      Io.close io)

let test_search_path_show_refused =
  unconfirmed_search_path ~sqlstate_:"08006"
    ~reply:
      (Wire.error_response
         [ ('S', "ERROR"); ('V', "ERROR"); ('C', "42501"); ('M', "permission denied") ]
      ^ Wire.ready_for_query 'I')

let test_search_path_show_empty =
  unconfirmed_search_path ~sqlstate_:"08P01"
    ~reply:(Fake_pg.complete "SHOW" ^ Wire.ready_for_query 'I')

(* ------------------------------------------------------------ cancel *)

let backend_key ms =
  List.find_map
    (function
      | 'K', p ->
          let c = Wire.cursor p in
          let pid = Wire.get_int32 c in
          let key = Wire.get_int32 c in
          Some (pid, key)
      | _ -> None)
    ms

(* A CancelRequest; the proxy closes the connection once it has dealt with it. *)
let cancel port ~pid ~key =
  let* io = connect port in
  let* () = Io.write io (Wire.encode_cancel ~pid ~key) in
  let* () =
    Lwt.catch
      (fun () ->
        Lwt_unix.with_timeout 5. (fun () ->
            let* _ = Io.read_byte io in
            Lwt.return_unit))
      (fun _ -> Lwt.return_unit)
  in
  Io.close io

(* The client gets the proxy's own key for its session; only that key cancels, only
   while the session lives, and the upstream is addressed with its real key. *)
let test_cancel_key () =
  with_env (fun e ->
      let* io, ms = login e.port in
      let pid, key =
        match backend_key ms with
        | Some k -> k
        | None -> Alcotest.fail "no BackendKeyData"
      in
      check_bool "not the upstream's key" true ((pid, key) <> (4242, 99));
      let forwarded () = e.pg.cancels in
      let pairs = Alcotest.(list (pair int int)) in
      let* () = cancel e.port ~pid ~key:(key lxor 1) in
      Alcotest.check pairs "wrong key: nothing forwarded" [] (forwarded ());
      let* () = cancel e.port ~pid:(pid lxor 1) ~key in
      Alcotest.check pairs "unknown backend: nothing forwarded" [] (forwarded ());
      let* () = cancel e.port ~pid:4242 ~key:99 in
      Alcotest.check pairs "the upstream's own key means nothing here" [] (forwarded ());
      let* () = cancel e.port ~pid ~key in
      let* () = wait_until "cancel forwarded" (fun () -> forwarded () <> []) in
      Alcotest.check pairs "right key: forwarded with the upstream's"
        [ (4242, 99) ]
        (forwarded ());
      (* once the session is over its key cancels nothing: the upstream backend id may
         belong to someone else's session by then *)
      let* () = Io.close io in
      let* () = wait_until "session gone" (fun () -> Server.active e.srv = 0) in
      let* () = cancel e.port ~pid ~key in
      let* () = wait_until "request handled" (fun () -> Server.active e.srv = 0) in
      Alcotest.check pairs "stale key: nothing forwarded" [ (4242, 99) ] (forwarded ());
      Lwt.return_unit)

(* ------------------------------------------------- upstream SCRAM *)

(* The proxy authenticates the upstream too: a peer that cannot prove it knows the
   password (wrong ServerSignature, or no server-final message at all) gets no session,
   and no client statement. *)
let upstream_scram ending ~accepted () =
  with_env
    ~prepare:(fun pg -> pg.auth <- Fake_pg.Scram ("upstream-password", ending))
    ~make:(fun ~up_port ~audit_file ->
      config ~up_port ~audit_file
        ~upstream:[ ("password", `String "upstream-password") ]
        ())
    (fun e ->
      let* io, ms = login e.port in
      check_int "the exchange took place" 1 e.pg.passwords;
      if accepted then (
        check_str "session opened" "" (message ms);
        let* ms = simple io q_ok in
        check_str "served" "CZ" (tags ms);
        Io.close io)
      else (
        check_str "upstream connection failure" "08006" (sqlstate ms);
        check_bool "FATAL" true (List.exists is_fatal ms);
        check_bool "no ReadyForQuery" false (String.contains (tags ms) 'Z');
        let* () = wait_until "upstream closed" (fun () -> e.pg.closed = 1) in
        Alcotest.(check (list string))
          "nothing was sent to the unverified peer" [] (Fake_pg.queries e.pg);
        Io.close io))

let test_upstream_scram_honest = upstream_scram Fake_pg.Honest ~accepted:true
let test_upstream_scram_forged = upstream_scram Fake_pg.Wrong_signature ~accepted:false
let test_upstream_scram_skipped = upstream_scram Fake_pg.No_server_final ~accepted:false

(* ------------------------------------- reload during authentication *)

(* A connection accepted before a reload authenticates against the configuration it was
   accepted under. If the reload changed what that session depends on (here: the user's
   password was rotated), the session is ended as soon as it is authenticated, like any
   other session the reload made stale. *)
let test_reload_during_authentication () =
  let rotated = ref false in
  let make ~up_port ~audit_file =
    config ~up_port ~audit_file
      ~users:
        [
          (if !rotated then user_json ~verifier:(Lazy.force other_verifier) ()
           else user_json ());
        ]
      ()
  in
  with_env ~make (fun e ->
      let* io, ms =
        login e.port ~before_response:(fun () ->
            rotated := true;
            reload e)
      in
      (* startup may complete (ReadyForQuery) before the session is ended *)
      let* ms = if List.exists is_fatal ms then Lwt.return ms else read_until_ready io in
      check_str "ended: admin_shutdown" "57P01" (sqlstate ms);
      check_bool "FATAL" true (List.exists is_fatal ms);
      check_bool "says why" true (contains (message ms) "configuration");
      let* () = Io.close io in
      (* the old password no longer opens sessions; the new one does *)
      let* io, ms = login e.port in
      check_str "old password refused" "28P01" (sqlstate ms);
      let* () = Io.close io in
      let* io = login_ok ~password:"rotated-password" e.port in
      let* ms = simple io q_ok in
      check_str "new password served" "CZ" (tags ms);
      Io.close io)

(* ------------------------------------------- client certificate auth *)

module Pki = struct
  let ok = function Ok x -> x | Error (`Msg m) -> failwith m

  let dn cn =
    [
      X509.Distinguished_name.(
        Relative_distinguished_name.singleton (CN (Common_name.v cn)));
    ]

  let at offset =
    match Ptime.add_span (Ptime_clock.now ()) (Ptime.Span.of_int_s offset) with
    | Some t -> t
    | None -> failwith "time"

  let make_ca name =
    let key = X509.Private_key.generate `P256 in
    let csr = ok (X509.Signing_request.create (dn name) key) in
    let extensions =
      X509.Extension.(
        empty
        |> add Basic_constraints (true, (true, None))
        |> add Key_usage (true, [ `Key_cert_sign; `CRL_sign; `Digital_signature ]))
    in
    match
      X509.Signing_request.sign csr ~valid_from:(at (-3600)) ~valid_until:(at 86400)
        ~extensions key (dn name)
    with
    | Ok c -> (key, c)
    | Error _ -> failwith "sign ca"

  let make_leaf (ca_key, ca_cert) ~cn ~usage ~san =
    let key = X509.Private_key.generate `P256 in
    let csr = ok (X509.Signing_request.create (dn cn) key) in
    let extensions =
      X509.Extension.(
        empty
        |> add Basic_constraints (true, (false, None))
        |> add Key_usage (true, [ `Digital_signature; `Key_agreement ])
        |> add Ext_key_usage (false, [ usage ])
        |> add Subject_alt_name (false, san))
    in
    match
      X509.Signing_request.sign csr ~valid_from:(at (-3600)) ~valid_until:(at 86400)
        ~extensions ca_key
        (X509.Certificate.subject ca_cert)
    with
    | Ok c -> (key, c)
    | Error _ -> failwith "sign leaf"

  let uri l = X509.General_name.(singleton URI l)
  let agent_spiffe = "spiffe://haltsql.test/agent"
  let other_spiffe = "spiffe://haltsql.test/other"
  let ca = lazy (make_ca "haltsql test CA")
  let other_ca = lazy (make_ca "another CA")

  let server =
    lazy
      (make_leaf (Lazy.force ca) ~cn:"localhost" ~usage:`Server_auth
         ~san:
           X509.General_name.(
             singleton DNS [ "localhost" ] |> add IP [ "\127\000\000\001" ]))

  let client ?(ca = ca) ?(usage = `Client_auth) ~cn uris =
    lazy (make_leaf (Lazy.force ca) ~cn ~usage ~san:(uri uris))

  (* the identity the tests configure, by CN or by SPIFFE ID *)
  let agent = client ~cn:"agent-cert" [ agent_spiffe ]

  (* same CA, a certificate for somebody else *)
  let other = client ~cn:"someone-else" [ other_spiffe ]

  (* the configured SPIFFE ID next to a second URI SAN *)
  let two_uris = client ~cn:"someone-else" [ agent_spiffe; other_spiffe ]

  (* the configured names, but only valid as a TLS server certificate *)
  let server_only = client ~usage:`Server_auth ~cn:"agent-cert" [ agent_spiffe ]

  (* the configured names, signed by a CA the proxy does not trust *)
  let rogue = client ~ca:other_ca ~cn:"agent-cert" [ agent_spiffe ]
  let cert_pem (_, c) = `String (X509.Certificate.encode_pem c)
  let key_pem (k, _) = `String (X509.Private_key.encode_pem k)
end

let cert_config ?(client_ca = Pki.ca) ?limits identities ~up_port ~audit_file =
  let identity m =
    `Assoc
      [
        m;
        ("policy", `String "proxy-test");
        ("context", `Assoc [ ("tenant_id", `String "acme") ]);
      ]
  in
  config ~up_port ~audit_file ?limits
    ~auth:
      (`Assoc
         [
           ("method", `String "cert"); ("identities", `List (List.map identity identities));
         ])
    ~extra:
      [
        ( "tls",
          `Assoc
            [
              ("cert", Pki.cert_pem (Lazy.force Pki.server));
              ("key", Pki.key_pem (Lazy.force Pki.server));
              ("client_ca", Pki.cert_pem (Lazy.force client_ca));
              ("client_auth", `String "require");
            ] );
      ]
    ()

(* SSLRequest, TLS handshake (optionally with a client certificate), startup packet.
   [Error] when the handshake fails; otherwise the connection and what came back up to
   ReadyForQuery, a FATAL error or the end of the stream. *)
let tls_connect ?client port =
  let* io = connect port in
  let* () = Io.write io Wire.encode_ssl_request in
  let* answer = Io.read_byte io in
  if answer <> 'S' then Alcotest.failf "SSLRequest answered with %C" answer;
  let authenticator =
    X509.Authenticator.chain_of_trust
      ~time:(fun () -> Some (Ptime_clock.now ()))
      [ snd (Lazy.force Pki.ca) ]
  in
  let certificates =
    match client with
    | Some c ->
        let key, cert = Lazy.force c in
        `Single ([ cert ], key)
    | None -> `None
  in
  let cfg =
    match Tls.Config.client ~authenticator ~certificates () with
    | Ok c -> c
    | Error (`Msg m) -> Alcotest.fail m
  in
  let host = Domain_name.(host_exn (of_string_exn "localhost")) in
  let* r =
    Lwt.catch
      (fun () ->
        let* t = Tls_lwt.Unix.client_of_fd cfg ~host (Io.fd io) in
        Lwt.return (Ok (Io.of_tls (Io.fd io) t)))
      (fun ex -> Lwt.return (Error (Printexc.to_string ex)))
  in
  match r with
  | Error m ->
      let* () = Io.close io in
      Lwt.return (Error m)
  | Ok tio -> Lwt.return (Ok tio)

let tls_login ?client port =
  let* r = tls_connect ?client port in
  match r with
  | Error m -> Lwt.return (Error m)
  | Ok tio ->
      let* () =
        Lwt.catch
          (fun () ->
            Io.write tio
              (Wire.encode_startup [ ("user", "whoever"); ("database", "app") ]))
          (fun _ -> Lwt.return_unit)
      in
      let* ms = read_until_ready tio in
      Lwt.return (Ok (tio, ms))

let cert_accepted name e client =
  let* r = tls_login ~client e.port in
  match r with
  | Error m -> Alcotest.failf "%s: TLS handshake failed: %s" name m
  | Ok (io, ms) ->
      check_str (name ^ ": no error") "" (message ms);
      check_bool (name ^ ": ReadyForQuery") true (String.contains (tags ms) 'Z');
      let* ms = simple io q_ok in
      check_str (name ^ ": served") "CZ" (tags ms);
      Lwt.return io

(* A certificate the CA signed, but for an identity that is not configured: the TLS
   handshake succeeds and the session is then refused. *)
let cert_not_authorized name e client =
  let* r = tls_login ~client e.port in
  match r with
  | Error m -> Alcotest.failf "%s: TLS handshake failed: %s" name m
  | Ok (io, ms) ->
      check_str (name ^ ": invalid_authorization_specification") "28000" (sqlstate ms);
      check_bool (name ^ ": FATAL") true (List.exists is_fatal ms);
      check_bool (name ^ ": says why") true (contains (message ms) "not authorized");
      check_bool (name ^ ": no ReadyForQuery") false (String.contains (tags ms) 'Z');
      Io.close io

(* A certificate the proxy must not accept at all: the handshake fails, or the
   connection dies before anything is authenticated. *)
let cert_rejected name e client =
  let* r = tls_login ?client e.port in
  match r with
  | Error _ -> Lwt.return_unit
  | Ok (io, ms) ->
      check_bool (name ^ ": never authenticated") false (String.contains (tags ms) 'Z');
      check_bool (name ^ ": no AuthenticationOk") false (String.contains (tags ms) 'R');
      Io.close io

let test_cert_identity_cn () =
  with_env
    ~make:(cert_config [ ("subject_cn", `String "agent-cert") ])
    (fun e ->
      let* io = cert_accepted "configured CN" e Pki.agent in
      let* () = cert_not_authorized "another CN from the same CA" e Pki.other in
      let* () = cert_not_authorized "another CN, two URI SANs" e Pki.two_uris in
      check_int "one upstream session: the authorized one" 1 e.pg.connections;
      Alcotest.(check (list string))
        "its statement ran under the identity's policy" [ "proxy-test" ]
        (List.sort_uniq compare (List.map (jstr "policy") (events e "statement")));
      Io.close io)

let test_cert_identity_spiffe () =
  with_env
    ~make:(cert_config [ ("spiffe_id", `String Pki.agent_spiffe) ])
    (fun e ->
      let* io = cert_accepted "configured SPIFFE ID" e Pki.agent in
      let* () = cert_not_authorized "another SPIFFE ID" e Pki.other in
      (* exactly one URI SAN makes a SPIFFE identity; with two there is none *)
      let* () = cert_not_authorized "configured ID among two URI SANs" e Pki.two_uris in
      check_int "one upstream session: the authorized one" 1 e.pg.connections;
      Io.close io)

let test_cert_rejected () =
  with_env
    ~make:(cert_config [ ("subject_cn", `String "agent-cert") ])
    (fun e ->
      let* () = cert_rejected "no client certificate" e None in
      let* () = cert_rejected "untrusted CA" e (Some Pki.rogue) in
      (* right CA and names, but the certificate is for TLS servers only *)
      let* () = cert_rejected "serverAuth-only certificate" e (Some Pki.server_only) in
      let* () = wait_until "connections closed" (fun () -> Server.active e.srv = 0) in
      check_int "no upstream session was opened" 0 e.pg.connections;
      (* the control: the same proxy does accept the real client certificate *)
      let* io = cert_accepted "configured CN" e Pki.agent in
      Io.close io)

(* A reload that replaces the client CA ends certificate sessions: their certificate
   was verified against a CA that is no longer trusted. *)
let test_reload_client_ca () =
  let replaced = ref false in
  let make ~up_port ~audit_file =
    cert_config
      ~client_ca:(if !replaced then Pki.other_ca else Pki.ca)
      [ ("subject_cn", `String "agent-cert") ]
      ~up_port ~audit_file
  in
  with_env ~make (fun e ->
      let* io = cert_accepted "before" e Pki.agent in
      let* () = reload e in
      let* ms = simple io q_ok in
      check_str "an unchanged reload leaves the session alone" "CZ" (tags ms);
      replaced := true;
      let* () = reload e in
      let* m = expect_terminated "client CA replaced" io in
      check_bool "says why" true (contains m "configuration");
      let* () =
        cert_rejected "the old CA's certificate no longer connects" e (Some Pki.agent)
      in
      Io.close io)

(* ------------------------------------- the same rules, without PostgreSQL *)

(* test_proxy_integration checks what follows against the lab database and skips without
   it; these are the in-process counterparts, so that the rules are checked wherever the
   test suite runs. *)

(* The tenant parameter of a Bind is the session's, whatever the client sent. *)
let test_bind_overwrites_tenant () =
  with_env (fun e ->
      let* io = login_ok e.port in
      let* () =
        Io.write io
          (parse ~name:"t" q_tenant ^ bind ~stmt:"t" [ "globex" ] ^ execute () ^ sync)
      in
      let* ms = read_until_ready io in
      check_str "served" "12CZ" (tags ms);
      let sent =
        List.filter_map
          (function 'B', p -> Some (Wire.decode_bind p).params | _ -> None)
          (Fake_pg.received e.pg)
      in
      Alcotest.(check (list (list (option string))))
        "the upstream is bound to the session's tenant" [ [ Some "acme" ] ] sent;
      Io.close io)

(* Startup packets the proxy refuses before authentication. *)
let test_startup_refusals () =
  with_env (fun e ->
      let refused name params code =
        let* io = connect e.port in
        let* () = Io.write io (Wire.encode_startup params) in
        let* ms = read_until_ready io in
        check_str name code (sqlstate ms);
        check_bool (name ^ ": FATAL") true (List.exists is_fatal ms);
        check_bool
          (name ^ ": before any authentication exchange")
          false
          (String.contains (tags ms) 'R');
        Io.close io
      in
      let* () =
        refused "replication connection"
          [ ("user", "agent"); ("database", "app"); ("replication", "database") ]
          "28000"
      in
      let* () =
        refused "another database" [ ("user", "agent"); ("database", "postgres") ] "3D000"
      in
      let* () = refused "no user" [ ("database", "app") ] "28000" in
      check_int "no upstream connection was opened" 0 e.pg.connections;
      Lwt.return_unit)

(* COPY data from the client ends the session; nothing of it reaches the upstream. *)
let test_client_copy_data () =
  with_env (fun e ->
      let* io = login_ok e.port in
      let* () = Io.write io (Wire.frame 'd' "1\tacme\n") in
      let* ms = read_until_ready io in
      check_str "protocol violation" "08P01" (sqlstate ms);
      check_bool "FATAL" true (List.exists is_fatal ms);
      let* () = wait_until "upstream closed" (fun () -> e.pg.closed = 1) in
      check_int "no CopyData reached the upstream" 0 (Fake_pg.count_tag e.pg 'd');
      Io.close io)

let server_tls required =
  ( "tls",
    `Assoc
      [
        ("cert", Pki.cert_pem (Lazy.force Pki.server));
        ("key", Pki.key_pem (Lazy.force Pki.server));
        ("required", `Bool required);
      ] )

(* tls.required: a plaintext startup is refused before authentication. *)
let test_tls_required () =
  let attempt required =
    let got = ref "" in
    with_env
      ~make:(fun ~up_port ~audit_file ->
        config ~up_port ~audit_file ~extra:[ server_tls required ] ())
      (fun e ->
        let* io, ms = login_startup_only e.port in
        (got :=
           match ms with
           | [ ('E', p) ] -> field 'C' p
           | [ ('R', _) ] -> "authentication requested"
           | _ -> tags ms);
        Io.close io);
    !got
  in
  check_str "required: plaintext refused" "28000" (attempt true);
  check_str "not required: plaintext may authenticate" "authentication requested"
    (attempt false)

(* Bytes sent in the clear right behind an SSLRequest are not read as if they had come
   through TLS (CVE-2021-23214). *)
let test_ssl_request_pipelined () =
  with_env
    ~make:(fun ~up_port ~audit_file ->
      config ~up_port ~audit_file ~extra:[ server_tls false ] ())
    (fun e ->
      let* io = connect e.port in
      let* () =
        Io.write io
          (Wire.encode_ssl_request
          ^ Wire.encode_startup [ ("user", "agent"); ("database", "app") ])
      in
      let* first = Lwt.catch (fun () -> Io.read_byte io) (fun _ -> Lwt.return '!') in
      check_bool "TLS is not started over the smuggled bytes" false (first = 'S');
      check_bool "and they are not answered as a startup packet" false (first = 'R');
      let* () = wait_until "connection dropped" (fun () -> Server.active e.srv = 0) in
      check_int "nothing reached the upstream" 0 e.pg.connections;
      Io.close io)

let test_max_connections () =
  with_env
    ~make:(limits [ ("max_connections", `Int 2) ])
    (fun e ->
      let* a = login_ok e.port in
      let* b = connect e.port in
      let* () = wait_until "two connections" (fun () -> Server.active e.srv = 2) in
      let* c = connect e.port in
      let* code, msg = refused_at_accept c in
      check_str "the third is refused" "53300" code;
      check_bool "says which limit" true (contains msg "max_connections");
      let* () = Io.close c in
      let* () = Io.close b in
      let* () = wait_until "slot released" (fun () -> Server.active e.srv = 1) in
      let* d = login_ok e.port in
      let* ms = simple a q_ok in
      check_str "established sessions are unaffected" "CZ" (tags ms);
      let* () = Io.close d in
      Io.close a)

let test_idle_timeout () =
  with_env
    ~make:(limits [ ("idle_timeout_seconds", `Float 0.3) ])
    (fun e ->
      let* io = login_ok e.port in
      let* ms = simple io q_ok in
      check_str "served" "CZ" (tags ms);
      let t0 = Unix.gettimeofday () in
      let* ms = read_until_ready io in
      check_str "idle session ended" "57P05" (sqlstate ms);
      check_bool "FATAL" true (List.exists is_fatal ms);
      check_bool "not before the timeout" true (Unix.gettimeofday () -. t0 >= 0.25);
      let* () = wait_until "upstream closed" (fun () -> e.pg.closed = 1) in
      Io.close io)

(* upstream.tls.mode: require against a server without TLS: no session, and nothing is
   sent to it in the clear (not even the startup packet with the user name). *)
let test_upstream_tls_unavailable () =
  with_env
    ~make:(fun ~up_port ~audit_file ->
      config ~up_port ~audit_file
        ~upstream:[ ("tls", `Assoc [ ("mode", `String "require") ]) ]
        ())
    (fun e ->
      let* io, ms = login e.port in
      check_str "upstream connection failure" "08006" (sqlstate ms);
      check_bool "FATAL" true (List.exists is_fatal ms);
      let* () = wait_until "upstream closed" (fun () -> e.pg.closed = 1) in
      Alcotest.(check (list (list (pair string string))))
        "no startup packet was sent in the clear" [] e.pg.startups;
      Io.close io)

(* Raw SQL is written to the audit log only when audit.log_raw_sql asks for it. *)
let test_audit_raw_sql () =
  let sql_fields audit =
    let got = ref [] in
    with_env
      ~make:(fun ~up_port ~audit_file -> config ~up_port ~audit_file ~audit ())
      (fun e ->
        let* io = login_ok e.port in
        let* ms = simple io q_ok in
        check_str "served" "CZ" (tags ms);
        let* ms = simple io q_denied in
        check_str "denied" "EZ" (tags ms);
        got := List.map (jstr "sql") (events e "statement");
        check_bool "the hash is always there" true
          (List.for_all
             (fun r -> jstr "sql_sha256" r <> "<missing>")
             (events e "statement"));
        Io.close io);
    !got
  in
  Alcotest.(check (list string))
    "default: no statement text" [ "<missing>"; "<missing>" ] (sql_fields []);
  Alcotest.(check (list string))
    "log_raw_sql: true" [ q_ok; q_denied ]
    (sql_fields [ ("log_raw_sql", `Bool true) ])

(* Regression: the FATAL error that ends a session was lost on TLS connections. The
   session's pending read was cancelled first, tls-lwt then treats the connection as
   failed and refuses the write, and the client saw the connection drop without a
   word. Three ways a session is ended from outside its client loop: *)

(* ... by the proxy (lifetime limit; a reload goes the same way, see above) *)
let test_tls_end_lifetime () =
  with_env
    ~make:
      (cert_config
         ~limits:[ ("max_session_lifetime_seconds", `Float 0.4) ]
         [ ("subject_cn", `String "agent-cert") ])
    (fun e ->
      let* io = cert_accepted "before the limit" e Pki.agent in
      let* m = expect_terminated "lifetime over TLS" io in
      check_bool "names the limit" true (contains m "max_session_lifetime_seconds");
      Io.close io)

(* ... by what the upstream sent *)
let test_tls_end_upstream_violation () =
  with_env
    ~prepare:(fun pg ->
      pg.on_query <- (fun q -> if q = q_ok then Some (copy_response 'H') else None))
    ~make:(cert_config [ ("subject_cn", `String "agent-cert") ])
    (fun e ->
      let* r = tls_login ~client:Pki.agent e.port in
      match r with
      | Error m -> Alcotest.failf "TLS handshake failed: %s" m
      | Ok (io, ms) ->
          check_str "logged in" "" (message ms);
          let* ms = simple io q_ok in
          check_str "the client is told why" "08P01" (sqlstate ms);
          check_bool "FATAL" true (List.exists is_fatal ms);
          check_bool "names COPY" true (contains (message ms) "COPY");
          Io.close io)

(* ... by the authentication timeout, after the TLS handshake *)
let test_tls_end_auth_timeout () =
  with_env
    ~make:
      (cert_config
         ~limits:[ ("auth_timeout_seconds", `Float 1.) ]
         [ ("subject_cn", `String "agent-cert") ])
    (fun e ->
      let* r = tls_connect ~client:Pki.agent e.port in
      match r with
      | Error m -> Alcotest.failf "TLS handshake failed: %s" m
      | Ok io ->
          (* no startup packet *)
          let* ms = read_until_ready io in
          check_str "the client is told why" "08006" (sqlstate ms);
          check_bool "FATAL" true (List.exists is_fatal ms);
          check_bool "names the timeout" true (contains (message ms) "timed out");
          Io.close io)

let () =
  Sec.init_rng ();
  (try Sys.set_signal Sys.sigpipe Sys.Signal_ignore with _ -> ());
  Alcotest.run "proxy-session"
    [
      ( "TLS: the error that ends a session reaches the client",
        [
          Alcotest.test_case "session lifetime" `Quick test_tls_end_lifetime;
          Alcotest.test_case "upstream violation" `Quick test_tls_end_upstream_violation;
          Alcotest.test_case "authentication timeout" `Quick test_tls_end_auth_timeout;
        ] );
      ( "startup packet",
        [
          Alcotest.test_case "client run-time parameters are not forwarded" `Quick
            test_startup_parameters_not_forwarded;
          Alcotest.test_case "application_name is vetted" `Quick
            test_application_name_vetted;
        ] );
      ( "enforcement",
        [
          Alcotest.test_case "allow_transaction_control: false" `Quick
            test_transaction_control_off;
          Alcotest.test_case "proxy-level denials: refused, not forwarded, audited" `Quick
            test_proxy_level_denials;
          Alcotest.test_case "unnamed statement gone after a simple query" `Quick
            test_unnamed_statement_after_simple_query;
        ] );
      ( "without PostgreSQL",
        [
          Alcotest.test_case "Bind: tenant parameter overwritten on the wire" `Quick
            test_bind_overwrites_tenant;
          Alcotest.test_case "startup: replication, other database, no user" `Quick
            test_startup_refusals;
          Alcotest.test_case "COPY data from the client" `Quick test_client_copy_data;
          Alcotest.test_case "tls.required" `Quick test_tls_required;
          Alcotest.test_case "SSLRequest with pipelined plaintext" `Quick
            test_ssl_request_pipelined;
          Alcotest.test_case "max_connections" `Quick test_max_connections;
          Alcotest.test_case "idle timeout" `Quick test_idle_timeout;
          Alcotest.test_case "upstream TLS required but unavailable" `Quick
            test_upstream_tls_unavailable;
          Alcotest.test_case "audit.log_raw_sql" `Quick test_audit_raw_sql;
        ] );
      ( "misbehaving upstream",
        [
          Alcotest.test_case "COPY OUT response" `Quick test_upstream_copy_out;
          Alcotest.test_case "COPY IN response" `Quick test_upstream_copy_in;
          Alcotest.test_case "authentication request mid-session" `Quick
            test_upstream_auth_request;
          Alcotest.test_case "standard_conforming_strings turned off" `Quick
            test_upstream_scs_off;
          Alcotest.test_case "client_encoding changed" `Quick
            test_upstream_encoding_changed;
          Alcotest.test_case "SHOW search_path refused" `Quick
            test_search_path_show_refused;
          Alcotest.test_case "SHOW search_path without a row" `Quick
            test_search_path_show_empty;
          Alcotest.test_case "SCRAM: honest server" `Quick test_upstream_scram_honest;
          Alcotest.test_case "SCRAM: forged server signature" `Quick
            test_upstream_scram_forged;
          Alcotest.test_case "SCRAM: no server-final message" `Quick
            test_upstream_scram_skipped;
        ] );
      ( "cancel",
        [
          Alcotest.test_case "only the session's own key, while it lives" `Quick
            test_cancel_key;
        ] );
      ( "client certificates",
        [
          Alcotest.test_case "identity by subject CN" `Quick test_cert_identity_cn;
          Alcotest.test_case "identity by SPIFFE ID" `Quick test_cert_identity_spiffe;
          Alcotest.test_case "no, untrusted or server-only certificate" `Quick
            test_cert_rejected;
          Alcotest.test_case "reload replaces the client CA: session ended" `Quick
            test_reload_client_ca;
          Alcotest.test_case "reload during authentication: session ended" `Quick
            test_reload_during_authentication;
        ] );
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
      ( "execute audit",
        [
          Alcotest.test_case "prepared once, run N times: N records, no values" `Quick
            test_execute_audited;
          Alcotest.test_case "portals" `Quick test_execute_portals;
          Alcotest.test_case "unaudited Execute is refused" `Quick
            test_execute_fail_closed;
        ] );
      ( "pre-auth connections",
        [
          Alcotest.test_case "per-address cap on unauthenticated connections" `Quick
            test_preauth_cap;
          Alcotest.test_case "0 disables the cap" `Quick test_preauth_cap_disabled;
        ] );
      ( "upstream transport",
        [
          Alcotest.test_case "MD5 over plaintext refused unless allowed" `Quick
            test_md5_plaintext;
          Alcotest.test_case "MD5 upstream, seen from a client" `Quick test_md5_session;
          Alcotest.test_case "startup warnings" `Quick test_transport_notes;
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
