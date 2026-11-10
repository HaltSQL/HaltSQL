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

let with_env ?(prepare = fun (_ : Fake_pg.t) -> ()) ?reload ?(cfg = fun c -> c)
    ?(audit_file = fresh_audit_file ()) (f : env -> unit Lwt.t) =
  Lwt_main.run
    (let* pg = Fake_pg.start () in
     prepare pg;
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
