(* Real haltsql-proxy audit records: the proxy binary in front of the lab Postgres 17
   (localhost:5417, make -C lab up), driven with the catalog tools' wire client, then
   `haltsql report` on the proxy's audit file. Skips cleanly when the proxy binary or
   Postgres is unavailable.

   Database: haltsql_shadow_report_<pid> (created and dropped here). *)

module R = Haltsql_report
module Pg = Haltsql_catalog_tools.Pg_wire
module Dsn = Haltsql_catalog_tools.Pg_dsn
module Scram = Haltsql_pgwire.Scram

let pg_port = 5417
let db = Printf.sprintf "haltsql_shadow_report_%d" (Unix.getpid ())
let agent_pw = "shadow-agent-pass-5d1e"
let upstream_pw = Option.value ~default:"haltlab" (Sys.getenv_opt "HALTSQL_PGPASSWORD")
let absolute p = if Filename.is_relative p then Filename.concat (Sys.getcwd ()) p else p
let proxy_bin = Option.map absolute (Sys.getenv_opt "HALTSQL_PROXY_BIN")
let cli = Option.map absolute (Sys.getenv_opt "HALTSQL_REPORT_CLI")
let fx name = absolute (Filename.concat "fixtures" name)
let read_file f = In_channel.with_open_bin f In_channel.input_all

let contains s sub =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  n = 0 || go 0

let tcp_open port =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Fun.protect
    ~finally:(fun () -> try Unix.close fd with _ -> ())
    (fun () ->
      try
        Unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, port));
        true
      with _ -> false)

let free_port () =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind fd (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> 0 in
  Unix.close fd;
  p

let dsn ?(dbname = "postgres") ?(user = "postgres") ?(password = upstream_pw) port =
  {
    Dsn.host = "127.0.0.1";
    port;
    user;
    password = Some password;
    dbname;
    sslmode = Dsn.Disable;
    sslrootcert = None;
    connect_timeout = Some 5.;
    application_name = Some "haltsql-report-test";
  }

let sql ?dbname q =
  Lwt_main.run
    (Pg.with_conn ~read_only:false (dsn ?dbname pg_port) (fun c -> Pg.simple_query c q))

let skip_reason =
  match (proxy_bin, cli) with
  | None, _ | _, None ->
      Some "HALTSQL_PROXY_BIN / HALTSQL_REPORT_CLI not set (run via dune test)"
  | Some _, Some _ -> (
      if not (tcp_open pg_port) then
        Some "lab Postgres not reachable on localhost:5417 (make -C lab up)"
      else
        match sql "SELECT 1" with
        | _ -> None
        | exception e ->
            Some ("cannot log in to the lab Postgres: " ^ Printexc.to_string e))

let tmp = lazy (Filename.temp_dir "haltsql_shadow_proxy" "")

let config ~audit =
  `Assoc
    [
      ("apiVersion", `String "haltsql.dev/v1");
      ("kind", `String "ProxyConfig");
      ( "upstream",
        `Assoc
          [
            ("host", `String "127.0.0.1");
            ("port", `Int pg_port);
            ("database", `String db);
            ("user", `String "postgres");
            ("password", `String "${env:PROXY_UPSTREAM_PW}");
          ] );
      ("policies", `List [ `Assoc [ ("path", `String (fx "shop-enforce.yaml")) ] ]);
      ( "auth",
        `Assoc
          [
            ("method", `String "scram");
            ( "users",
              `List
                [
                  `Assoc
                    [
                      ("name", `String "agent");
                      ( "scram_verifier",
                        `String (Scram.verifier_to_string (Scram.make_verifier agent_pw))
                      );
                      ("policy", `String "shop-enforce");
                      ("context", `Assoc [ ("tenant_id", `String "acme") ]);
                    ];
                ] );
          ] );
      ( "audit",
        `Assoc
          [
            ("type", `String "file"); ("path", `String audit); ("log_raw_sql", `Bool true);
          ] );
      ("logging", `Assoc [ ("level", `String "error") ]);
      ("shutdown_grace_seconds", `Int 2);
    ]

let start_proxy ~audit =
  let dir = Lazy.force tmp in
  let port = free_port () in
  let path = Filename.concat dir "proxy.json" in
  Out_channel.with_open_bin path (fun oc ->
      output_string oc (Yojson.Safe.to_string (config ~audit)));
  let log = Filename.concat dir "proxy.log" in
  let out = Unix.openfile log [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o600 in
  let devnull = Unix.openfile "/dev/null" [ Unix.O_RDWR ] 0 in
  let bin = Option.get proxy_bin in
  let env = Array.append (Unix.environment ()) [| "PROXY_UPSTREAM_PW=" ^ upstream_pw |] in
  let pid =
    Unix.create_process_env bin
      [| bin; "run"; "-c"; path; "--listen"; Printf.sprintf "127.0.0.1:%d" port |]
      env devnull out out
  in
  Unix.close out;
  Unix.close devnull;
  let rec wait n =
    if tcp_open port then ()
    else if n = 0 then failwith ("proxy did not start: " ^ read_file log)
    else (
      Unix.sleepf 0.1;
      wait (n - 1))
  in
  wait 100;
  (pid, port)

let stop_proxy pid =
  (try Unix.kill pid Sys.sigterm with Unix.Unix_error _ -> ());
  let deadline = Unix.gettimeofday () +. 15. in
  let rec wait () =
    match Unix.waitpid [ Unix.WNOHANG ] pid with
    | 0, _ when Unix.gettimeofday () < deadline ->
        Unix.sleepf 0.1;
        wait ()
    | 0, _ -> (
        (try Unix.kill pid Sys.sigkill with Unix.Unix_error _ -> ());
        try ignore (Unix.waitpid [] pid) with Unix.Unix_error _ -> ())
    | _ -> ()
    | exception Unix.Unix_error (Unix.EINTR, _, _) -> wait ()
  in
  wait ()

(* Statements sent through the proxy: (sql, expected to reach Postgres). *)
let statements =
  [
    "SELECT code FROM app.currencies LIMIT 5";
    "SELECT code, md5(code) FROM app.currencies LIMIT 5";
    "SELECT code, md5(code) FROM app.currencies LIMIT 7";
    "SELECT code FROM app.currencies LIMIT 400";
    "SELECT id FROM app.orders LIMIT 5";
    "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 5";
    "SELECT r.id, r.amount_cents FROM app.refunds r WHERE r.tenant_id = 'acme' LIMIT 5";
  ]

let audit_text = ref ""

let run_traffic () =
  let dir = Lazy.force tmp in
  let audit = Filename.concat dir "proxy-audit.jsonl" in
  ignore (sql (Printf.sprintf "DROP DATABASE IF EXISTS %s" db));
  ignore (sql (Printf.sprintf "CREATE DATABASE %s" db));
  ignore
    (sql ~dbname:db
       "CREATE SCHEMA app; CREATE TABLE app.currencies (code text PRIMARY KEY); INSERT \
        INTO app.currencies VALUES ('EUR'), ('USD'); CREATE TABLE app.orders (id int, \
        tenant_id text, status text, total_cents int, created_at timestamptz)");
  let pid, port = start_proxy ~audit in
  Fun.protect
    ~finally:(fun () -> stop_proxy pid)
    (fun () ->
      Lwt_main.run
        (Pg.with_conn ~read_only:false
           (dsn ~dbname:db ~user:"agent" ~password:agent_pw port) (fun c ->
             Lwt_list.iter_s
               (fun q ->
                 Lwt.catch
                   (fun () -> Lwt.map ignore (Pg.simple_query c q))
                   (function Pg.Error _ -> Lwt.return_unit | e -> Lwt.fail e))
               statements)));
  audit_text := read_file audit;
  audit

let cleanup () =
  (try ignore (sql (Printf.sprintf "DROP DATABASE IF EXISTS %s WITH (FORCE)" db))
   with _ -> ());
  match Lazy.is_val tmp with
  | true -> (
      let d = Lazy.force tmp in
      Array.iter
        (fun f -> try Sys.remove (Filename.concat d f) with _ -> ())
        (Sys.readdir d);
      try Unix.rmdir d with _ -> ())
  | false -> ()

let run_cli args =
  let bin = Option.get cli in
  let ic, oc, ec =
    Unix.open_process_args_full bin
      (Array.of_list (bin :: "report" :: args))
      (Unix.environment ())
  in
  close_out oc;
  let out = In_channel.input_all ic and err = In_channel.input_all ec in
  let code =
    match Unix.close_process_full (ic, oc, ec) with Unix.WEXITED c -> c | _ -> 255
  in
  (code, out, err)

let proxy_report audit () =
  let lines = String.split_on_char '\n' !audit_text |> List.filter (fun l -> l <> "") in
  let recs = List.filter_map (fun l -> Result.to_option (R.Record.of_line l)) lines in
  Alcotest.(check int)
    "one record per statement" (List.length statements) (List.length recs);
  List.iter
    (fun (r : R.Record.t) ->
      Alcotest.(check bool) "proxy source" true (r.source = R.Record.Proxy);
      Alcotest.(check string) "user" "agent" r.caller;
      Alcotest.(check bool) "raw sql" true (r.sql <> None);
      Alcotest.(check bool) "timestamp" true (r.ts <> None))
    recs;
  let outcomes =
    List.map (fun (r : R.Record.t) -> R.Record.outcome_to_string r.outcome) recs
  in
  Alcotest.(check (list string))
    "outcomes"
    [ "allowed"; "denied"; "denied"; "denied"; "denied"; "denied"; "denied" ]
    outcomes;
  let code, out, err =
    run_cli
      [ "--format"; "json"; "--suggest"; "--policy-file"; fx "shop-enforce.yaml"; audit ]
  in
  if code <> 0 then Alcotest.failf "report exited %d: %s" code err;
  let j = Yojson.Safe.from_string out in
  let open Yojson.Safe.Util in
  let s = member "summary" j in
  Alcotest.(check int) "records" (List.length statements) (to_int (member "records" s));
  Alcotest.(check int) "denied" 6 (to_int (member "denied" (member "totals" s)));
  Alcotest.(check bool)
    "proxy source row" true
    (List.exists
       (fun r -> to_string (member "source" r) = "proxy")
       (to_list (member "by_source" s)));
  let ids =
    member "suggest" j |> member "suggestions" |> to_list
    |> List.map (fun x -> to_string (member "id" x))
    |> List.sort compare
  in
  Alcotest.(check (list string))
    "suggestions"
    [
      "shop-enforce/function/md5"; "shop-enforce/limit"; "shop-enforce/table/app.refunds";
    ]
    ids;
  let codes =
    member "suggest" j |> member "codes" |> to_list
    |> List.map (fun r -> (to_string (member "code" r), to_string (member "category" r)))
  in
  Alcotest.(check (option string))
    "tenancy never relaxed" (Some "never_weaken")
    (List.assoc_opt "E_TENANT_MISSING" codes);
  Alcotest.(check (option string))
    "param unbound: query fix" (Some "query_fix")
    (List.assoc_opt "E_PARAM_UNBOUND" codes);
  Alcotest.(check bool)
    "chain status reported" true
    (contains (Yojson.Safe.to_string (member "inputs" j)) "hash chain ok"
    || contains (Yojson.Safe.to_string (member "inputs" j)) "not hash-chained")

let () =
  match skip_reason with
  | Some why ->
      Printf.printf "SKIP test_report_proxy: %s\n" why;
      Alcotest.run "report-proxy"
        [ ("proxy", [ Alcotest.test_case ("skipped: " ^ why) `Quick (fun () -> ()) ]) ]
  | None ->
      let audit =
        try run_traffic ()
        with e ->
          cleanup ();
          raise e
      in
      Fun.protect ~finally:cleanup (fun () ->
          Alcotest.run ~and_exit:false "report-proxy"
            [
              ( "proxy",
                [
                  Alcotest.test_case "haltsql report on real proxy audit records" `Quick
                    (proxy_report audit);
                ] );
            ])
