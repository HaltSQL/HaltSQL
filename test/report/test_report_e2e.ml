(* End-to-end: real audit records from in-process haltsql-servers (one logging raw SQL,
   one logging only hashes), the `haltsql report` command on them (summary, suggestions,
   --apply-to with a patched policy that then allows the denied queries and still denies
   tenant escapes), and Report_api (the server's rolling report endpoint). *)

open Lwt.Syntax
open Haltsql_server
module Client = Cohttp_lwt_unix.Client
module R = Haltsql_report
module Report = Report_api.Make (Haltsql_report.Live)

let fx name = Filename.concat (Sys.getcwd ()) (Filename.concat "fixtures" name)

let tmpdir =
  let d =
    Filename.concat
      (Filename.get_temp_dir_name ())
      (Printf.sprintf "haltsql-shadow-report-%d" (Unix.getpid ()))
  in
  (try Unix.mkdir d 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  d

let tmp name = Filename.concat tmpdir name
let read_file f = In_channel.with_open_bin f In_channel.input_all
let cli = Option.get (Sys.getenv_opt "HALTSQL_REPORT_CLI")
let cli = if Filename.is_relative cli then Filename.concat (Sys.getcwd ()) cli else cli

let contains s sub =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  n = 0 || go 0

let token_analytics = "token-analytics-3f9a"
let token_bi = "token-bi-77c1"
let audit_raw = tmp "audit-raw.jsonl"
let audit_hashed = tmp "audit-hashed.jsonl"

let () =
  List.iter
    (fun f -> try Sys.remove f with Sys_error _ -> ())
    [ audit_raw; audit_hashed ]

let start ~audit ~raw =
  let sources =
    {
      State.config_file = None;
      policy_files = [ fx "shop-shadow.yaml"; fx "shop-enforce.yaml" ];
      overrides =
        (fun c ->
          {
            c with
            Haltsql.Config.tokens =
              [
                {
                  token_name = "analytics";
                  token_sha256 = Auth.sha256_hex token_analytics;
                  token_policy = "shop-shadow";
                };
                {
                  token_name = "bi";
                  token_sha256 = Auth.sha256_hex token_bi;
                  token_policy = "shop-enforce";
                };
              ];
            allow_unauthenticated = false;
            audit_sinks = [ Haltsql.Config.Audit_file audit ];
            sinks =
              [
                {
                  Haltsql.Config.sink = Haltsql.Config.Sink_file audit;
                  on_error = Haltsql.Config.Fail_closed;
                };
              ];
            log_raw_sql = raw;
            reload_watch = false;
          });
    }
  in
  match State.load sources with
  | Error e -> failwith (String.concat "; " e)
  | Ok cfg ->
      let st = State.create ~sources cfg in
      let fd, port = Server.bind_listen "127.0.0.1:0" in
      let stop, _ = Lwt.wait () in
      Lwt.async (fun () -> Server.serve ~watch_interval:0.5 st fd ~stop);
      (st, port)

let () = Log.setup ~level:"error" ~format:"json"
let st_raw, port_raw = start ~audit:audit_raw ~raw:true
let _st_hashed, port_hashed = start ~audit:audit_hashed ~raw:false

let verify port token sql =
  let body =
    Printf.sprintf {|{"sql":%s,"context":{"tenant_id":"acme"}}|}
      (Yojson.Safe.to_string (`String sql))
  in
  let* r, b =
    Client.call
      ~headers:
        (Cohttp.Header.of_list
           [ ("authorization", "Bearer " ^ token); ("content-type", "application/json") ])
      ~body:(Cohttp_lwt.Body.of_string body)
      `POST
      (Uri.of_string (Printf.sprintf "http://127.0.0.1:%d/v1/verify" port))
  in
  let* s = Cohttp_lwt.Body.to_string b in
  let code = Cohttp.Code.code_of_status (Cohttp.Response.status r) in
  if code <> 200 then failwith (Printf.sprintf "verify %d: %s" code s);
  Lwt.return (Yojson.Safe.from_string s)

(* Shadow traffic of the analytics agent, and enforced traffic of the bi agent. *)
let shadow_queries =
  [
    "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT 10";
    "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT 20";
    "SELECT status, region FROM app.orders WHERE tenant_id = $1 LIMIT 20";
    "SELECT md5(status) FROM app.orders WHERE tenant_id = $1 LIMIT 10";
    "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 500";
    "SELECT r.id, r.amount_cents FROM app.refunds r WHERE r.tenant_id = $1 LIMIT 10";
    "SELECT email FROM app.customers WHERE tenant_id = $1 LIMIT 10";
    "SELECT shipping_address FROM app.orders WHERE tenant_id = $1 LIMIT 10";
    "SELECT pg_sleep(5) FROM app.currencies LIMIT 1";
    "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT $2";
    "SELEC id FROM app.orders";
    "DELETE FROM app.orders WHERE tenant_id = $1";
    "SELECT id, status FROM app.orders WHERE tenant_id = $1 LIMIT 10";
  ]

let escapes =
  [
    "SELECT id, region FROM app.orders LIMIT 10";
    "SELECT md5(status) FROM app.orders WHERE tenant_id = 'globex' LIMIT 10";
    "SELECT r.id FROM app.refunds r LIMIT 10";
    "SELECT id FROM app.orders WHERE tenant_id = $1 OR true LIMIT 500";
  ]

let enforced_queries =
  [
    "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT 10";
    "SELECT code FROM app.currencies LIMIT 10";
  ]

let generate () =
  Lwt_main.run
    (let* () =
       Lwt_list.iter_s
         (fun sql ->
           let* _ = verify port_raw token_analytics sql in
           let* _ = verify port_hashed token_analytics sql in
           Lwt.return_unit)
         (shadow_queries @ escapes)
     in
     Lwt_list.iter_s
       (fun sql ->
         let* _ = verify port_raw token_bi sql in
         let* _ = verify port_hashed token_bi sql in
         Lwt.return_unit)
       enforced_queries)

let () = generate ()

let run_cli args =
  let argv = Array.of_list (cli :: "report" :: args) in
  let ic, oc, ec = Unix.open_process_args_full cli argv (Unix.environment ()) in
  close_out oc;
  let out = In_channel.input_all ic and err = In_channel.input_all ec in
  let code =
    match Unix.close_process_full (ic, oc, ec) with
    | Unix.WEXITED c -> c
    | Unix.WSIGNALED _ | Unix.WSTOPPED _ -> 255
  in
  (code, out, err)

let json_cli args =
  match run_cli ("--format" :: "json" :: args) with
  | 0, out, _ -> Yojson.Safe.from_string out
  | c, out, err -> Alcotest.failf "report exited %d: %s %s" c out err

let ( |> ) x f = f x
let member k j = Yojson.Safe.Util.member k j
let to_int = Yojson.Safe.Util.to_int
let to_list = Yojson.Safe.Util.to_list
let to_string = Yojson.Safe.Util.to_string
let rows key j = to_list j |> List.map (fun r -> (to_string (member key r), r))

let suggestion_ids j =
  member "suggest" j |> member "suggestions" |> to_list
  |> List.map (fun s -> to_string (member "id" s))
  |> List.sort compare

(* ------------------------------------------------------------------ tests *)

let n_shadow = List.length shadow_queries + List.length escapes

let audit_records () =
  (* the server's own chain verifier accepts both files; the report says so too *)
  List.iter
    (fun f ->
      match Audit.verify_file f with
      | Ok n -> Alcotest.(check int) "records" (n_shadow + List.length enforced_queries) n
      | Error e -> Alcotest.failf "%s: line %d: %s" f e.line_no e.problem)
    [ audit_raw; audit_hashed ];
  let lines =
    read_file audit_raw |> String.split_on_char '\n' |> List.filter (fun l -> l <> "")
  in
  let recs = List.map (fun l -> Result.get_ok (R.Record.of_line l)) lines in
  Alcotest.(check int) "all parsed" (List.length lines) (List.length recs);
  let first = List.hd recs in
  Alcotest.(check string) "caller" "analytics" first.caller;
  Alcotest.(check string) "policy" "shop-shadow" first.policy;
  Alcotest.(check string)
    "shadow" "shadow_denied"
    (R.Record.outcome_to_string first.outcome);
  Alcotest.(check (list string)) "codes" [ "E_COLUMN_DENIED" ] first.codes;
  Alcotest.(check bool) "raw sql logged" true (first.sql <> None);
  let hashed =
    read_file audit_hashed |> String.split_on_char '\n'
    |> List.filter (fun l -> l <> "")
    |> List.map (fun l -> Result.get_ok (R.Record.of_line l))
  in
  Alcotest.(check bool)
    "no raw sql" true
    (List.for_all (fun (r : R.Record.t) -> r.sql = None) hashed)

let cli_summary () =
  let j = json_cli [ audit_raw ] in
  let s = member "summary" j in
  Alcotest.(check int) "records" (n_shadow + 2) (to_int (member "records" s));
  let totals = member "totals" s in
  Alcotest.(check int)
    "shadow-denied" (n_shadow - 1)
    (to_int (member "shadow_denied" totals));
  Alcotest.(check int) "denied" 1 (to_int (member "denied" totals));
  Alcotest.(check int) "allowed" 2 (to_int (member "allowed" totals));
  let by_caller = rows "caller" (member "by_caller" s) in
  Alcotest.(check (list string)) "callers" [ "analytics"; "bi" ] (List.map fst by_caller);
  let by_code = rows "code" (member "by_code" s) in
  Alcotest.(check int)
    "E_COLUMN_DENIED" 7
    (to_int (member "total" (List.assoc "E_COLUMN_DENIED" by_code)));
  Alcotest.(check bool)
    "inputs report the chain" true
    (contains (Yojson.Safe.to_string (member "inputs" j)) "hash chain ok");
  Alcotest.(check bool)
    "no suggest section without --suggest" true
    (member "suggest" j = `Null);
  (* filters *)
  let j = json_cli [ audit_raw; "--policy"; "shop-enforce" ] in
  Alcotest.(check int) "policy filter" 2 (to_int (member "records" (member "summary" j)));
  let j = json_cli [ audit_raw; "--since"; "2099-01-01" ] in
  Alcotest.(check int) "since" 0 (to_int (member "records" (member "summary" j)));
  let j = json_cli [ audit_raw; "--until"; "2000-01-01" ] in
  Alcotest.(check int) "until" 0 (to_int (member "records" (member "summary" j)));
  (* a directory, and stdin *)
  let j = json_cli [ tmpdir ] in
  Alcotest.(check int)
    "directory"
    (2 * (n_shadow + 2))
    (to_int (member "records" (member "summary" j)));
  let code, out, _ =
    let argv =
      [|
        "/bin/sh";
        "-c";
        Printf.sprintf "%s report --format json - < %s" (Filename.quote cli)
          (Filename.quote audit_raw);
      |]
    in
    let ic, oc, ec = Unix.open_process_args_full "/bin/sh" argv (Unix.environment ()) in
    close_out oc;
    let out = In_channel.input_all ic in
    ignore (In_channel.input_all ec);
    ( (match Unix.close_process_full (ic, oc, ec) with Unix.WEXITED c -> c | _ -> 255),
      out )
    |> fun (c, o) -> (c, o, ())
  in
  Alcotest.(check int) "stdin exit" 0 code;
  Alcotest.(check int)
    "stdin" (n_shadow + 2)
    (to_int (member "records" (member "summary" (Yojson.Safe.from_string out))));
  (* text and markdown *)
  let code, text, _ =
    run_cli [ audit_raw; "--suggest"; "--policy-file"; fx "shop-shadow.yaml" ]
  in
  Alcotest.(check int) "text exit" 0 code;
  List.iter
    (fun s -> Alcotest.(check bool) s true (contains text s))
    [
      "HaltSQL shadow report";
      "By reason code";
      "Top denied queries";
      "Suggestions";
      "add region to tables.app.orders.columns";
    ];
  let code, md, _ =
    run_cli
      [
        audit_raw;
        "--format";
        "markdown";
        "--suggest";
        "--policy-file";
        fx "shop-shadow.yaml";
      ]
  in
  Alcotest.(check int) "markdown exit" 0 code;
  Alcotest.(check bool)
    "markdown table" true
    (contains md "| Code | Total | Denied | Shadow-denied |");
  Alcotest.(check bool) "markdown yaml" true (contains md "```yaml");
  (* usage errors *)
  let code, _, err = run_cli [ audit_raw; "--apply-to"; fx "shop-shadow.yaml" ] in
  Alcotest.(check int) "apply-to without -o" 2 code;
  Alcotest.(check bool) "message" true (contains err "-o");
  let code, _, _ = run_cli [ tmp "missing.jsonl" ] in
  Alcotest.(check int) "missing input" 2 code;
  let code, _, _ = run_cli [ audit_raw; "--since"; "soon" ] in
  Alcotest.(check int) "bad since" 2 code

let cli_suggest () =
  let j =
    json_cli
      [
        audit_raw;
        "--suggest";
        "--policy-file";
        fx "shop-shadow.yaml";
        "--policy-file";
        fx "shop-enforce.yaml";
        "--pii";
        fx "pii.json";
      ]
  in
  Alcotest.(check (list string))
    "suggestions"
    [
      "shop-enforce/column/app.orders.region";
      "shop-shadow/column/app.orders.region";
      "shop-shadow/function/md5";
      "shop-shadow/limit";
      "shop-shadow/table/app.refunds";
    ]
    (suggestion_ids j);
  let sg = member "suggest" j in
  let region =
    List.find
      (fun s -> to_string (member "id" s) = "shop-shadow/column/app.orders.region")
      (to_list (member "suggestions" sg))
  in
  (* three shadow queries plus the tenant escape that also reads region *)
  Alcotest.(check int) "evidence" 4 (to_int (member "records" (member "evidence" region)));
  Alcotest.(check bool)
    "summary" true
    (contains
       (to_string (member "summary" region))
       "4 shadow-denied queries by caller analytics read app.orders.region \
        (E_COLUMN_DENIED)");
  let flagged =
    to_list (member "pii_flagged" sg) |> List.map (fun i -> to_string (member "target" i))
  in
  Alcotest.(check bool)
    "manifest PII" true
    (List.mem "app.orders.shipping_address" flagged);
  Alcotest.(check bool) "heuristic PII" true (List.mem "app.customers.email" flagged);
  let codes =
    to_list (member "codes" sg)
    |> List.map (fun r -> (to_string (member "code" r), to_string (member "category" r)))
  in
  List.iter
    (fun (c, cat) ->
      Alcotest.(check (option string)) c (Some cat) (List.assoc_opt c codes))
    [
      ("E_TENANT_MISSING", "never_weaken");
      ("E_STATEMENT_KIND", "never_weaken");
      ("E_PARSE", "query_fix");
    ];
  let unsafe =
    to_list (member "not_suggested" sg)
    |> List.filter_map (fun i ->
        if to_string (member "category" i) = "unsafe" then
          Some (to_string (member "target" i))
        else None)
  in
  Alcotest.(check bool) "pg_sleep refused" true (List.mem "pg_sleep()" unsafe);
  (* hashed-only log: codes but no detail *)
  let j =
    json_cli [ audit_hashed; "--suggest"; "--policy-file"; fx "shop-shadow.yaml" ]
  in
  Alcotest.(check (list string)) "no detail, no suggestion" [] (suggestion_ids j);
  Alcotest.(check bool)
    "missing detail counted" true
    (to_int (member "missing_detail" (member "suggest" j)) > 0)

let codes_of (v : Haltsql.Verdict.t) =
  List.map
    (fun (r : Haltsql.Reason.t) -> Haltsql.Reason.code_to_string r.code)
    (v.reasons @ v.shadow_reasons)

let cli_apply () =
  let out = tmp "patched/shop-shadow.next.yaml" in
  let code, text, err =
    run_cli
      [
        audit_raw; "--pii"; fx "pii.json"; "--apply-to"; fx "shop-shadow.yaml"; "-o"; out;
      ]
  in
  if code <> 0 then Alcotest.failf "apply exited %d: %s %s" code text err;
  Alcotest.(check bool) "note" true (contains text "applied 4 suggestion(s)");
  Alcotest.(check bool)
    "what-if" true
    (contains text "tenancy denial(s) are still denied");
  let patched =
    match Haltsql.Policy_load.of_file out with
    | Ok p -> p
    | Error e ->
        Alcotest.failf "patched policy does not load: %s"
          (String.concat "; " (List.map Haltsql.Load_error.to_string e))
  in
  Alcotest.(check bool) "header comment" true (contains (read_file out) "# Patched by");
  let ctx = Haltsql.Context.make [ ("tenant_id", Haltsql.Context.One "acme") ] in
  let previously_denied =
    [
      "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT 10";
      "SELECT status, region FROM app.orders WHERE tenant_id = $1 LIMIT 20";
      "SELECT md5(status) FROM app.orders WHERE tenant_id = $1 LIMIT 10";
      "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 500";
      "SELECT r.id, r.amount_cents FROM app.refunds r WHERE r.tenant_id = $1 LIMIT 10";
    ]
  in
  let enforced = { patched with mode = Haltsql.Policy.Enforce } in
  List.iter
    (fun sql ->
      let v = Haltsql.verify enforced ctx sql in
      Alcotest.(check (list string)) ("now allowed: " ^ sql) [] (codes_of v);
      Alcotest.(check bool) "allowed" true v.allowed)
    previously_denied;
  List.iter
    (fun sql ->
      let v = Haltsql.verify enforced ctx sql in
      Alcotest.(check bool) ("tenant escape still denied: " ^ sql) false v.allowed;
      Alcotest.(check bool)
        "tenancy code" true
        (List.exists (fun c -> contains c "E_TENANT") (codes_of v)))
    escapes;
  (* PII stays denied; writes stay denied *)
  List.iter
    (fun sql ->
      let v = Haltsql.verify enforced ctx sql in
      Alcotest.(check bool) ("still denied: " ^ sql) false v.allowed)
    [
      "SELECT email FROM app.customers WHERE tenant_id = $1 LIMIT 10";
      "SELECT shipping_address FROM app.orders WHERE tenant_id = $1 LIMIT 10";
      "DELETE FROM app.orders WHERE tenant_id = $1";
      "SELECT pg_sleep(5) FROM app.currencies LIMIT 1";
    ];
  (* --accept applies only the chosen suggestion; JSON output *)
  let out_json = tmp "patched/only-md5.json" in
  let code, _, err =
    run_cli
      [
        audit_raw;
        "--apply-to";
        fx "shop-shadow.yaml";
        "--accept";
        "shop-shadow/function/md5";
        "-o";
        out_json;
      ]
  in
  if code <> 0 then Alcotest.failf "accept exited %d: %s" code err;
  (match Haltsql.Policy_load.of_file out_json with
  | Ok p ->
      Alcotest.(check bool) "md5 allowed" true (List.mem "md5" p.functions);
      Alcotest.(check bool)
        "region not added" false
        (List.exists
           (fun (t : Haltsql.Policy.table) ->
             t.name = "orders"
             &&
             match t.columns with
             | Haltsql.Policy.Only l -> List.mem "region" l
             | All -> true)
           p.tables)
  | Error _ -> Alcotest.fail "json output does not load");
  let code, _, err =
    run_cli
      [
        audit_raw; "--apply-to"; fx "shop-shadow.yaml"; "--accept"; "nope"; "-o"; out_json;
      ]
  in
  Alcotest.(check int) "unknown --accept" 2 code;
  Alcotest.(check bool) "message" true (contains err "no such suggestion")

(* ------------------------------------------------------------- Report_api *)

let admin ?(enabled = true) ?(window = 3600) ?(max = 1000) () =
  {
    Haltsql.Config.default_admin with
    admin_enabled = enabled;
    report_window_seconds = window;
    max_tracked_queries = max;
  }

let audit_fields file =
  read_file file |> String.split_on_char '\n'
  |> List.filter (fun l -> l <> "")
  |> List.map (fun l ->
      match Yojson.Safe.from_string l with `Assoc kv -> kv | _ -> Alcotest.fail "record")

let distinct_fps file =
  audit_fields file
  |> List.filter_map Haltsql_report.Live.of_audit_fields
  |> List.map Haltsql_report.Live.fingerprint
  |> List.sort_uniq compare |> List.length

let report_api () =
  let clock = ref (Unix.gettimeofday ()) in
  let now () = !clock in
  let policies = st_raw.snap.policies in
  (* disabled: nothing kept, 404 *)
  let off = Report.create ~now (admin ~enabled:false ()) in
  List.iter (Report.observe off) (audit_fields audit_raw);
  Alcotest.(check int) "disabled keeps nothing" 0 (Report.tracked off);
  Alcotest.(check int) "disabled 404" 404 (fst (Report.handle off ~policies ~query:[]));
  (* enabled: records exactly as the server writes them (raw SQL on) *)
  let t = Report.create ~now (admin ()) in
  List.iter (Report.observe t) (audit_fields audit_raw);
  let status, body = Report.handle t ~policies ~query:[] in
  Alcotest.(check int) "200" 200 status;
  Alcotest.(check int)
    "tracked records" (n_shadow + 2)
    (to_int (member "tracked_records" body));
  Alcotest.(check int)
    "tracked queries" (distinct_fps audit_raw)
    (to_int (member "tracked_queries" body));
  Alcotest.(check int)
    "records" (n_shadow + 2)
    (to_int (member "records" (member "summary" body)));
  let ids =
    member "suggest" body |> member "suggestions" |> to_list
    |> List.map (fun s -> to_string (member "id" s))
  in
  Alcotest.(check bool)
    "server suggests the column" true
    (List.mem "shop-shadow/column/app.orders.region" ids);
  (* the window keeps one SQL per fingerprint; the details are shared with the rest *)
  let region =
    member "suggest" body |> member "suggestions" |> to_list
    |> List.find (fun s ->
        to_string (member "id" s) = "shop-shadow/column/app.orders.region")
  in
  Alcotest.(check int)
    "evidence across one fingerprint" 4
    (to_int (member "records" (member "evidence" region)));
  Alcotest.(check bool)
    "server flags email (name heuristic)" true
    (List.exists
       (fun i -> to_string (member "target" i) = "app.customers.email")
       (to_list (member "pii_flagged" (member "suggest" body))));
  (* verdict path: detail without raw SQL *)
  let v2 = Report.create ~now (admin ()) in
  let ctx = Haltsql.Context.make [ ("tenant_id", Haltsql.Context.One "acme") ] in
  let shadow_policy = List.assoc "shop-shadow" policies in
  List.iter
    (fun sql ->
      Report.observe_verdict v2 ~caller:"analytics" ~caller_type:"token" ~sql:None
        (Haltsql.verify shadow_policy ctx sql))
    shadow_queries;
  let _, body = Report.handle v2 ~policies ~query:[ ("policy", [ "shop-shadow" ]) ] in
  let sugg = member "suggest" body |> member "suggestions" |> to_list in
  let applicable id =
    List.find_map
      (fun s ->
        if to_string (member "id" s) = id then
          Some (Yojson.Safe.Util.to_bool (member "applicable" s))
        else None)
      sugg
  in
  Alcotest.(check (option bool))
    "column from verdict detail" (Some true)
    (applicable "shop-shadow/column/app.orders.region");
  Alcotest.(check (option bool))
    "table without SQL: not applicable" (Some false)
    (applicable "shop-shadow/table/app.refunds");
  Alcotest.(check bool)
    "no SQL in the report" false
    (contains (Yojson.Safe.to_string body) "SELECT");
  (* parameters *)
  let bad q = fst (Report.handle t ~policies ~query:q) in
  Alcotest.(check int) "unknown param" 400 (bad [ ("x", [ "1" ]) ]);
  Alcotest.(check int) "bad top" 400 (bad [ ("top", [ "0" ]) ]);
  Alcotest.(check int) "bad suggest" 400 (bad [ ("suggest", [ "maybe" ]) ]);
  Alcotest.(check int) "bad since" 400 (bad [ ("since", [ "soon" ]) ]);
  Alcotest.(check int) "repeated" 400 (bad [ ("top", [ "1"; "2" ]) ]);
  let _, b =
    Report.handle t ~policies ~query:[ ("suggest", [ "false" ]); ("top", [ "1" ]) ]
  in
  Alcotest.(check bool) "suggest=false" true (member "suggest" b = `Null);
  Alcotest.(check int)
    "top=1" 1
    (List.length (to_list (member "top_denied" (member "summary" b))));
  (* bounds: distinct queries (least recently seen evicted first) *)
  let small = Report.create ~now (admin ~max:5 ()) in
  List.iter (Report.observe small) (audit_fields audit_raw);
  Alcotest.(check int) "bounded queries" 5 (Report.tracked_queries small);
  (* a query seen again after its eviction is tracked (and later evicted) anew *)
  Alcotest.(check bool) "evicted" true (Report.evicted small >= distinct_fps audit_raw - 5);
  let last5 =
    List.rev (audit_fields audit_raw)
    |> List.filter_map (fun kv -> Haltsql_report.Live.of_audit_fields kv)
    |> List.map Haltsql_report.Live.fingerprint
    |> List.fold_left
         (fun acc f -> if List.mem f acc || List.length acc = 5 then acc else f :: acc)
         []
  in
  let _, b =
    Report.handle small ~policies ~query:[ ("suggest", [ "false" ]); ("top", [ "100" ]) ]
  in
  let kept =
    member "summary" b |> member "top_denied" |> to_list
    |> List.map (fun q -> to_string (member "fingerprint" q))
  in
  List.iter
    (fun f -> Alcotest.(check bool) "most recent kept" true (List.mem f last5))
    kept;
  (* bounds: records per query; only one keeps its SQL *)
  let hot = Report.create ~now (admin ()) in
  let one = List.hd (audit_fields audit_raw) in
  for _ = 1 to 40 do
    Report.observe hot one
  done;
  Alcotest.(check int) "one query" 1 (Report.tracked_queries hot);
  Alcotest.(check int) "records capped" Report_api.records_per_query (Report.tracked hot);
  Alcotest.(check int)
    "sampled out"
    (40 - Report_api.records_per_query)
    (Report.sampled_out hot);
  (* bounds: age *)
  let aged = Report.create ~now (admin ~window:60 ()) in
  List.iter (Report.observe aged) (audit_fields audit_raw);
  clock := !clock +. 61.;
  let _, b = Report.handle aged ~policies ~query:[] in
  Alcotest.(check int) "window expired" 0 (to_int (member "tracked_records" b));
  (* reconfigure: disabling drops everything *)
  Report.reconfigure t (admin ~enabled:false ());
  Alcotest.(check int) "dropped on disable" 0 (Report.tracked t)

let () =
  Alcotest.run "report-e2e"
    [
      ( "server",
        [
          Alcotest.test_case "audit records from the real server" `Quick audit_records;
          Alcotest.test_case "haltsql report: summary, filters, formats" `Quick
            cli_summary;
          Alcotest.test_case "haltsql report --suggest" `Quick cli_suggest;
          Alcotest.test_case "haltsql report --apply-to" `Quick cli_apply;
          Alcotest.test_case "Report_api rolling window and handler" `Quick report_api;
        ] );
    ]
