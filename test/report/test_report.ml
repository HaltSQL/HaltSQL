(* Unit tests of haltsql.report against the real verifier: records, findings, summaries,
   every suggestion rule, the never-weaken rules, PII flagging, patching, and a QCheck
   property that applying suggestions never turns a tenancy denial into an allow. *)

open Haltsql
module R = Haltsql_report

let fx name = Filename.concat "fixtures" name

let load file =
  match Policy_load.of_file (fx file) with
  | Ok p -> p
  | Error e ->
      Alcotest.failf "cannot load %s: %s" file
        (String.concat "; " (List.map Load_error.to_string e))

let shadow = load "shop-shadow.yaml"
let enforce = load "shop-enforce.yaml"
let ctx = Context.make [ ("tenant_id", Context.One "acme") ]
let t0 = 1_780_000_000.

(* A record exactly as the server would build it for this verdict. *)
let record ?(policy = enforce) ?(caller = "analytics") ?(ts = t0) ?(with_sql = true) sql =
  let v = Haltsql.verify policy ctx sql in
  R.Record.of_verdict ~ts ~caller ~caller_type:"token"
    ~sql:(if with_sql then Some sql else None)
    v

let codes_of (v : Verdict.t) =
  List.map
    (fun (r : Reason.t) -> Reason.code_to_string r.code)
    (v.reasons @ v.shadow_reasons)

let cfg ?(pii = R.Pii.none)
    ?(policies = [ (enforce.name, enforce); (shadow.name, shadow) ]) () =
  { R.Suggest.default_config with policies; pii; verify = Some Haltsql.verify }

let ids (t : R.Suggest.t) =
  List.map (fun (s : R.Suggest.suggestion) -> s.id) t.suggestions

let find_item (t : R.Suggest.t) target =
  List.find_opt
    (fun (i : R.Suggest.item) -> i.target = target)
    (t.pii_flagged @ t.not_suggested)

let check_ids msg expected t =
  Alcotest.(check (list string))
    msg (List.sort compare expected)
    (List.sort compare (ids t))

(* ------------------------------------------------------------------ time *)

let time () =
  let p s = R.Rtime.parse_rfc3339 s in
  Alcotest.(check (option (float 0.001))) "epoch" (Some 0.) (p "1970-01-01T00:00:00Z");
  Alcotest.(check (option (float 0.001)))
    "millis" (Some 1717243200.123)
    (p "2024-06-01T12:00:00.123Z");
  Alcotest.(check (option (float 0.001)))
    "offset" (Some 1717243200.)
    (p "2024-06-01T14:00:00+02:00");
  Alcotest.(check (option (float 0.001)))
    "leap day" (Some 1709208000.) (p "2024-02-29T12:00:00Z");
  List.iter
    (fun s -> Alcotest.(check (option (float 0.))) s None (p s))
    [
      "";
      "2024-02-30T00:00:00Z";
      "2024-06-01T12:00:00";
      "2024-06-01T25:00:00Z";
      "x";
      "2024-06-01T12:00:00Zjunk";
    ];
  Alcotest.(check string)
    "format" "2024-06-01T12:00:00Z"
    (R.Rtime.to_rfc3339 1717243200.9);
  Alcotest.(check (result (float 0.) string))
    "24h"
    (Ok (100000. -. 86400.))
    (R.Rtime.parse_bound ~now:100000. "24h");
  Alcotest.(check (result (float 0.) string))
    "date" (Ok 1717200000.)
    (R.Rtime.parse_bound ~now:0. "2024-06-01");
  Alcotest.(check bool)
    "bad bound" true
    (Result.is_error (R.Rtime.parse_bound ~now:0. "soon"));
  Alcotest.(check bool)
    "zero duration" true
    (Result.is_error (R.Rtime.parse_duration "0h"))

(* --------------------------------------------------------------- records *)

let server_line =
  {|{"ts":"2026-11-07T10:00:00.000Z","request_id":"r1","caller":"analytics","caller_type":"token","subject":null,"policy":"shop-shadow","policy_version":"sha256:ab","allowed":true,"shadow":true,"codes":["E_COLUMN_DENIED","E_COLUMN_DENIED"],"sql_sha256":"aa","fingerprint":"fp1","elapsed_us":10,"prev_hash":"00","hash":"11"}|}

let proxy_line =
  {|{"ts":"2026-11-07T10:00:01.500Z","event":"statement","session":"s1","user":"agent","policy":"shop-enforce","policy_version":"sha256:cd","protocol":"extended","allowed":false,"reasons":["E_TABLE_DENIED"],"shadow_reasons":[],"sql_sha256":"bb","fingerprint":"fp2","tables":["app.refunds"],"bind_params":[1],"statement":"","sql":"SELECT 1"}|}

let proxy_local =
  {|{"ts":"2026-11-07T10:00:02Z","event":"bind","session":"s1","user":"agent","policy":"shop-enforce","allowed":false,"reasons":["E_PARAM_UNBOUND"],"message":"haltsql: ..."}|}

let records_parse () =
  let ok l = match R.Record.of_line l with Ok r -> r | Error e -> Alcotest.fail e in
  let s = ok server_line in
  Alcotest.(check string)
    "server outcome" "shadow_denied"
    (R.Record.outcome_to_string s.outcome);
  Alcotest.(check (list string)) "dedup codes" [ "E_COLUMN_DENIED" ] s.codes;
  Alcotest.(check string) "caller" "analytics" s.caller;
  Alcotest.(check (option string)) "no sql" None s.sql;
  Alcotest.(check (option (float 0.001)))
    "ts"
    (R.Rtime.parse_rfc3339 "2026-11-07T10:00:00Z")
    s.ts;
  let p = ok proxy_line in
  Alcotest.(check string) "proxy outcome" "denied" (R.Record.outcome_to_string p.outcome);
  Alcotest.(check string) "proxy user" "agent" p.caller;
  Alcotest.(check (list string)) "tables" [ "app.refunds" ] p.tables;
  Alcotest.(check (option string)) "sql" (Some "SELECT 1") p.sql;
  let l = ok proxy_local in
  Alcotest.(check string) "local event" "bind" l.event;
  Alcotest.(check (list string)) "local codes" [ "E_PARAM_UNBOUND" ] l.codes;
  let allowed =
    ok
      {|{"ts":"2026-11-07T10:00:00Z","caller":"a","policy":"p","allowed":true,"shadow":false,"codes":[]}|}
  in
  Alcotest.(check string) "allowed" "allowed" (R.Record.outcome_to_string allowed.outcome);
  let denied =
    ok {|{"caller":"a","policy":"p","allowed":false,"shadow":false,"codes":["E_PARSE"]}|}
  in
  Alcotest.(check string) "denied" "denied" (R.Record.outcome_to_string denied.outcome);
  Alcotest.(check (option (float 0.))) "untimed" None denied.ts;
  List.iter
    (fun l -> Alcotest.(check bool) l true (Result.is_error (R.Record.of_line l)))
    [
      "not json";
      "[]";
      {|{"ts":"x","level":"info","msg":"listening"}|};
      {|{"allowed":"yes","codes":[]}|};
      {|{"allowed":true,"codes":"E_PARSE"}|};
      {|{"allowed":true,"codes":[1]}|};
      {|{"event":"statement","reasons":[]}|};
    ]

(* -------------------------------------------------------------- findings *)

let finding_of policy sql =
  let v = Haltsql.verify policy ctx sql in
  List.map
    (fun (r : Reason.t) ->
      R.Finding.of_reason
        {
          R.Record.code = Reason.code_to_string r.code;
          rule = r.rule;
          message = r.message;
        })
    (v.reasons @ v.shadow_reasons)

let findings () =
  let has msg sql pred =
    Alcotest.(check bool) msg true (List.exists pred (finding_of enforce sql))
  in
  has "column" "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT 5" (function
    | R.Finding.Column { table = "app.orders"; column = "region" } -> true
    | _ -> false);
  has "star" "SELECT * FROM app.orders WHERE tenant_id = $1 LIMIT 5" (function
    | R.Finding.Column_star "app.orders" -> true
    | _ -> false);
  has "function" "SELECT md5(status) FROM app.orders WHERE tenant_id = $1 LIMIT 5"
    (function
    | R.Finding.Function "md5" -> true
    | _ -> false);
  has "qualified function"
    "SELECT app.f(status) FROM app.orders WHERE tenant_id = $1 LIMIT 5" (function
    | R.Finding.Function "app.f" -> true
    | _ -> false);
  has "sql value" "SELECT current_user FROM app.currencies LIMIT 1" (function
    | R.Finding.Sql_value_function _ -> true
    | _ -> false);
  has "qualified table" "SELECT id FROM app.refunds WHERE tenant_id = $1 LIMIT 5"
    (function
    | R.Finding.Table { schema = Some "app"; name = "refunds" } -> true
    | _ -> false);
  has "unqualified table" "SELECT id FROM refunds WHERE tenant_id = $1 LIMIT 5" (function
    | R.Finding.Table { schema = None; name = "refunds" } -> true
    | _ -> false);
  has "system catalog" "SELECT usename FROM pg_shadow LIMIT 1" (function
    | R.Finding.System_relation "pg_shadow" -> true
    | _ -> false);
  has "limit" "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 500" (function
    | R.Finding.Limit_value 500 -> true
    | _ -> false);
  has "limit param" "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT $2" (function
    | R.Finding.Limit_non_constant -> true
    | _ -> false);
  Alcotest.(check bool)
    "unknown rule" true
    (R.Finding.of_reason { R.Record.code = "E_X"; rule = "x.y"; message = "z" }
    = R.Finding.Unrecognized)

(* --------------------------------------------------------------- summary *)

let summary () =
  let recs =
    [
      record ~ts:t0 "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT 5";
      record ~ts:(t0 +. 60.)
        "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT 6";
      record ~ts:(t0 +. 4000.) ~caller:"bi" ~with_sql:false
        "SELECT id FROM app.orders LIMIT 5";
      record ~ts:(t0 +. 4100.) ~caller:"bi"
        "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 5";
      record ~policy:shadow ~ts:(t0 +. 4200.)
        "SELECT md5(status) FROM app.orders WHERE tenant_id = $1 LIMIT 5";
    ]
  in
  let s = R.Summary.compute ~bucket_seconds:3600 recs in
  Alcotest.(check int) "records" 5 s.records;
  Alcotest.(check int) "allowed" 1 s.totals.allowed;
  Alcotest.(check int) "denied" 3 s.totals.denied;
  Alcotest.(check int) "shadow" 1 s.totals.shadow_denied;
  let code c =
    List.assoc_opt c s.by_code |> Option.map (fun (c : R.Summary.count) -> c.total)
  in
  Alcotest.(check (option int)) "column denied" (Some 2) (code "E_COLUMN_DENIED");
  Alcotest.(check (option int)) "tenant missing" (Some 1) (code "E_TENANT_MISSING");
  Alcotest.(check (option int)) "function" (Some 1) (code "E_FUNCTION_DENIED");
  Alcotest.(check bool)
    "region column" true
    (List.mem_assoc "app.orders.region" s.by_column);
  Alcotest.(check bool) "orders table" true (List.mem_assoc "app.orders" s.by_table);
  Alcotest.(check (list string))
    "callers" [ "analytics"; "bi" ] (List.map fst s.by_caller);
  Alcotest.(check (list string))
    "policies"
    [ "shop-enforce"; "shop-shadow" ]
    (List.sort compare (List.map fst s.by_policy));
  Alcotest.(check int) "buckets" 2 (List.length s.buckets);
  (* the two region queries share a fingerprint: one group, counted twice *)
  let top = List.hd s.top_denied in
  Alcotest.(check int) "grouped" 2 top.count.total;
  Alcotest.(check bool) "example sql" true (top.example_sql <> None);
  let no_sql =
    List.find
      (fun (q : R.Summary.query) -> List.mem_assoc "E_TENANT_MISSING" q.codes)
      s.top_denied
  in
  Alcotest.(check (option string)) "no sql logged, none shown" None no_sql.example_sql;
  (* JSON shape *)
  let j = R.Summary.to_json s in
  Alcotest.(check bool)
    "json totals" true
    (Yojson.Safe.Util.(j |> member "totals" |> member "denied" |> to_int) = 3)

(* ----------------------------------------------------------- suggestions *)

let suggest ?pii ?policies recs = R.Suggest.compute (cfg ?pii ?policies ()) recs

let column_rule () =
  let recs =
    List.init 3 (fun i ->
        record ~policy:shadow
          ~caller:(if i = 0 then "bi" else "analytics")
          (Printf.sprintf
             "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT %d" (i + 1)))
  in
  let t = suggest recs in
  check_ids "column" [ "shop-shadow/column/app.orders.region" ] t;
  let s = List.hd t.suggestions in
  Alcotest.(check int) "evidence" 3 s.evidence.records;
  Alcotest.(check int) "shadow" 3 s.evidence.shadow_denied;
  Alcotest.(check string)
    "summary"
    "3 shadow-denied queries by callers analytics, bi read app.orders.region \
     (E_COLUMN_DENIED); add region to tables.app.orders.columns"
    s.summary;
  Alcotest.(check string)
    "yaml"
    "tables:\n\
    \  app.orders:\n\
    \    columns: [id, tenant_id, status, total_cents, created_at, region]\n"
    s.yaml;
  Alcotest.(check bool) "applicable" true s.applicable;
  (* below the threshold *)
  let t = R.Suggest.compute { (cfg ()) with min_records = 4 } recs in
  check_ids "threshold" [] t

let function_rules () =
  let t =
    suggest
      [
        record "SELECT md5(status) FROM app.orders WHERE tenant_id = $1 LIMIT 5";
        record "SELECT pg_sleep(1) FROM app.currencies LIMIT 1";
        record "SELECT set_config('a','b',false) FROM app.currencies LIMIT 1";
        record "SELECT app.f(status) FROM app.orders WHERE tenant_id = $1 LIMIT 5";
        record "SELECT current_user FROM app.currencies LIMIT 1";
        record "SELECT count(*) FROM app.orders WHERE tenant_id = $1 LIMIT 5";
      ]
  in
  check_ids "only md5" [ "shop-enforce/function/md5" ] t;
  let cat target =
    match find_item t target with
    | Some i -> R.Suggest.category_to_string i.category
    | None -> "missing"
  in
  Alcotest.(check string) "pg_sleep unsafe" "unsafe" (cat "pg_sleep()");
  Alcotest.(check string) "set_config unsafe" "unsafe" (cat "set_config()");
  Alcotest.(check string) "user function" "unsafe" (cat "app.f()");
  Alcotest.(check bool)
    "sql value unsafe" true
    (List.exists
       (fun (i : R.Suggest.item) ->
         i.category = R.Suggest.Unsafe
         && i.i_code = "E_FUNCTION_DENIED"
         && String.lowercase_ascii i.target <> "pg_sleep()"
         && String.length i.target > 0
         && i.target.[String.length i.target - 1] <> ')')
       t.not_suggested)

let limit_rules () =
  let t =
    suggest
      [
        record "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 500";
        record "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 300";
      ]
  in
  check_ids "raise" [ "shop-enforce/limit" ] t;
  let s = List.hd t.suggestions in
  Alcotest.(check string) "max observed" "require_limit:\n  max: 500\n" s.yaml;
  Alcotest.(check int) "evidence" 2 s.evidence.records;
  let t =
    suggest [ record "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 5000" ]
  in
  check_ids "too far" [] t;
  Alcotest.(check bool)
    "needs review" true
    (match find_item t "LIMIT 5000" with
    | Some i -> i.category = R.Suggest.Needs_review
    | None -> false);
  let t = suggest [ record "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT $2" ] in
  check_ids "param" [] t;
  Alcotest.(check bool)
    "query fix" true
    (List.exists
       (fun (i : R.Suggest.item) -> i.category = R.Suggest.Query_fix)
       t.not_suggested);
  let t = suggest [ record "SELECT id FROM app.orders WHERE tenant_id = $1" ] in
  check_ids "limit required" [] t;
  Alcotest.(check bool)
    "E_LIMIT_REQUIRED query fix" true
    (List.exists
       (fun (r : R.Suggest.code_row) ->
         r.c_code = "E_LIMIT_REQUIRED" && r.c_category = R.Suggest.Query_fix)
       t.codes)

let table_rules () =
  let t =
    suggest
      [
        record
          "SELECT r.id, r.amount_cents FROM app.refunds r WHERE r.tenant_id = $1 LIMIT 5";
        record "SELECT id, reason FROM refunds WHERE tenant_id = $1 LIMIT 5";
        record "SELECT usename FROM pg_shadow LIMIT 1";
        record "SELECT * FROM pg_catalog.pg_authid LIMIT 1";
        record "SELECT a FROM information_schema.tables LIMIT 1";
      ]
  in
  check_ids "refunds" [ "shop-enforce/table/app.refunds" ] t;
  let s = List.hd t.suggestions in
  Alcotest.(check int) "both spellings" 2 s.evidence.records;
  (match s.change with
  | R.Suggest.Add_table { columns; tenant_columns; _ } ->
      Alcotest.(check (list string))
        "columns"
        [ "tenant_id"; "amount_cents"; "id"; "reason" ]
        columns;
      Alcotest.(check (list (pair string string)))
        "tenant-scoped"
        [ ("tenant_id", "tenant") ]
        tenant_columns
  | _ -> Alcotest.fail "expected add_table");
  Alcotest.(check bool)
    "yaml has tenant_column" true
    (s.yaml
   = "tables:\n\
     \  app.refunds:\n\
     \    columns: [tenant_id, amount_cents, id, reason]\n\
     \    tenant_column: tenant_id\n");
  List.iter
    (fun target ->
      Alcotest.(check bool)
        target true
        (match find_item t target with
        | Some i -> i.category = R.Suggest.Unsafe
        | None -> false))
    [ "pg_shadow"; "pg_catalog.pg_authid"; "information_schema.tables" ];
  (* without SQL the columns are unknown: suggested, but not applicable *)
  let t =
    suggest
      [ record ~with_sql:false "SELECT id FROM app.refunds WHERE tenant_id = $1 LIMIT 5" ]
  in
  Alcotest.(check (list bool))
    "not applicable" [ false ]
    (List.map (fun (s : R.Suggest.suggestion) -> s.applicable) t.suggestions);
  (* a policy without tenancy adds a global table *)
  let global =
    match
      Policy_load.of_string Docload.Yaml
        "apiVersion: haltsql.dev/v1\n\
         kind: Policy\n\
         metadata: {name: g}\n\
         search_path: [app]\n\
         tables:\n\
        \  app.a: {columns: [x]}\n"
    with
    | Ok p -> p
    | Error _ -> Alcotest.fail "global policy"
  in
  let v = Haltsql.verify global Context.empty "SELECT y FROM app.b" in
  let r = R.Record.of_verdict ~ts:t0 ~caller:"c" ~sql:(Some "SELECT y FROM app.b") v in
  let t = R.Suggest.compute (cfg ~policies:[ ("g", global) ] ()) [ r ] in
  (match (List.hd t.suggestions).change with
  | R.Suggest.Add_table { tenant_columns = []; columns = [ "y" ]; _ } -> ()
  | _ -> Alcotest.fail "expected a global table with column y");
  (* 33+ observations where only the 33rd retains SQL still produce an applicable suggestion *)
  let stripped = { r with sql = None } in
  let batch = List.init 32 (fun _ -> stripped) @ [ r ] in
  let t33 = R.Suggest.compute (cfg ~policies:[ ("g", global) ] ()) batch in
  Alcotest.(check (list bool))
    "applicable after 33 observations" [ true ]
    (List.map (fun (s : R.Suggest.suggestion) -> s.applicable) t33.suggestions)

let pii_rules () =
  let manifest ~schema ~table ~column =
    if schema = "app" && table = "orders" && column = "shipping_address" then
      Some "PII (dbt)"
    else None
  in
  let pii = R.Pii.union [ manifest; R.Pii.name_heuristic () ] in
  let t =
    suggest ~pii
      [
        record "SELECT shipping_address FROM app.orders WHERE tenant_id = $1 LIMIT 5";
        record "SELECT email FROM app.customers WHERE tenant_id = $1 LIMIT 5";
        record {|SELECT "customerPhone" FROM app.customers WHERE tenant_id = $1 LIMIT 5|};
        record "SELECT region FROM app.orders WHERE tenant_id = $1 LIMIT 5";
        record "SELECT r.id, r.card_pci FROM app.refunds r WHERE r.tenant_id = $1 LIMIT 5";
      ]
  in
  check_ids "only region and refunds"
    [ "shop-enforce/column/app.orders.region"; "shop-enforce/table/app.refunds" ]
    t;
  let flagged = List.map (fun (i : R.Suggest.item) -> i.target) t.pii_flagged in
  List.iter
    (fun c -> Alcotest.(check bool) c true (List.mem c flagged))
    [
      "app.orders.shipping_address";
      "app.customers.email";
      "app.refunds.card_pci";
      "app.customers.customerPhone" (* camelCase split by the heuristic *);
    ];
  let refunds =
    List.find
      (fun (s : R.Suggest.suggestion) -> s.id = "shop-enforce/table/app.refunds")
      t.suggestions
  in
  (match refunds.change with
  | R.Suggest.Add_table { columns; _ } ->
      Alcotest.(check bool) "pii column left out" false (List.mem "card_pci" columns)
  | _ -> Alcotest.fail "add_table");
  Alcotest.(check (option string))
    "heuristic" (Some "column name matches \"email\"")
    (R.Pii.name_heuristic () ~schema:"a" ~table:"b" ~column:"contact_email");
  Alcotest.(check (option string))
    "heuristic digit split" (Some "column name matches \"email\"")
    (R.Pii.name_heuristic () ~schema:"a" ~table:"b" ~column:"email1");
  Alcotest.(check (option string))
    "heuristic acronym split" (Some "column name matches \"pii\"")
    (R.Pii.name_heuristic () ~schema:"a" ~table:"b" ~column:"PIIData")

let never_weaken () =
  let t =
    suggest
      [
        (* tenancy only *)
        record "SELECT id FROM app.orders LIMIT 5";
        record "SELECT id FROM app.orders WHERE tenant_id = 'other' LIMIT 5";
        record "SELECT id FROM app.orders WHERE tenant_id = $1 OR true LIMIT 5";
        (* writes and statement kinds *)
        record "DELETE FROM app.orders WHERE tenant_id = $1";
        record "UPDATE app.orders SET status = 'x' WHERE tenant_id = $1";
        record "DROP TABLE app.orders";
        (* query fixes *)
        record "SELECT FROM WHERE";
        record "SELECT 1; SELECT 2";
        record "SELECT id FROM app.orders WHERE tenant_id = $1 FOR UPDATE LIMIT 5";
      ]
  in
  check_ids "nothing suggested" [] t;
  let cat c =
    List.find_opt (fun (r : R.Suggest.code_row) -> r.c_code = c) t.codes
    |> Option.map (fun (r : R.Suggest.code_row) ->
        R.Suggest.category_to_string r.c_category)
  in
  Alcotest.(check (option string))
    "tenant missing" (Some "never_weaken") (cat "E_TENANT_MISSING");
  Alcotest.(check (option string))
    "statement kind" (Some "never_weaken") (cat "E_STATEMENT_KIND");
  Alcotest.(check (option string)) "parse" (Some "query_fix") (cat "E_PARSE");
  Alcotest.(check (option string)) "multi" (Some "query_fix") (cat "E_MULTI_STATEMENT");
  Alcotest.(check (option string))
    "locking" (Some "never_weaken") (cat "E_LOCKING_CLAUSE");
  (* the classification is total and puts the named codes where the docs say *)
  List.iter
    (fun c ->
      let k = R.Suggest.classify c in
      let s = Reason.code_to_string c in
      if String.length s > 9 && String.sub s 0 9 = "E_TENANT_" then
        Alcotest.(check bool) s true (k = Some R.Suggest.Never_weaken))
    Reason.all_codes;
  List.iter
    (fun c ->
      Alcotest.(check bool)
        "query fix" true
        (R.Suggest.classify c = Some R.Suggest.Query_fix))
    [ Reason.E_PARAM_UNBOUND; E_UNSUPPORTED; E_PARSE ];
  Alcotest.(check bool)
    "writes" true
    (R.Suggest.classify Reason.E_WRITE_DENIED = Some R.Suggest.Never_weaken);
  (* a record with a column denial AND a tenancy denial: the column may be suggested, but
     the tenancy code is listed as never relaxed *)
  let t = suggest [ record "SELECT region FROM app.orders LIMIT 5" ] in
  check_ids "column only" [ "shop-enforce/column/app.orders.region" ] t;
  Alcotest.(check (option string))
    "tenancy listed" (Some "never_weaken")
    (List.find_opt (fun (r : R.Suggest.code_row) -> r.c_code = "E_TENANT_MISSING") t.codes
    |> Option.map (fun (r : R.Suggest.code_row) ->
        R.Suggest.category_to_string r.c_category))

let other_rules () =
  (* star: query fix; already allowed (older records); missing detail; unknown policy *)
  let star = record "SELECT * FROM app.orders WHERE tenant_id = $1 LIMIT 5" in
  let t = suggest [ star ] in
  check_ids "star" [] t;
  Alcotest.(check bool)
    "star is a query fix" true
    (match find_item t "app.orders.*" with
    | Some i -> i.category = R.Suggest.Query_fix
    | None -> false);
  let old =
    record ~policy:enforce "SELECT region FROM app.orders WHERE tenant_id = $1 LIMIT 5"
  in
  let widened =
    {
      enforce with
      tables =
        List.map
          (fun (tb : Policy.table) ->
            if tb.name = "orders" then { tb with columns = Policy.All } else tb)
          enforce.tables;
    }
  in
  let t = suggest ~policies:[ (enforce.name, widened) ] [ old ] in
  check_ids "already allowed" [] t;
  Alcotest.(check bool)
    "category" true
    (match find_item t "app.orders.region" with
    | Some i -> i.category = R.Suggest.Already_allowed
    | None -> false);
  let bare =
    match
      R.Record.of_line
        {|{"caller":"a","policy":"shop-enforce","allowed":false,"shadow":false,"codes":["E_COLUMN_DENIED"]}|}
    with
    | Ok r -> r
    | Error e -> Alcotest.fail e
  in
  let t = suggest [ bare ] in
  Alcotest.(check int) "missing detail" 1 t.missing_detail;
  let t = suggest ~policies:[] [ old ] in
  Alcotest.(check (list bool))
    "unknown policy: not applicable" [ false ]
    (List.map (fun (s : R.Suggest.suggestion) -> s.applicable) t.suggestions);
  (* details are limited to the codes the record itself carries *)
  let v = Haltsql.verify enforce ctx "SELECT region FROM app.orders LIMIT 5" in
  let only_tenant = { bare with codes = [ "E_TENANT_MISSING" ]; sql = Some "x" } in
  let r = R.Record.with_details only_tenant v in
  Alcotest.(check (list string))
    "filtered" [ "E_TENANT_MISSING" ]
    (List.sort_uniq compare (List.map (fun (d : R.Record.reason) -> d.code) r.details));
  Alcotest.(check (option string))
    "yaml scalar quoting" (Some "\"Event Type\"")
    (Some (R.Suggest.yaml_scalar "Event Type"));
  Alcotest.(check string) "yaml reserved" "\"no\"" (R.Suggest.yaml_scalar "no");
  Alcotest.(check string) "yaml newline" "\"a\\nb\"" (R.Suggest.yaml_scalar "a\nb")

(* ----------------------------------------------------------------- patch *)

let read_doc file =
  match Docload.of_file (fx file) with Ok d -> d | Error _ -> Alcotest.fail "doc"

let denied_queries =
  [
    "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT 10";
    "SELECT md5(status) FROM app.orders WHERE tenant_id = $1 LIMIT 10";
    "SELECT id FROM app.orders WHERE tenant_id = $1 LIMIT 500";
    "SELECT r.id, r.amount_cents FROM app.refunds r WHERE r.tenant_id = $1 LIMIT 10";
  ]

let escapes =
  [
    "SELECT id, region FROM app.orders LIMIT 10";
    "SELECT md5(status) FROM app.orders WHERE tenant_id = 'other' LIMIT 10";
    "SELECT r.id FROM app.refunds r LIMIT 10";
    "SELECT r.id, r.amount_cents FROM app.refunds r WHERE r.tenant_id = $1 OR true LIMIT \
     10";
    "SELECT o.id FROM app.orders o JOIN app.refunds r ON r.id = o.id WHERE o.tenant_id = \
     $1 LIMIT 10";
  ]

let patch_roundtrip file policy () =
  let recs = List.map (record ~policy) (denied_queries @ escapes) in
  let t = suggest recs in
  Alcotest.(check int) "four suggestions" 4 (List.length t.suggestions);
  let doc', o = R.Patch.apply policy (read_doc file) t.suggestions in
  Alcotest.(check int) "applied" 4 (List.length o.applied);
  Alcotest.(check (list (pair string string))) "skipped" [] o.skipped;
  let patched =
    match R.Patch.validate ~file:"patched" ~base_dir:"fixtures" doc' with
    | Ok p -> p
    | Error e ->
        Alcotest.failf "invalid: %s"
          (String.concat "; " (List.map Load_error.to_string e))
  in
  (* the re-serialized text loads back to the same policy *)
  let text = R.Patch.render Docload.Yaml ~applied:o.applied doc' in
  (match Policy_load.of_string ~base_dir:"fixtures" Docload.Yaml text with
  | Ok p -> Alcotest.(check string) "same version" patched.version p.version
  | Error _ -> Alcotest.fail "rendered YAML does not load");
  List.iter
    (fun sql ->
      let v = Haltsql.verify patched ctx sql in
      Alcotest.(check (list string)) ("now allowed: " ^ sql) [] (codes_of v);
      Alcotest.(check bool) "allowed" true v.allowed)
    denied_queries;
  List.iter
    (fun sql ->
      let v = Haltsql.verify patched ctx sql in
      Alcotest.(check bool)
        ("still denied: " ^ sql) true
        (List.exists
           (fun c -> String.length c > 8 && String.sub c 0 8 = "E_TENANT")
           (codes_of v)))
    escapes;
  (* applying again is a no-op *)
  let _, o2 = R.Patch.apply patched doc' t.suggestions in
  Alcotest.(check (list string)) "idempotent" [] o2.applied

(* Regression: ts_rewrite runs its second argument as SQL, so a shadow denial of it must
   never become an applicable suggestion (it escaped the tenancy rules). The other
   functions have side effects or expose server state. *)
let dynamic_sql_function_rules () =
  let fns =
    [
      ( "ts_rewrite",
        "ts_rewrite(to_tsquery('a'), 'SELECT to_tsquery(''a''), to_tsquery(status) FROM \
         app.orders')" );
      ("brin_summarize_new_values", "brin_summarize_new_values('app.orders_brin')");
      ("brin_summarize_range", "brin_summarize_range('app.orders_brin', 0)");
      ("brin_desummarize_range", "brin_desummarize_range('app.orders_brin', 0)");
      ("gin_clean_pending_list", "gin_clean_pending_list('app.orders_gin')");
      ("setseed", "setseed(0.5)");
      ("getpgusername", "getpgusername()");
    ]
  in
  let recs =
    List.map
      (fun (_, call) ->
        record
          (Printf.sprintf
             "SELECT %s AS x FROM app.orders o WHERE o.tenant_id = $1 LIMIT 1" call))
      fns
  in
  let t = suggest recs in
  check_ids "only the safe to_tsquery" [ "shop-enforce/function/to_tsquery" ] t;
  List.iter
    (fun (f, _) ->
      Alcotest.(check string)
        (f ^ " unsafe") "unsafe"
        (match find_item t (f ^ "()") with
        | Some i -> R.Suggest.category_to_string i.category
        | None -> "missing");
      Alcotest.(check bool)
        (f ^ " unsafe_function") true
        (R.Suggest.unsafe_function f <> None))
    fns;
  let doc', o = R.Patch.apply enforce (read_doc "shop-enforce.yaml") t.suggestions in
  Alcotest.(check (list string))
    "--apply-to adds only to_tsquery"
    [ "shop-enforce/function/to_tsquery" ]
    o.applied;
  let text = R.Patch.render Docload.Yaml ~applied:o.applied doc' in
  List.iter
    (fun (f, _) ->
      Alcotest.(check bool)
        (f ^ " not in the patched policy")
        false
        (let n = String.length f in
         let rec go i =
           i + n <= String.length text && (String.sub text i n = f || go (i + 1))
         in
         go 0))
    fns

let patch_misc () =
  let t =
    suggest [ record "SELECT id, region FROM app.orders WHERE tenant_id = $1 LIMIT 10" ]
  in
  (* a JSON document; a suggestion for another policy is skipped *)
  let json_doc =
    match
      Docload.of_string Docload.Json
        (Docload.to_string Docload.Json (read_doc "shop-enforce.yaml"))
    with
    | Ok d -> d
    | Error _ -> Alcotest.fail "json"
  in
  let _, o = R.Patch.apply enforce json_doc t.suggestions in
  Alcotest.(check (list string))
    "json applied"
    [ "shop-enforce/column/app.orders.region" ]
    o.applied;
  let _, o = R.Patch.apply shadow (read_doc "shop-shadow.yaml") t.suggestions in
  Alcotest.(check int) "other policy skipped" 1 (List.length o.skipped);
  Alcotest.(check string)
    "relative" "../catalog/s.json"
    (R.Patch.relative_path ~from_dir:"/a/b/policies" "/a/b/catalog/s.json");
  let doc = `Assoc [ ("catalog", `String "../catalog/s.json") ] in
  Alcotest.(check string)
    "rebased" {|{"catalog":"../../catalog/s.json"}|}
    (Yojson.Safe.to_string
       (R.Patch.rebase_catalog ~from_dir:"/a/b/policies" ~to_dir:"/a/b/out/x" doc))

(* -------------------------------------------------------------- property *)

(* Random queries over the fixture: a table, some columns (some denied, some sensitive),
   maybe a function, a LIMIT, and a tenant predicate that may be missing or broken. *)
let gen_query =
  let open QCheck.Gen in
  let table =
    oneof_list
      [
        ("app.orders", "o");
        ("app.customers", "c");
        ("app.refunds", "r");
        ("app.currencies", "x");
        ("refunds", "r");
      ]
  in
  let col =
    oneof_list
      [ "id"; "status"; "region"; "name"; "email"; "amount_cents"; "code"; "tenant_id" ]
  in
  let fn =
    oneof_list
      [ None; Some "md5"; Some "upper"; Some "pg_sleep"; Some "count"; Some "lower" ]
  in
  let limit =
    oneof_list
      [ ""; " LIMIT 10"; " LIMIT 500"; " LIMIT 5000"; " LIMIT $2"; " LIMIT 1000" ]
  in
  let pred =
    oneof_list
      [
        (fun _ -> "");
        (fun a -> Printf.sprintf " WHERE %s.tenant_id = $1" a);
        (fun a -> Printf.sprintf " WHERE %s.tenant_id = 'other'" a);
        (fun a -> Printf.sprintf " WHERE %s.tenant_id = $1 OR true" a);
        (fun a -> Printf.sprintf " WHERE %s.id = 1" a);
      ]
  in
  let* t, a = table in
  let* cols = list_size (int_range 1 3) col in
  let* f = fn in
  let* l = limit in
  let* p = pred in
  let sel =
    String.concat ", "
      (List.mapi
         (fun i c ->
           match (f, i) with
           | Some f, 0 -> Printf.sprintf "%s(%s.%s)" f a c
           | _ -> a ^ "." ^ c)
         cols)
  in
  let where = p a in
  return (Printf.sprintf "SELECT %s FROM %s %s%s%s" sel t a where l)

let tenancy_code c = String.length c > 8 && String.sub c 0 8 = "E_TENANT"
let applied_total = ref 0
let tenancy_checked = ref 0

let prop_never_weaken =
  QCheck.Test.make ~name:"applying suggestions never turns a tenancy denial into an allow"
    ~count:
      (match Sys.getenv_opt "HALTSQL_QCHECK_COUNT" with
      | Some n -> int_of_string n
      | None -> 150)
    QCheck.(make ~print:(String.concat "\n") Gen.(list_size (int_range 1 25) gen_query))
    (fun queries ->
      List.for_all
        (fun policy ->
          let recs = List.map (record ~policy) queries in
          let t = suggest ~pii:R.Pii.none recs in
          let file =
            if policy == shadow then "shop-shadow.yaml" else "shop-enforce.yaml"
          in
          let doc', o = R.Patch.apply policy (read_doc file) t.suggestions in
          applied_total := !applied_total + List.length o.applied;
          match R.Patch.validate ~base_dir:"fixtures" doc' with
          | Error e ->
              QCheck.Test.fail_reportf "patched policy invalid: %s"
                (String.concat "; " (List.map Load_error.to_string e))
          | Ok patched ->
              List.for_all
                (fun sql ->
                  let before = Haltsql.verify policy ctx sql in
                  let after = Haltsql.verify patched ctx sql in
                  let enforce_after =
                    Haltsql.verify { patched with mode = Policy.Enforce } ctx sql
                  in
                  if List.exists tenancy_code (codes_of before) then (
                    incr tenancy_checked;
                    List.exists tenancy_code (codes_of after)
                    && not enforce_after.allowed
                    || QCheck.Test.fail_reportf "tenancy weakened for %s" sql)
                  else true)
                queries)
        [ enforce; shadow ])

let () =
  let seed =
    match Sys.getenv_opt "HALTSQL_QCHECK_SEED" with
    | Some s -> int_of_string s
    | None -> 4242
  in
  Alcotest.run "report"
    [
      ("time", [ Alcotest.test_case "rfc3339 and bounds" `Quick time ]);
      ("records", [ Alcotest.test_case "server and proxy formats" `Quick records_parse ]);
      ("findings", [ Alcotest.test_case "every rule, real verifier" `Quick findings ]);
      ("summary", [ Alcotest.test_case "counts, breakdowns, buckets, top" `Quick summary ]);
      ( "suggest",
        [
          Alcotest.test_case "columns" `Quick column_rule;
          Alcotest.test_case "functions" `Quick function_rules;
          Alcotest.test_case "dynamic-SQL and side-effect functions" `Quick
            dynamic_sql_function_rules;
          Alcotest.test_case "limits" `Quick limit_rules;
          Alcotest.test_case "tables" `Quick table_rules;
          Alcotest.test_case "pii flagged" `Quick pii_rules;
          Alcotest.test_case "never weaken tenancy or writes" `Quick never_weaken;
          Alcotest.test_case "star, stale, missing detail" `Quick other_rules;
        ] );
      ( "patch",
        [
          Alcotest.test_case "enforce: allows denied, still denies escapes" `Quick
            (patch_roundtrip "shop-enforce.yaml" enforce);
          Alcotest.test_case "shadow: allows denied, still denies escapes" `Quick
            (patch_roundtrip "shop-shadow.yaml" shadow);
          Alcotest.test_case "json, other policy, catalog paths" `Quick patch_misc;
        ] );
      ( "property",
        [
          QCheck_alcotest.to_alcotest
            ~rand:(Random.State.make [| seed |])
            prop_never_weaken;
          Alcotest.test_case "the property exercised patches and tenancy denials" `Quick
            (fun () ->
              Alcotest.(check bool) "suggestions applied" true (!applied_total > 50);
              Alcotest.(check bool) "tenancy denials checked" true (!tenancy_checked > 100));
        ] );
    ]
