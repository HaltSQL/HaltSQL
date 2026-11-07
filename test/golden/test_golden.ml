(* Golden verdict JSON snapshots for representative queries.

   Each case's verdict (Verdict.to_json minus [elapsed_us]) is compared with
   test/golden/expected/<name>.json. Set HALTSQL_GOLDEN_UPDATE=1 to rewrite the
   snapshots in the source tree (found through DUNE_SOURCEROOT, or
   HALTSQL_GOLDEN_DIR). *)

open Haltsql

let fixtures = Option.value (Sys.getenv_opt "HALTSQL_FIXTURES") ~default:"../fixtures"

type case = {
  name : string;
  policy : string;
  context : (string * Context.value) list;
  sql : string;
}

let acme = [ ("tenant_id", Context.One "acme") ]
let c ?(policy = "saas") ?(context = acme) name sql = { name; policy; context; sql }

let cases =
  [
    c "allow_simple_bound" "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 10";
    c "allow_join_report"
      "SELECT c.name, count(*) AS n, sum(o.total_cents) AS revenue FROM orders o JOIN \
       customers c ON c.id = o.customer_id AND c.tenant_id = $1 WHERE o.tenant_id = $1 \
       GROUP BY c.name ORDER BY revenue DESC LIMIT 20";
    c "allow_global_only" "SELECT code, symbol FROM currencies ORDER BY code LIMIT 50";
    c "allow_cte_window"
      "WITH m AS (SELECT date_trunc('month', created_at) AS month, sum(total_cents) AS \
       rev FROM orders WHERE tenant_id = $1 GROUP BY 1) SELECT month, rev, lag(rev) OVER \
       (ORDER BY month) AS prev FROM m ORDER BY month LIMIT 24";
    c "deny_tenant_missing" "SELECT id FROM orders LIMIT 10";
    c "deny_or_tautology" "SELECT id FROM orders WHERE tenant_id = $1 OR 1 = 1 LIMIT 10";
    c "deny_union_branch_unfiltered"
      "SELECT id FROM orders WHERE tenant_id = $1 UNION ALL SELECT id FROM orders LIMIT \
       10";
    c "deny_outer_predicate_only"
      "SELECT s.id FROM (SELECT id, tenant_id FROM orders) s WHERE s.tenant_id = $1 \
       LIMIT 10";
    c "deny_pii_column" "SELECT name, email FROM customers WHERE tenant_id = $1 LIMIT 10";
    c "deny_star_pii" "SELECT * FROM customers WHERE tenant_id = $1 LIMIT 10";
    c "deny_whole_row"
      "SELECT row_to_json(c) FROM customers c WHERE c.tenant_id = $1 LIMIT 10";
    c "deny_table_not_in_policy"
      "SELECT secret FROM api_keys WHERE tenant_id = $1 LIMIT 10";
    c "deny_system_catalog" "SELECT tablename FROM pg_catalog.pg_tables LIMIT 10";
    c "deny_pg_sleep" "SELECT pg_sleep(10) FROM orders WHERE tenant_id = $1 LIMIT 1";
    c "deny_regclass_cast" "SELECT 'app.api_keys'::regclass LIMIT 1";
    c "deny_multi_statement" "SELECT 1 LIMIT 1; DROP TABLE app.orders";
    c "deny_statement_kind" "DROP TABLE app.orders";
    c "deny_data_modifying_cte"
      "WITH d AS (DELETE FROM orders WHERE tenant_id = $1 RETURNING id) SELECT id FROM d \
       LIMIT 10";
    c "deny_limit_required" "SELECT id FROM orders WHERE tenant_id = $1";
    c "deny_limit_too_high" "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5000";
    c "deny_for_update" "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 1 FOR UPDATE";
    c "deny_parse_error" "SELEC id FROM orders";
    c "deny_param_unbound"
      "SELECT id FROM orders WHERE tenant_id = $1 AND id = $2 LIMIT 10";
    c "deny_context_missing" ~context:[]
      "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10";
    c "literal_mismatch" ~policy:"saas_literal"
      "SELECT id FROM orders WHERE tenant_id = 'globex' LIMIT 10";
    c "literal_allow" ~policy:"saas_literal"
      "SELECT id FROM orders WHERE tenant_id = 'acme' LIMIT 10";
    c "composite_allow" ~policy:"composite"
      ~context:[ ("org_id", Context.One "o1"); ("workspace_id", Context.One "w1") ]
      "SELECT id, name FROM projects WHERE org_id = $1 AND workspace_id = $2 LIMIT 10";
    c "sets_allow" ~policy:"hierarchical"
      ~context:[ ("tenant_ids", Context.Many [ "acme"; "acme-eu"; "acme-us" ]) ]
      "SELECT id, name FROM accounts WHERE tenant_id = ANY($1) LIMIT 10";
    c "shadow_would_deny" ~policy:"shadow" "SELECT id FROM orders LIMIT 10";
    c "writes_update_allow" ~policy:"writes"
      "UPDATE tickets SET status = 'closed' WHERE tenant_id = $1 AND id = 42";
    c "writes_tenant_write" ~policy:"writes"
      "UPDATE tickets SET tenant_id = 'globex' WHERE tenant_id = $1 AND id = 42";
  ]

let policies = Hashtbl.create 8

let policy name =
  match Hashtbl.find_opt policies name with
  | Some p -> p
  | None ->
      let file = Filename.concat fixtures ("policies/" ^ name ^ ".yaml") in
      let p =
        match Policy_load.of_file file with
        | Ok p -> p
        | Error es ->
            failwith (String.concat "\n" (file :: List.map Load_error.to_string es))
      in
      Hashtbl.add policies name p;
      p

let render (c : case) =
  let v = Haltsql.verify (policy c.policy) (Context.make c.context) c.sql in
  let j =
    match Verdict.to_json v with
    | `Assoc kvs -> `Assoc (("sql", `String c.sql) :: List.remove_assoc "elapsed_us" kvs)
    | j -> j
  in
  Yojson.Safe.pretty_to_string j ^ "\n"

let read_file f =
  match open_in_bin f with
  | exception Sys_error _ -> None
  | ic ->
      let s = really_input_string ic (in_channel_length ic) in
      close_in ic;
      Some s

let update = Sys.getenv_opt "HALTSQL_GOLDEN_UPDATE" = Some "1"

let source_dir () =
  match Sys.getenv_opt "HALTSQL_GOLDEN_DIR" with
  | Some d -> d
  | None -> (
      match Sys.getenv_opt "DUNE_SOURCEROOT" with
      | Some r -> Filename.concat r "test/golden/expected"
      | None -> "expected")

let check (c : case) () =
  let actual = render c in
  if update then begin
    let f = Filename.concat (source_dir ()) (c.name ^ ".json") in
    let oc = open_out_bin f in
    output_string oc actual;
    close_out oc;
    Printf.printf "updated %s\n" f
  end
  else
    match read_file (Filename.concat "expected" (c.name ^ ".json")) with
    | None ->
        Alcotest.failf
          "missing snapshot expected/%s.json; run with HALTSQL_GOLDEN_UPDATE=1.\n\
           actual:\n\
           %s"
          c.name actual
    | Some expected ->
        if expected <> actual then
          Alcotest.failf "verdict changed for %s\n--- expected\n%s+++ actual\n%s" c.name
            expected actual

let () =
  Alcotest.run "haltsql-golden"
    [ ("verdicts", List.map (fun c -> Alcotest.test_case c.name `Quick (check c)) cases) ]
