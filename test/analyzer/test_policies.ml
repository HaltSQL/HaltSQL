(* End-to-end: real example policies (YAML/JSON via Policy_load) + SQL strings. *)

open Haltsql_core
open Reason
module A = Haltsql_analyzer.Analyzer
module P = Haltsql_parse.Pg_parse
module L = Haltsql_load.Policy_load

let root = "../../examples/policies/"

let load name =
  match L.of_file (root ^ name) with
  | Ok p -> p
  | Error es ->
      Alcotest.failf "cannot load %s: %s" name
        (String.concat "; " (List.map (fun (e : Load_error.t) -> e.message) es))

let t file ?(ctx = Context.make [ ("tenant_id", Context.One "acme") ]) ?binds name sql
    expect =
  Alcotest.test_case
    (file ^ ": " ^ name)
    `Quick
    (fun () ->
      let policy = load file in
      match P.parse ~limits:policy.limits sql with
      | Error r -> Alcotest.failf "parse error: %s" r.message
      | Ok [ stmt ] -> Helpers.check_analysis ?binds ~expect (A.analyze policy ctx stmt)
      | Ok _ -> Alcotest.fail "expected one statement")

let acme = [ (1, Context.One "acme") ]
let ws = Context.make [ ("org_id", Context.One "o1"); ("workspace_id", Context.One "w1") ]
let orgs = Context.make [ ("org_ids", Context.Many [ "acme"; "acme-eu" ]) ]

let cases =
  [
    t "saas.yaml" "basic" "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 10" []
      ~binds:acme;
    t "saas.json" "basic (json twin)"
      "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 10" [] ~binds:acme;
    t "saas.yaml" "star leaks internal_notes"
      "SELECT * FROM orders WHERE tenant_id = $1 LIMIT 10" [ E_COLUMN_DENIED ];
    t "saas.yaml" "hidden column"
      "SELECT internal_notes FROM orders WHERE tenant_id = $1 LIMIT 10"
      [ E_COLUMN_DENIED ];
    t "saas.yaml" "email" "SELECT email FROM customers WHERE tenant_id = $1 LIMIT 10"
      [ E_COLUMN_DENIED ];
    t "saas.yaml" "limit required" "SELECT id FROM orders WHERE tenant_id = $1"
      [ E_LIMIT_REQUIRED ];
    t "saas.yaml" "limit too high" "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5000"
      [ E_LIMIT_TOO_HIGH ];
    t "saas.yaml" "pg_sleep" "SELECT pg_sleep(1) LIMIT 1" [ E_FUNCTION_DENIED ];
    t "saas.yaml" "regclass" "SELECT 'app.orders'::regclass LIMIT 1" [ E_CAST_DENIED ];
    t "saas.yaml" "pg_catalog" "SELECT relname FROM pg_class LIMIT 1" [ E_TABLE_DENIED ];
    t "saas.yaml" "currencies star" "SELECT * FROM currencies LIMIT 5" [];
    t "saas.yaml" "join tenancy"
      "SELECT c.name, sum(o.total_cents) AS t FROM orders o JOIN customers c ON c.id = \
       o.customer_id AND c.tenant_id = $1 WHERE o.tenant_id = $1 GROUP BY c.name ORDER \
       BY t DESC LIMIT 20"
      [] ~binds:acme;
    t "saas.yaml" "union bypass"
      "SELECT id FROM orders WHERE tenant_id = $1 UNION SELECT id FROM invoices LIMIT 10"
      [ E_TENANT_MISSING ];
    t "saas.yaml" "delete denied" "DELETE FROM orders WHERE tenant_id = $1"
      [ E_STATEMENT_KIND; E_WRITE_DENIED ];
    t "composite.yaml" ~ctx:ws "both keys"
      "SELECT id, title FROM documents WHERE org_id = $1 AND workspace_id = $2 LIMIT 10"
      []
      ~binds:[ (1, Context.One "o1"); (2, Context.One "w1") ];
    t "composite.yaml" ~ctx:ws "one key missing"
      "SELECT id FROM documents WHERE org_id = $1 LIMIT 10" [ E_TENANT_MISSING ];
    t "composite.yaml" ~ctx:ws "org-level table"
      "SELECT display_name FROM members WHERE org_id = $1 LIMIT 10" []
      ~binds:[ (1, Context.One "o1") ];
    t "composite.yaml" "context missing"
      "SELECT id FROM members WHERE org_id = $1 LIMIT 10"
      [ E_CONTEXT_MISSING; E_PARAM_UNBOUND ];
    t "hierarchical.yaml" ~ctx:orgs "any"
      "SELECT day, revenue_cents FROM revenue_daily WHERE org_id = ANY ($1) LIMIT 100" []
      ~binds:[ (1, Context.Many [ "acme"; "acme-eu" ]) ];
    t "hierarchical.yaml" ~ctx:orgs "equals with set"
      "SELECT day FROM revenue_daily WHERE org_id = $1 LIMIT 100"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "hierarchical.yaml" ~ctx:orgs "second search_path schema needs qualification"
      "SELECT name FROM organizations WHERE id = ANY ($1) LIMIT 10"
      [ E_TABLE_DENIED; E_PARAM_UNBOUND ];
    t "hierarchical.yaml" ~ctx:orgs "qualified second schema"
      "SELECT name FROM public.organizations WHERE id = ANY ($1) LIMIT 10" []
      ~binds:[ (1, Context.Many [ "acme"; "acme-eu" ]) ];
    t "writes.yaml" "insert"
      "INSERT INTO tickets (tenant_id, subject) VALUES ($1, 'help')" [] ~binds:acme;
    t "writes.yaml" "insert default non-tenant"
      "INSERT INTO tickets (tenant_id, subject, status) VALUES ($1, 'help', DEFAULT)" []
      ~binds:acme;
    t "writes.yaml" "insert default tenant"
      "INSERT INTO tickets (tenant_id, subject) VALUES (DEFAULT, 'help')"
      [ E_TENANT_WRITE ];
    t "writes.yaml" "update allowed col"
      "UPDATE tickets SET status = 'closed' WHERE tenant_id = $1 AND id = 3" []
      ~binds:acme;
    t "writes.yaml" "update subject denied"
      "UPDATE tickets SET subject = 'x' WHERE tenant_id = $1" [ E_WRITE_DENIED ];
    t "writes.yaml" "update tenant"
      "UPDATE tickets SET tenant_id = 'evil' WHERE tenant_id = $1"
      [ E_WRITE_DENIED; E_TENANT_WRITE ];
    t "writes.yaml" "delete tickets denied" "DELETE FROM tickets WHERE tenant_id = $1"
      [ E_WRITE_DENIED ];
    t "writes.yaml" "delete drafts"
      "DELETE FROM ticket_drafts WHERE tenant_id = $1 AND id = 9" [] ~binds:acme;
    t "writes.yaml" "delete drafts unfiltered" "DELETE FROM ticket_drafts WHERE id = 9"
      [ E_TENANT_MISSING ];
    t "writes.yaml" "update set default"
      "UPDATE tickets SET status = DEFAULT WHERE tenant_id = $1" [ E_UNSUPPORTED ];
  ]

let suites = [ ("policies.examples", cases) ]
