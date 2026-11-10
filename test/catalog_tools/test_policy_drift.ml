(* Policy_drift.check: each finding code, and the clean case, on hand-built snapshots. *)

open Haltsql_core
module Ct = Haltsql_catalog_tools
module Snap = Ct.Snapshot
module Drift = Ct.Policy_drift

let col ?(ty = "text") n = { Catalog.col_name = n; col_type = Some ty }
let table schema name cols = { Catalog.schema; name; columns = List.map col cols }

let snapshot ?(schemas = [ "app"; "public" ]) ?(kinds = []) tables : Snap.t =
  {
    Snap.catalog = { Catalog.tables };
    relkinds =
      List.map
        (fun (t : Catalog.table) ->
          ( (t.schema, t.name),
            Option.value (List.assoc_opt (t.schema, t.name) kinds) ~default:Snap.Table ))
        tables;
    database = Some "app";
    server_version = Some "17.0";
    schemas;
    authoritative = true;
  }

let orders = table "app" "orders" [ "id"; "tenant_id"; "status"; "secret" ]
let customers = table "app" "customers" [ "id"; "tenant_id"; "name" ]

(* The policy carries its own catalog (as [catalog:] would give it): orders with four
   columns, customers with three. *)
let policy ?(search_path = "[app]") ?(with_catalog = true) () =
  let yaml =
    Printf.sprintf
      {|apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: drift }
search_path: %s
tenancy: { mode: bound, keys: { tenant: "${ctx.tenant_id}" } }
tables:
  app.orders:
    columns: [id, tenant_id, status]
    tenant_column: tenant_id
  app.customers:
    columns: [id, tenant_id, name]
    tenant_column: tenant_id
|}
      search_path
  in
  match Haltsql_load.Policy_load.of_string Haltsql_load.Docload.Yaml yaml with
  | Error _ -> Alcotest.fail "test policy does not load"
  | Ok p ->
      if with_catalog then
        { p with Policy.catalog = { Catalog.tables = [ orders; customers ] } }
      else p

let contains s sub =
  let n = String.length sub in
  let rec go i = i + n <= String.length s && (String.sub s i n = sub || go (i + 1)) in
  go 0

let codes fs = List.map (fun (f : Drift.finding) -> (f.code, f.table)) fs
let pairs = Alcotest.(list (pair string (option string)))

let clean () =
  Alcotest.check pairs "no findings" []
    (codes (Drift.check (policy ()) (snapshot [ orders; customers ])))

let table_missing () =
  Alcotest.check pairs "missing table"
    [ ("E_DRIFT_TABLE_MISSING", Some "app.customers") ]
    (codes (Drift.check (policy ()) (snapshot [ orders ])))

let column_missing () =
  let live = table "app" "orders" [ "id"; "tenant_id"; "secret" ] in
  Alcotest.check pairs "allowed column gone: missing and stale"
    [
      ("E_DRIFT_CATALOG_STALE", Some "app.orders");
      ("E_DRIFT_COLUMN_MISSING", Some "app.orders");
    ]
    (codes (Drift.check (policy ()) (snapshot [ live; customers ])));
  let no_tenant = table "app" "customers" [ "id"; "name" ] in
  Alcotest.(check bool)
    "tenant column gone is reported" true
    (List.mem
       ("E_DRIFT_COLUMN_MISSING", Some "app.customers")
       (codes (Drift.check (policy ()) (snapshot [ orders; no_tenant ]))))

(* The case that matters most: the database gained a column the policy does not allow.
   With the stale catalog the analyzer would let SELECT * read it. *)
let catalog_stale () =
  let live = table "app" "customers" [ "id"; "tenant_id"; "name"; "ssn" ] in
  let fs = Drift.check (policy ()) (snapshot [ orders; live ]) in
  Alcotest.check pairs "new column"
    [ ("E_DRIFT_CATALOG_STALE", Some "app.customers") ]
    (codes fs);
  let msg = (List.hd fs).message in
  Alcotest.(check bool)
    "names the new column" true
    (contains msg "new in the database: ssn")

let no_catalog () =
  Alcotest.check pairs "warn per table"
    [
      ("W_DRIFT_NO_CATALOG", Some "app.customers");
      ("W_DRIFT_NO_CATALOG", Some "app.orders");
    ]
    (codes (Drift.check (policy ~with_catalog:false ()) (snapshot [ orders; customers ])))

let shadowed () =
  let decoy = table "public" "orders" [ "id" ] in
  let live = snapshot [ orders; customers; decoy ] in
  Alcotest.check pairs "earlier schema captures the name"
    [ ("E_DRIFT_SHADOWED", Some "app.orders") ]
    (codes (Drift.check (policy ~search_path:"[public, app]" ()) live));
  Alcotest.check pairs "a later schema does not" []
    (codes (Drift.check (policy ~search_path:"[app, public]" ()) live));
  Alcotest.check pairs "nor a schema outside search_path" []
    (codes (Drift.check (policy ~search_path:"[app]" ()) live))

let views () =
  let kinds = [ (("app", "customers"), Snap.View) ] in
  Alcotest.check pairs "view is opaque"
    [ ("W_DRIFT_VIEW", Some "app.customers") ]
    (codes (Drift.check (policy ()) (snapshot ~kinds [ orders; customers ])));
  let kinds = [ (("app", "orders"), Snap.Partitioned_table) ] in
  Alcotest.check pairs "a partitioned table is a table" []
    (codes (Drift.check (policy ()) (snapshot ~kinds [ orders; customers ])))

let schema_not_pulled () =
  Alcotest.check pairs "not checked is said, not passed silently"
    [
      ("W_DRIFT_SCHEMA_NOT_PULLED", Some "app.customers");
      ("W_DRIFT_SCHEMA_NOT_PULLED", Some "app.orders");
    ]
    (codes (Drift.check (policy ()) (snapshot ~schemas:[ "billing" ] [])))

let errors_first () =
  let kinds = [ (("app", "customers"), Snap.View) ] in
  let fs = Drift.check (policy ()) (snapshot ~kinds [ customers ]) in
  Alcotest.(check (list string))
    "errors before warnings" [ "error"; "warning" ]
    (List.map (fun (f : Drift.finding) -> Drift.severity_to_string f.severity) fs)

let () =
  let tc n f = Alcotest.test_case n `Quick f in
  Alcotest.run "policy_drift"
    [
      ( "check",
        [
          tc "clean" clean;
          tc "table missing" table_missing;
          tc "column missing" column_missing;
          tc "catalog stale" catalog_stale;
          tc "no catalog" no_catalog;
          tc "shadowed" shadowed;
          tc "views" views;
          tc "schema not pulled" schema_not_pulled;
          tc "errors first" errors_first;
        ] );
    ]
