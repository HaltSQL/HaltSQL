open Haltsql_core
open Haltsql_load
open Helpers

let catalog_cases =
  [
    tc "catalog strings and objects" (fun () ->
        let c =
          get_ok
            (Catalog_load.of_json
               (get_ok (yaml "tables:\n  app.t: {columns: [a, {name: b, type: text}]}\n")))
        in
        let t = Option.get (Catalog.find c ~schema:"app" ~name:"t") in
        Alcotest.(check (list string)) "cols" [ "a"; "b" ] (Catalog.column_names t));
    tc "catalog keeps case" (fun () ->
        let c =
          get_ok
            (Catalog_load.of_json
               (get_ok (yaml "tables:\n  App.Orders: {columns: [Id]}\n")))
        in
        ignore (Option.get (Catalog.find c ~schema:"App" ~name:"Orders")));
    tc "catalog wrapper keys" (fun () ->
        ignore
          (get_ok
             (Catalog_load.of_json
                (get_ok
                   (yaml
                      "apiVersion: haltsql.dev/v1\n\
                       kind: Catalog\n\
                       metadata: {x: 1}\n\
                       tables: {}\n")))));
    tc "catalog round trips Catalog.to_json" (fun () ->
        let c = get_ok (Catalog_load.of_file (ex "catalog/saas.snapshot.json")) in
        let c' = get_ok (Catalog_load.of_json (Catalog.to_json c)) in
        Alcotest.(check bool) "eq" true (c = c'));
    tc "catalog wrong kind" (fun () ->
        check_err ~path:"kind" ~msg:"expected kind"
          (Catalog_load.of_json
             (`Assoc [ ("kind", `String "Policy"); ("tables", `Assoc []) ])));
    tc "catalog unqualified table" (fun () ->
        check_err ~path:"tables.t" ~msg:"schema.table"
          (Catalog_load.of_json (get_ok (yaml "tables: {t: {columns: [a]}}"))));
    tc "catalog duplicate column" (fun () ->
        check_err ~path:"tables.\"s.t\".columns[1]" ~msg:"duplicate column"
          (Catalog_load.of_json (get_ok (yaml "tables: {s.t: {columns: [a, a]}}"))));
    tc "catalog missing tables" (fun () ->
        check_err ~path:"tables" ~msg:"required" (Catalog_load.of_json (`Assoc [])));
    tc "catalog bad column" (fun () ->
        check_err ~msg:"expected a column name"
          (Catalog_load.of_json (get_ok (yaml "tables: {s.t: {columns: [1]}}"))));
    tc "catalog unknown key" (fun () ->
        check_err ~path:"tabels" ~msg:"unknown key"
          (Catalog_load.of_json (get_ok (yaml "tabels: {}"))));
  ]

let suite_yaml =
  {|apiVersion: haltsql.dev/v1
kind: TestSuite
metadata: {name: s}
policy: ../p.yaml
defaults:
  context: {tenant_id: acme, org_ids: [a, b], n: 7}
cases:
  - name: one
    sql: SELECT 1
    expect: allow
    bind: [{param: 1, value: acme}, {param: 2, value: [x, 3]}]
  - name: two
    sql: SELECT 2
    expect: deny
    context: {tenant_id: globex}
    codes: [E_TENANT_MISSING, E_LIMIT]
    tags: [a, b]
|}

let suite s =
  match yaml s with Ok j -> Test_suite.of_json ~base_dir:"/x/y" j | Error e -> Error e

let suite_cases =
  [
    tc "suite loads" (fun () ->
        let t = get_ok (suite suite_yaml) in
        Alcotest.(check string) "name" "s" t.suite_name;
        Alcotest.(check string) "policy path" "/x/p.yaml" t.policy_path;
        Alcotest.(check int) "cases" 2 (List.length t.cases));
    tc "suite defaults context" (fun () ->
        let c = List.hd (get_ok (suite suite_yaml)).cases in
        Alcotest.(check bool)
          "tenant" true
          (Context.find c.context "tenant_id" = Some (Context.One "acme"));
        Alcotest.(check bool)
          "set" true
          (Context.find c.context "org_ids" = Some (Context.Many [ "a"; "b" ]));
        Alcotest.(check bool)
          "int" true
          (Context.find c.context "n" = Some (Context.One "7")));
    tc "suite case context replaces defaults" (fun () ->
        let c = List.nth (get_ok (suite suite_yaml)).cases 1 in
        Alcotest.(check bool)
          "tenant" true
          (Context.find c.context "tenant_id" = Some (Context.One "globex"));
        Alcotest.(check bool) "no org_ids" true (Context.find c.context "org_ids" = None));
    tc "suite codes, tags, bind" (fun () ->
        let t = get_ok (suite suite_yaml) in
        let c1 = List.hd t.cases and c2 = List.nth t.cases 1 in
        Alcotest.(check bool)
          "codes" true
          (c2.codes = [ Reason.E_TENANT_MISSING; Reason.E_LIMIT ]);
        Alcotest.(check (list string)) "tags" [ "a"; "b" ] c2.tags;
        Alcotest.(check bool)
          "bind" true
          (c1.bind = Some [ (1, Context.One "acme"); (2, Context.Many [ "x"; "3" ]) ]);
        Alcotest.(check bool) "no bind" true (c2.bind = None);
        Alcotest.(check bool)
          "expect" true
          (c1.expect = Test_suite.Allow && c2.expect = Test_suite.Deny));
    tc "suite unknown code" (fun () ->
        check_err ~path:"cases[1].codes[0]" ~msg:"unknown reason code"
          (suite (Str_replace.replace suite_yaml "E_TENANT_MISSING" "E_NOPE")));
    tc "suite bad expect" (fun () ->
        check_err ~path:"cases[0].expect" ~msg:"invalid value"
          (suite (Str_replace.replace suite_yaml "expect: allow" "expect: maybe")));
    tc "suite codes with allow" (fun () ->
        check_err ~path:"cases[0].codes" ~msg:"only be given when expect is deny"
          (suite
             (Str_replace.replace suite_yaml "expect: allow"
                "expect: allow\n    codes: [E_PARSE]")));
    tc "suite duplicate case names" (fun () ->
        check_err ~path:"cases[1]" ~msg:"duplicate case name"
          (suite (Str_replace.replace suite_yaml "name: two" "name: one")));
    tc "suite missing sql" (fun () ->
        check_err ~path:"cases[0].sql" ~msg:"required"
          (suite (Str_replace.replace suite_yaml "sql: SELECT 1" "tags: []")));
    tc "suite bad context" (fun () ->
        check_err ~path:"cases[1].context" ~msg:"context values"
          (suite
             (Str_replace.replace suite_yaml "{tenant_id: globex}" "{tenant_id: {x: 1}}")));
    tc "suite empty cases" (fun () ->
        check_err ~path:"cases" ~msg:"at least one case"
          (suite
             "apiVersion: haltsql.dev/v1\n\
              kind: TestSuite\n\
              metadata: {name: s}\n\
              policy: p.yaml\n\
              cases: []\n"));
    tc "suite example loads" (fun () ->
        let t = get_ok (Test_suite.of_file (ex "suites/saas.suite.yaml")) in
        Alcotest.(check bool) "abs" false (Filename.is_relative t.policy_path);
        Alcotest.(check bool) "policy exists" true (Sys.file_exists t.policy_path);
        ignore (get_ok (Policy_load.of_file t.policy_path)));
  ]

let schema_cases =
  [
    tc "schemas up to date on disk" (fun () ->
        List.iter
          (fun (name, schema) ->
            let path = Filename.concat (Filename.concat root "schemas") name in
            let expected = Yojson.Safe.pretty_to_string schema ^ "\n" in
            let actual =
              try In_channel.with_open_bin path In_channel.input_all
              with Sys_error _ -> Alcotest.failf "%s missing; run gen_schemas" path
            in
            if actual <> expected then
              Alcotest.failf
                "%s is stale; regenerate with: dune exec --build-dir _build_load \
                 test/load/gen_schemas.exe -- schemas/"
                path)
          Schemas.all);
    tc "schemas declare draft 2020-12 and ids" (fun () ->
        List.iter
          (fun (name, s) ->
            let open Yojson.Safe.Util in
            Alcotest.(check string)
              name "https://json-schema.org/draft/2020-12/schema"
              (to_string (member "$schema" s));
            Alcotest.(check bool) "id" true (contains (to_string (member "$id" s)) name))
          Schemas.all);
    tc "every property has a description" (fun () ->
        let rec walk path (j : Yojson.Safe.t) =
          match j with
          | `Assoc kvs ->
              (match List.assoc_opt "properties" kvs with
              | Some (`Assoc props) ->
                  List.iter
                    (fun (k, v) ->
                      match v with
                      | `Assoc pk when List.mem_assoc "description" pk -> ()
                      | _ -> Alcotest.failf "%s.%s has no description" path k)
                    props
              | _ -> ());
              List.iter (fun (k, v) -> walk (path ^ "." ^ k) v) kvs
          | `List l -> List.iter (walk path) l
          | _ -> ()
        in
        List.iter (fun (n, s) -> walk n s) Schemas.all);
    tc "policy schema lists all top-level keys" (fun () ->
        let open Yojson.Safe.Util in
        let props = keys (member "properties" Schemas.policy) in
        List.iter
          (fun k -> Alcotest.(check bool) k true (List.mem k props))
          [
            "apiVersion";
            "kind";
            "metadata";
            "dialect";
            "search_path";
            "catalog";
            "limits";
            "statements";
            "require_limit";
            "tenancy";
            "tables";
            "functions";
            "operators";
            "deny_casts";
            "allow_explain";
            "mode";
          ]);
    tc "policy schema presets match loader" (fun () ->
        let s = Yojson.Safe.to_string Schemas.policy in
        List.iter
          (fun (n, _) -> Alcotest.(check bool) n true (contains s ("\"" ^ n ^ "\"")))
          Policy_load.function_presets);
    tc "config and scenario schemas" (fun () ->
        let open Yojson.Safe.Util in
        Alcotest.(check bool)
          "config server" true
          (List.mem "server" (keys (member "properties" Schemas.config)));
        Alcotest.(check bool)
          "scenario workloads" true
          (List.mem "workloads" (keys (member "properties" Schemas.scenario)));
        Alcotest.(check bool)
          "catalog tables" true
          (List.mem "tables" (keys (member "properties" Schemas.catalog))));
  ]

let all_examples_cases =
  [
    tc "every example loads" (fun () ->
        let rec files dir =
          Array.to_list (Sys.readdir dir)
          |> List.concat_map (fun f ->
              let p = Filename.concat dir f in
              if Sys.is_directory p then files p else [ p ])
        in
        let all = files examples in
        Alcotest.(check bool) "found" true (List.length all >= 10);
        List.iter
          (fun f ->
            let j = get_ok (Docload.of_file f) in
            let kind =
              match j with `Assoc kvs -> List.assoc_opt "kind" kvs | _ -> None
            in
            match kind with
            | Some (`String "Policy") -> ignore (get_ok (Policy_load.of_file f))
            | Some (`String "Config") ->
                ignore
                  (get_ok
                     (Config.of_file
                        ~env:(fun n ->
                          if n = "HALTSQL_ANALYTICS_TOKEN_HASH" then
                            Some (String.make 64 'c')
                          else if n = "OTEL_EXPORTER_OTLP_ENDPOINT" then Some "x"
                          else None)
                        f))
            | Some (`String "Catalog") -> ignore (get_ok (Catalog_load.of_file f))
            | Some (`String "TestSuite") -> ignore (get_ok (Test_suite.of_file f))
            | _ -> Alcotest.failf "example %s has no known kind" f)
          all);
  ]

let tests =
  [
    ("catalog", catalog_cases);
    ("test-suite", suite_cases);
    ("schemas", schema_cases);
    ("examples", all_examples_cases);
  ]
