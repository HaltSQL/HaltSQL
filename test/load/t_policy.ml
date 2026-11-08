open Haltsql_core
open Haltsql_load
open Helpers

let tbl (p : Policy.t) schema name =
  match Policy.find_table p ~schema ~name with
  | Some t -> t
  | None -> Alcotest.failf "table %s.%s not found" schema name

let sl = Alcotest.(list string)

let happy =
  [
    tc "minimal policy defaults" (fun () ->
        let p = pol_ok "" in
        Alcotest.(check string) "name" "t" p.name;
        Alcotest.(check string) "dialect" "postgres" p.dialect;
        Alcotest.check sl "search_path" [ "public" ] p.search_path;
        Alcotest.(check bool) "limits" true (p.limits = Policy.default_limits);
        Alcotest.(check bool) "statements" true (p.statements = [ Policy.Select ]);
        Alcotest.(check bool) "require_limit" true (p.require_limit = None);
        Alcotest.(check bool)
          "tenancy" true
          (p.tenancy = { Policy.mode = Bound; keys = [] });
        Alcotest.check sl "operators"
          (List.sort_uniq compare Policy_load.default_operators)
          p.operators;
        Alcotest.check sl "casts"
          (List.sort_uniq compare Policy_load.default_deny_casts)
          p.deny_casts;
        Alcotest.(check bool) "explain" false p.allow_explain;
        Alcotest.(check bool) "mode" true (p.mode = Policy.Enforce);
        Alcotest.(check string) "api" "haltsql.dev/v1" p.api_version;
        Alcotest.(check bool)
          "version" true
          (String.length p.version = 71 && String.sub p.version 0 7 = "sha256:"));
    tc "metadata owner/description" (fun () ->
        let p =
          get_ok
            (Policy_load.of_string Docload.Yaml
               "apiVersion: haltsql.dev/v1\n\
                kind: Policy\n\
                metadata: {name: a, owner: o, description: d}\n")
        in
        Alcotest.(check (option string)) "owner" (Some "o") p.owner;
        Alcotest.(check (option string)) "desc" (Some "d") p.description);
    tc "dialect postgres-17" (fun () ->
        Alcotest.(check string) "d" "postgres-17" (pol_ok "dialect: postgres-17").dialect);
    tc "search_path normalized" (fun () ->
        Alcotest.check sl "sp" [ "app"; "Mixed" ]
          (pol_ok "search_path: [APP, '\"Mixed\"']").search_path);
    tc "limits" (fun () ->
        let p =
          pol_ok "limits: {max_bytes: 100, max_depth: 10, max_nodes: 1000, max_joins: 0}"
        in
        Alcotest.(check bool)
          "l" true
          (p.limits = { max_bytes = 100; max_depth = 10; max_nodes = 1000; max_joins = 0 }));
    tc "partial limits keep defaults" (fun () ->
        let p = pol_ok "limits: {max_joins: 3}" in
        Alcotest.(check int) "joins" 3 p.limits.max_joins;
        Alcotest.(check int) "bytes" 16384 p.limits.max_bytes);
    tc "statements canonical order and dedup" (fun () ->
        let p = pol_ok "statements: {allow: [delete, select, select, insert]}" in
        Alcotest.(check bool) "s" true (p.statements = [ Policy.Select; Insert; Delete ]));
    tc "require_limit" (fun () ->
        Alcotest.(check (option int))
          "r" (Some 50) (pol_ok "require_limit: {max: 50}").require_limit);
    tc "tenancy keys" (fun () ->
        let p =
          pol_ok
            "tenancy: {mode: literal, keys: {workspace: '${ctx.ws}', org: \
             '${ctx.org_id}'}}"
        in
        Alcotest.(check bool) "mode" true (p.tenancy.mode = Policy.Literal);
        Alcotest.(check (list (pair string string)))
          "keys"
          [ ("org", "org_id"); ("workspace", "ws") ]
          p.tenancy.keys);
    tc "tenancy unquoted placeholder" (fun () ->
        Alcotest.(check (list (pair string string)))
          "k"
          [ ("tenant", "tenant_id") ]
          (pol_ok "tenancy:\n  keys:\n    tenant: ${ctx.tenant_id}\n").tenancy.keys);
    tc "tenancy value shorthand" (fun () ->
        Alcotest.(check (list (pair string string)))
          "k"
          [ ("tenant", "tid") ]
          (pol_ok "tenancy: {value: '${ctx.tid}'}").tenancy.keys);
    tc "tables qualify with search_path head" (fun () ->
        let p =
          pol_ok
            "search_path: [app, public]\n\
             tables:\n\
            \  orders: {columns: [id]}\n\
            \  public.x: {columns: '*'}\n"
        in
        ignore (tbl p "app" "orders");
        ignore (tbl p "public" "x"));
    tc "tables sorted" (fun () ->
        let p = pol_ok "tables:\n  zeta: {columns: [a]}\n  alpha: {columns: [a]}\n" in
        Alcotest.check sl "order" [ "alpha"; "zeta" ]
          (List.map (fun (t : Policy.table) -> t.name) p.tables));
    tc "identifier normalization" (fun () ->
        let p =
          pol_ok
            "tables:\n\
            \  App.Orders: {columns: [ID, '\"CreatedAt\"']}\n\
            \  '\"MixedCase\".\"Orders\"': {columns: '*'}\n\
            \  '\"we\"\"ird.name\"': {columns: [x]}\n"
        in
        let t = tbl p "app" "orders" in
        Alcotest.(check bool) "cols" true (t.columns = Policy.Only [ "id"; "CreatedAt" ]);
        ignore (tbl p "MixedCase" "Orders");
        ignore (tbl p "public" "we\"ird.name"));
    tc "tenant_column shorthand" (fun () ->
        let p =
          pol_ok
            "tenancy: {keys: {tenant: '${ctx.tenant_id}'}}\n\
             tables:\n\
            \  orders: {columns: [id, Tenant_ID], tenant_column: TENANT_ID}\n"
        in
        Alcotest.(check (list (pair string string)))
          "tc"
          [ ("tenant_id", "tenant") ]
          (tbl p "public" "orders").tenant_columns);
    tc "tenant_columns composite" (fun () ->
        let p =
          pol_ok
            "tenancy: {keys: {org: '${ctx.o}', ws: '${ctx.w}'}}\n\
             tables:\n\
            \  docs: {columns: [id, org_id, ws_id], tenant_columns: {ws_id: ws, org_id: \
             org}}\n"
        in
        Alcotest.(check (list (pair string string)))
          "tc"
          [ ("org_id", "org"); ("ws_id", "ws") ]
          (tbl p "public" "docs").tenant_columns);
    tc "tenant column with star columns" (fun () ->
        let p =
          pol_ok
            "tenancy: {value: '${ctx.t}'}\n\
             tables:\n\
            \  o: {columns: '*', tenant_column: tid}\n"
        in
        Alcotest.(check (list (pair string string)))
          "tc"
          [ ("tid", "tenant") ]
          (tbl p "public" "o").tenant_columns);
    tc "writes" (fun () ->
        let p =
          pol_ok
            "statements: {allow: [select, insert, update, delete]}\n\
             tables:\n\
            \  o: {columns: [a, b], writes: {insert: true, update: [b], delete: true}}\n\
            \  q: {columns: [a], writes: {update: '*'}}\n\
            \  r: {columns: [a], writes: {update: false}}\n"
        in
        let o = tbl p "public" "o" in
        Alcotest.(check bool)
          "o" true
          (o.writes
          = { insert = true; update = Some (Policy.Only [ "b" ]); delete = true });
        Alcotest.(check bool)
          "q" true
          ((tbl p "public" "q").writes.update = Some Policy.All);
        Alcotest.(check bool) "r" true ((tbl p "public" "r").writes = Policy.no_writes));
    tc "functions allow lower-cased and sorted" (fun () ->
        Alcotest.check sl "f"
          [ "app.my_fn"; "count"; "lower" ]
          (pol_ok "functions: {allow: [LOWER, count, App.My_Fn, count]}").functions);
    tc "presets expand" (fun () ->
        let p = pol_ok "functions: {presets: [aggregates, window]}" in
        List.iter
          (fun f -> Alcotest.(check bool) f true (List.mem f p.functions))
          [ "count"; "sum"; "row_number"; "lag" ];
        Alcotest.(check bool) "no lower" false (List.mem "lower" p.functions));
    tc "presets plus allow dedup" (fun () ->
        let p = pol_ok "functions: {presets: [aggregates], allow: [count, lower]}" in
        Alcotest.(check int)
          "count once" 1
          (List.length (List.filter (( = ) "count") p.functions)));
    tc "operators allow replaces" (fun () ->
        Alcotest.check sl "o" [ "<"; "=" ]
          (pol_ok "operators: {allow: ['=', '<']}").operators);
    tc "operators extend" (fun () ->
        let p = pol_ok "operators: {extend: ['#-']}" in
        Alcotest.(check bool) "ext" true (List.mem "#-" p.operators);
        Alcotest.(check bool) "default" true (List.mem "=" p.operators));
    tc "deny_casts list replaces" (fun () ->
        Alcotest.check sl "c" [ "regclass" ] (pol_ok "deny_casts: [RegClass]").deny_casts);
    tc "deny_casts extend" (fun () ->
        let p = pol_ok "deny_casts: {extend: [oid]}" in
        Alcotest.(check bool) "oid" true (List.mem "oid" p.deny_casts);
        Alcotest.(check bool) "regclass" true (List.mem "regclass" p.deny_casts));
    tc "allow_explain and shadow" (fun () ->
        let p = pol_ok "allow_explain: true\nmode: shadow" in
        Alcotest.(check bool) "e" true p.allow_explain;
        Alcotest.(check bool) "m" true (p.mode = Policy.Shadow));
    tc "no snapshot means an empty catalog (never derived from allowlists)" (fun () ->
        (* Regression: deriving catalog entries from allowed-column lists made
           SELECT * look safe on tables with hidden columns. *)
        let p = pol_ok "tables:\n  a: {columns: [x, y]}\n  b: {columns: '*'}\n" in
        Alcotest.(check int) "no tables" 0 (List.length p.catalog.tables));
    tc "inline catalog" (fun () ->
        let p =
          pol_ok
            "catalog: {tables: {public.a: {columns: [x, {name: y, type: INT8}]}}}\n\
             tables:\n\
            \  a: {columns: '*'}\n"
        in
        let t = Option.get (Catalog.find p.catalog ~schema:"public" ~name:"a") in
        Alcotest.(check (option string))
          "type" (Some "int8") (List.nth t.columns 1).col_type);
    tc "null optional fields are absent" (fun () ->
        ignore (pol_ok "dialect:\nlimits: ~\nfunctions: null"));
    tc "json source" (fun () ->
        ignore
          (get_ok
             (Policy_load.of_string Docload.Json
                {|{"apiVersion":"haltsql.dev/v1","kind":"Policy","metadata":{"name":"j"}}|})));
  ]

(* (name, extra yaml, expected path, message substring) *)
let error_table =
  [
    ("unknown top key", "tabels: {}", "tabels", "did you mean \"tables\"");
    ("unknown nested key", "limits: {max_byte: 1}", "limits.max_byte", "unknown key");
    (* Regression: "did you mean" hints used a quadratic-memory edit distance, so
       one huge unknown key could exhaust memory. Long keys now get the plain
       list of allowed keys. *)
    ( "huge unknown key",
      (* explicit "? key" form: YAML implicit keys are limited to 1024 chars *)
      "? " ^ String.make 200_000 'k' ^ "\n: 1",
      String.make 200_000 'k',
      "(allowed: apiVersion" );
    ( "unknown table key",
      "tables:\n  a: {columns: [x], tenant_colum: x}",
      "tables.a.tenant_colum",
      "unknown key" );
    ("bad dialect", "dialect: mysql", "dialect", "unsupported dialect");
    ("bad dialect version", "dialect: postgres-1", "dialect", "unsupported dialect");
    ("empty search_path", "search_path: []", "search_path", "must not be empty");
    ("dup search_path", "search_path: [a, A]", "search_path", "duplicate");
    ("bad ident", "search_path: ['a b']", "search_path[0]", "invalid identifier");
    ("limits type", "limits: {max_bytes: big}", "limits.max_bytes", "expected an integer");
    ("limits zero", "limits: {max_depth: 0}", "limits.max_depth", "between 1 and");
    ("limits huge", "limits: {max_bytes: 999999999}", "limits.max_bytes", "between");
    ("limits float", "limits: {max_nodes: 1.5}", "limits.max_nodes", "expected an integer");
    ( "statements unknown",
      "statements: {allow: [select, drop]}",
      "statements.allow[1]",
      "invalid value \"drop\"" );
    ( "statements empty",
      "statements: {allow: []}",
      "statements.allow",
      "must not be empty" );
    ("statements missing allow", "statements: {}", "statements.allow", "required");
    ("require_limit zero", "require_limit: {max: 0}", "require_limit.max", "between");
    ("require_limit missing", "require_limit: {}", "require_limit.max", "required");
    ("tenancy mode", "tenancy: {mode: strict}", "tenancy.mode", "invalid value");
    ( "tenancy bad placeholder",
      "tenancy: {keys: {t: tenant_id}}",
      "tenancy.keys.t",
      "context placeholder" );
    ( "tenancy env placeholder",
      "tenancy: {keys: {t: '${env:X}'}}",
      "tenancy.keys.t",
      "only allowed in Config" );
    ( "tenancy bad key name",
      "tenancy: {keys: {'bad-key': '${ctx.x}'}}",
      "tenancy.keys.bad-key",
      "invalid tenancy key" );
    ( "tenancy both",
      "tenancy: {value: '${ctx.a}', keys: {t: '${ctx.b}'}}",
      "tenancy.value",
      "not both" );
    ("tenancy empty keys", "tenancy: {keys: {}}", "tenancy.keys", "must not be empty");
    ( "env placeholder anywhere",
      "deny_casts: ['${env:X}']",
      "deny_casts[0]",
      "only allowed in Config" );
    ( "file placeholder in table",
      "tables:\n  a: {columns: ['${file:/etc/passwd}']}",
      "tables.a.columns[0]",
      "only allowed in Config" );
    ( "ctx placeholder outside tenancy",
      "dialect: '${ctx.d}'",
      "dialect",
      "only allowed in tenancy.keys" );
    ("columns missing", "tables:\n  a: {}", "tables.a.columns", "required");
    ( "columns empty",
      "tables:\n  a: {columns: []}",
      "tables.a.columns",
      "must not be empty" );
    ( "columns bad string",
      "tables:\n  a: {columns: all}",
      "tables.a.columns",
      "expected \"*\"" );
    ( "columns duplicate",
      "tables:\n  a: {columns: [x, X]}",
      "tables.a.columns[1]",
      "duplicate column" );
    ( "table three parts",
      "tables:\n  db.s.t: {columns: [x]}",
      "tables.\"db.s.t\"",
      "schema.table" );
    ( "table bad name",
      "tables:\n  'a-b': {columns: [x]}",
      "tables.a-b",
      "invalid identifier" );
    ( "table unterminated quote",
      "tables:\n  '\"abc': {columns: [x]}",
      "tables.\"\\\"abc\"",
      "unterminated" );
    ( "table duplicate after normalization",
      "tables:\n  orders: {columns: [x]}\n  PUBLIC.orders: {columns: [x]}",
      "tables.\"PUBLIC.orders\"",
      "more than once" );
    ( "tenant_column without keys",
      "tables:\n  a: {columns: [x], tenant_column: x}",
      "tables.a.tenant_column",
      "needs a tenancy key" );
    ( "tenant_column with two keys",
      "tenancy: {keys: {a: '${ctx.a}', b: '${ctx.b}'}}\n\
       tables:\n\
      \  t: {columns: [x], tenant_column: x}",
      "tables.t.tenant_column",
      "several keys" );
    ( "tenant_columns unknown key",
      "tenancy: {value: '${ctx.a}'}\n\
       tables:\n\
      \  t: {columns: [x], tenant_columns: {x: nope}}",
      "tables.t.tenant_columns.x",
      "unknown tenancy key" );
    ( "tenant column not readable",
      "tenancy: {value: '${ctx.a}'}\ntables:\n  t: {columns: [x], tenant_column: tid}",
      "tables.t.tenant_column",
      "must be listed in columns" );
    ( "tenant both forms",
      "tenancy: {value: '${ctx.a}'}\n\
       tables:\n\
      \  t: {columns: [x], tenant_column: x, tenant_columns: {x: tenant}}",
      "tables.t.tenant_columns",
      "not both" );
    ( "writes without statement",
      "tables:\n  t: {columns: [x], writes: {insert: true}}",
      "tables.t.writes.insert",
      "not in statements.allow" );
    ( "update without statement",
      "tables:\n  t: {columns: [x], writes: {update: [x]}}",
      "tables.t.writes.update",
      "not in statements.allow" );
    ( "delete without statement",
      "tables:\n  t: {columns: [x], writes: {delete: true}}",
      "tables.t.writes.delete",
      "not in statements.allow" );
    ( "update true",
      "statements: {allow: [update]}\n\
       tables:\n\
      \  t: {columns: [x], writes: {update: true}}",
      "tables.t.writes.update",
      "instead of true" );
    ( "update tenant column",
      "statements: {allow: [select, update]}\n\
       tenancy: {value: '${ctx.a}'}\n\
       tables:\n\
      \  t: {columns: [x, tid], tenant_column: tid, writes: {update: [x, tid]}}",
      "tables.t.writes.update",
      "must not be updatable" );
    ( "writes bool type",
      "statements: {allow: [insert]}\n\
       tables:\n\
      \  t: {columns: [x], writes: {insert: 'yes'}}",
      "tables.t.writes.insert",
      "expected a boolean" );
    ( "functions unknown preset",
      "functions: {presets: [everything]}",
      "functions.presets[0]",
      "unknown function preset" );
    ( "functions quoted",
      "functions: {allow: ['\"Lower\"']}",
      "functions.allow[0]",
      "must not be quoted" );
    ( "functions bad",
      "functions: {allow: ['pg_sleep(1)']}",
      "functions.allow[0]",
      "invalid identifier" );
    ( "operators bad",
      "operators: {allow: ['and']}",
      "operators.allow[0]",
      "invalid operator" );
    ("deny_casts bad type", "deny_casts: 5", "deny_casts", "expected a list of type names");
    ("deny_casts bad name", "deny_casts: ['1abc']", "deny_casts[0]", "invalid type name");
    ("allow_explain type", "allow_explain: yes", "allow_explain", "expected a boolean");
    ("mode bad", "mode: audit", "mode", "invalid value");
    ( "catalog missing file",
      "catalog: ./does-not-exist.json",
      "catalog",
      "cannot load catalog snapshot" );
    ("catalog wrong type", "catalog: 5", "catalog", "expected a path");
    ( "table not in catalog",
      "catalog: {tables: {public.a: {columns: [x]}}}\ntables:\n  b: {columns: [x]}",
      "tables.b",
      "not in the catalog" );
    ( "column not in catalog",
      "catalog: {tables: {public.a: {columns: [x]}}}\ntables:\n  a: {columns: [x, y]}",
      "tables.a.columns",
      "does not exist" );
    ( "tenant column not in catalog",
      "tenancy: {value: '${ctx.t}'}\n\
       catalog: {tables: {public.a: {columns: [x]}}}\n\
       tables:\n\
      \  a: {columns: '*', tenant_column: tid}",
      "tables.a.tenant_column",
      "does not exist" );
  ]

let header_errors =
  [
    tc "missing apiVersion" (fun () ->
        check_err ~path:"apiVersion" ~msg:"required"
          (Policy_load.of_string Docload.Yaml "kind: Policy\nmetadata: {name: a}"));
    tc "wrong apiVersion" (fun () ->
        check_err ~path:"apiVersion" ~msg:"unsupported apiVersion"
          (Policy_load.of_string Docload.Yaml
             "apiVersion: haltsql.dev/v2\nkind: Policy\nmetadata: {name: a}"));
    tc "wrong kind" (fun () ->
        check_err ~path:"kind" ~msg:"expected kind \"Policy\""
          (Policy_load.of_string Docload.Yaml
             "apiVersion: haltsql.dev/v1\nkind: Config\nmetadata: {name: a}"));
    tc "missing metadata" (fun () ->
        check_err ~path:"metadata" ~msg:"required"
          (Policy_load.of_string Docload.Yaml "apiVersion: haltsql.dev/v1\nkind: Policy"));
    tc "missing name" (fun () ->
        check_err ~path:"metadata.name" ~msg:"required"
          (Policy_load.of_string Docload.Yaml
             "apiVersion: haltsql.dev/v1\nkind: Policy\nmetadata: {owner: x}"));
    tc "bad name" (fun () ->
        check_err ~path:"metadata.name" ~msg:"invalid policy name"
          (Policy_load.of_string Docload.Yaml
             "apiVersion: haltsql.dev/v1\nkind: Policy\nmetadata: {name: 'a b'}"));
    tc "root not a mapping" (fun () ->
        check_err ~path:"" ~msg:"expected a mapping"
          (Policy_load.of_string Docload.Yaml "- a"));
    tc "collects all errors" (fun () ->
        let errs =
          get_err (pol "dialect: x\nmode: y\nlimits: {max_joins: -1}\nbogus: 1")
        in
        Alcotest.(check bool) "at least 4" true (List.length errs >= 4));
    tc "errors have line and column" (fun () ->
        let errs =
          get_err (pol "tables:\n  a:\n    columns: [x]\n    tenant_colum: x\n")
        in
        let e =
          List.find (fun (e : Load_error.t) -> e.path = "tables.a.tenant_colum") errs
        in
        Alcotest.(check (option int)) "line" (Some 7) e.line;
        Alcotest.(check (option int)) "col" (Some 5) e.column);
    tc "errors in json have positions" (fun () ->
        let errs =
          get_err
            (Policy_load.of_string ~file:"p.json" Docload.Json
               "{\"apiVersion\":\"haltsql.dev/v1\",\"kind\":\"Policy\",\n\
                \"metadata\":{\"name\":\"a\"},\n\
                \"mode\":\"x\"}")
        in
        let e = List.hd errs in
        Alcotest.(check (option int)) "line" (Some 3) e.line;
        Alcotest.(check (option string)) "file" (Some "p.json") e.file);
    tc "of_json without positions" (fun () ->
        let e =
          List.hd (get_err (Policy_load.of_json (`Assoc [ ("kind", `String "Policy") ])))
        in
        Alcotest.(check (option int)) "no line" None e.line);
  ]

let dangerous =
  [
    "pg_sleep";
    "pg_sleep_for";
    "pg_sleep_until";
    "dblink";
    "dblink_exec";
    "dblink_connect";
    "lo_import";
    "lo_export";
    "lo_get";
    "lo_put";
    "lo_from_bytea";
    "pg_read_file";
    "pg_read_binary_file";
    "pg_ls_dir";
    "pg_stat_file";
    "set_config";
    "current_setting";
    "nextval";
    "setval";
    "currval";
    "lastval";
    "txid_current";
    "txid_current_snapshot";
    "pg_advisory_lock";
    "pg_advisory_xact_lock";
    "pg_try_advisory_lock";
    "pg_terminate_backend";
    "pg_cancel_backend";
    "pg_reload_conf";
    "query_to_xml";
    "table_to_xml";
    "generate_series";
    "random";
    "gen_random_uuid";
    "uuid_generate_v4";
    "xmlparse";
    "xpath";
    "xmlelement";
    "row_to_json";
    "format";
    "repeat";
    "pg_logical_emit_message";
    "copy";
    "pg_notify";
  ]

let preset_cases =
  [
    tc "no dangerous function in any preset" (fun () ->
        List.iter
          (fun (preset, fs) ->
            List.iter
              (fun f ->
                let bad =
                  List.mem f dangerous
                  || List.exists
                       (fun prefix ->
                         String.length f >= String.length prefix
                         && String.sub f 0 (String.length prefix) = prefix)
                       [
                         "pg_"; "dblink"; "lo_"; "txid_"; "xml"; "set_"; "current_setting";
                       ]
                in
                if bad then Alcotest.failf "dangerous function %s in preset %s" f preset)
              fs)
          Policy_load.function_presets);
    tc "presets are lower-case and unique" (fun () ->
        List.iter
          (fun (_, fs) ->
            Alcotest.(check int)
              "unique" (List.length fs)
              (List.length (List.sort_uniq compare fs));
            List.iter (fun f -> Alcotest.(check string) f (String.lowercase_ascii f) f) fs)
          Policy_load.function_presets);
    tc "expected presets exist" (fun () ->
        List.iter
          (fun n ->
            Alcotest.(check bool) n true (List.mem_assoc n Policy_load.function_presets))
          [
            "aggregates";
            "math";
            "string";
            "regex";
            "datetime";
            "json";
            "conditional";
            "window";
          ]);
    tc "regex functions only in regex preset" (fun () ->
        List.iter
          (fun (n, fs) ->
            if n <> "regex" then
              List.iter
                (fun f -> if contains f "regexp" then Alcotest.failf "%s in %s" f n)
                fs)
          Policy_load.function_presets);
    tc "default deny casts" (fun () ->
        List.iter
          (fun c ->
            Alcotest.(check bool) c true (List.mem c Policy_load.default_deny_casts))
          [ "regclass"; "regproc"; "regtype"; "regnamespace"; "regrole"; "txid_snapshot" ]);
    tc "default operators" (fun () ->
        List.iter
          (fun o ->
            Alcotest.(check bool) o true (List.mem o Policy_load.default_operators))
          [ "="; "<>"; "||"; "~~"; "~~*"; "->>"; "@>"; "?|"; "&&" ]);
  ]

let version_cases =
  [
    tc "saas.yaml and saas.json same version" (fun () ->
        let a = get_ok (Policy_load.of_file (ex "policies/saas.yaml")) in
        let b = get_ok (Policy_load.of_file (ex "policies/saas.json")) in
        Alcotest.(check string) "version" a.version b.version;
        Alcotest.(check bool) "records equal" true (a = b));
    tc "version independent of key order" (fun () ->
        let a =
          pol_ok
            "mode: shadow\n\
             tables:\n\
            \  a: {columns: [x]}\n\
            \  b: {columns: [y]}\n\
             functions: {allow: [lower, count]}\n"
        in
        let b =
          pol_ok
            "functions: {allow: [count, lower]}\n\
             tables:\n\
            \  b: {columns: [y]}\n\
            \  a: {columns: [x]}\n\
             mode: shadow\n"
        in
        Alcotest.(check string) "v" a.version b.version);
    tc "version independent of spelling" (fun () ->
        let a = pol_ok "tables:\n  Orders: {columns: [ID]}\n" in
        let b = pol_ok "tables:\n  public.orders: {columns: [id]}\n" in
        Alcotest.(check string) "v" a.version b.version);
    tc "version changes with content" (fun () ->
        Alcotest.(check bool)
          "differs" true
          ((pol_ok "mode: shadow").version <> (pol_ok "mode: enforce").version));
    tc "version changes with column order" (fun () ->
        Alcotest.(check bool)
          "differs" true
          ((pol_ok "tables:\n  a: {columns: [x, y]}").version
         <> (pol_ok "tables:\n  a: {columns: [y, x]}").version));
    tc "version is sha256 of canonical to_json" (fun () ->
        let p = pol_ok "tables:\n  a: {columns: [x]}" in
        let rec sort = function
          | `Assoc kvs ->
              `Assoc
                (List.sort
                   (fun (a, _) (b, _) -> compare a b)
                   (List.map (fun (k, v) -> (k, sort v)) kvs))
          | `List l -> `List (List.map sort l)
          | j -> j
        in
        let s = Yojson.Safe.to_string (sort (Policy_load.to_json p)) in
        Alcotest.(check string)
          "v"
          ("sha256:" ^ Digestif.SHA256.(to_hex (digest_string s)))
          p.version);
    tc "to_json reloads to the same policy" (fun () ->
        List.iter
          (fun f ->
            let p = get_ok (Policy_load.of_file (ex f)) in
            let p' = get_ok (Policy_load.of_json (Policy_load.to_json p)) in
            Alcotest.(check bool) f true (p = p'))
          [
            "policies/saas.yaml";
            "policies/composite.yaml";
            "policies/hierarchical.yaml";
            "policies/writes.yaml";
            "policies/shadow.yaml";
          ]);
    tc "to_json yaml round trip" (fun () ->
        let p = get_ok (Policy_load.of_file (ex "policies/shadow.yaml")) in
        let y = Docload.to_string Docload.Yaml (Policy_load.to_json p) in
        let p' = get_ok (Policy_load.of_string Docload.Yaml y) in
        Alcotest.(check string) "v" p.version p'.version);
  ]

let example_cases =
  [
    tc "saas example contents" (fun () ->
        let p = get_ok (Policy_load.of_file (ex "policies/saas.yaml")) in
        Alcotest.(check int) "tables" 4 (List.length p.tables);
        let o = tbl p "app" "orders" in
        Alcotest.(check (list (pair string string)))
          "tenant"
          [ ("tenant_id", "tenant") ]
          o.tenant_columns;
        Alcotest.(check bool)
          "currencies global" true
          ((tbl p "app" "currencies").tenant_columns = []);
        Alcotest.(check int) "catalog from snapshot" 4 (List.length p.catalog.tables);
        Alcotest.(check bool)
          "has types" true
          ((List.hd
              (Option.get (Catalog.find p.catalog ~schema:"app" ~name:"orders")).columns)
             .col_type = Some "int8"));
    tc "composite example" (fun () ->
        let p = get_ok (Policy_load.of_file (ex "policies/composite.yaml")) in
        Alcotest.(check int) "keys" 2 (List.length p.tenancy.keys);
        Alcotest.(check int)
          "doc tenant cols" 2
          (List.length (tbl p "public" "documents").tenant_columns));
    tc "hierarchical example" (fun () ->
        let p = get_ok (Policy_load.of_file (ex "policies/hierarchical.yaml")) in
        Alcotest.(check (list (pair string string)))
          "keys"
          [ ("org", "org_ids") ]
          p.tenancy.keys);
    tc "writes example" (fun () ->
        let p = get_ok (Policy_load.of_file (ex "policies/writes.yaml")) in
        Alcotest.(check bool)
          "delete drafts" true (tbl p "support" "ticket_drafts").writes.delete);
    tc "shadow example" (fun () ->
        let p = get_ok (Policy_load.of_file (ex "policies/shadow.yaml")) in
        Alcotest.(check bool) "shadow" true (p.mode = Policy.Shadow);
        let t = tbl p "analytics" "CampaignEvents" in
        Alcotest.(check bool)
          "quoted col" true
          (t.columns
          = Policy.Only [ "id"; "tenant_id"; "campaign_id"; "EventType"; "occurred_at" ]));
  ]

let error_case (name, extra, path, msg) =
  tc name (fun () -> check_err ~path ~msg (pol extra))

let tests =
  [
    ("policy-happy", happy);
    ("policy-errors", List.map error_case error_table);
    ("policy-header", header_errors);
    ("presets", preset_cases);
    ("version", version_cases);
    ("policy-examples", example_cases);
  ]
