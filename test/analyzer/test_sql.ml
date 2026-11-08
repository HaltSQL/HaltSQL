(* SQL-string analyzer tests: parse with Haltsql_parse.Pg_parse, analyze,
   and assert the exact set of reason codes (and binds where relevant).
   Skipped (with a clear message) while the parser is still the stub. *)

open Haltsql_core
open Helpers
module P = Haltsql_parse.Pg_parse
open Reason

let parse sql = P.parse ~limits:Policy.default_limits sql

let parser_available =
  lazy
    (match parse "SELECT 1" with
    | Ok _ -> true
    | Error r ->
        Printf.printf "SKIP: SQL analyzer tests skipped, parser unavailable: %s\n%!"
          r.message;
        false)

let t ?(policy = default_policy) ?(ctx = ctx) ?binds ?tables ?columns ?kind name sql
    expect =
  Alcotest.test_case name `Quick (fun () ->
      if not (Lazy.force parser_available) then Alcotest.skip ();
      match parse sql with
      | Error r -> Alcotest.failf "parse error for %S: %s" sql r.message
      | Ok [ stmt ] -> (
          let a = A.analyze policy ctx stmt in
          check_analysis ?binds ?tables ?columns ~expect a;
          match kind with
          | Some k ->
              if a.statement_kind <> Some k then
                Alcotest.failf "unexpected statement_kind"
          | None -> ())
      | Ok _ -> Alcotest.failf "expected one statement: %S" sql)

let acme = Context.One "acme"
let b1 = [ (1, acme) ]

let p_all =
  policy ~statements:[ Policy.Select; Policy.Insert; Policy.Update; Policy.Delete ] ()

let p_lit = policy ~mode:Policy.Literal ()

let p_lit_all =
  policy ~mode:Policy.Literal
    ~statements:[ Policy.Select; Policy.Insert; Policy.Update; Policy.Delete ]
    ()

let p_limit = policy ~require_limit:100 ()
let p_explain = policy ~allow_explain:true ()
let p_joins2 = policy ~max_joins:2 ()

(* notes is deletable in p_notes so RETURNING leak paths can be tested *)
let p_notes =
  policy
    ~statements:[ Policy.Select; Policy.Delete; Policy.Update ]
    ~tables:
      [
        orders;
        currencies;
        items;
        {
          notes with
          writes =
            { Policy.insert = false; update = Some (only [ "body" ]); delete = true };
        };
      ]
    ()

(* ===================================================================== A *)
let statement_kinds =
  [
    t "select allowed" "SELECT code FROM currencies" [] ~kind:Policy.Select
      ~tables:[ "app.currencies" ] ~columns:[ "app.currencies.code" ];
    t "select constant" "SELECT 1" [];
    t "insert not allowed" "INSERT INTO currencies (code) VALUES ('x')"
      [ E_STATEMENT_KIND; E_WRITE_DENIED ]
      ~kind:Policy.Insert;
    t "update not allowed" "UPDATE currencies SET name = 'x'"
      [ E_STATEMENT_KIND; E_WRITE_DENIED ];
    t "delete not allowed" "DELETE FROM currencies" [ E_STATEMENT_KIND; E_WRITE_DENIED ];
    t "drop table" "DROP TABLE app.orders" [ E_STATEMENT_KIND ];
    t "create table" "CREATE TABLE x (a int)" [ E_STATEMENT_KIND ];
    t "alter table" "ALTER TABLE orders ADD COLUMN x int" [ E_STATEMENT_KIND ];
    t "set" "SET search_path = public" [ E_STATEMENT_KIND ];
    t "copy" "COPY orders TO STDOUT" [ E_STATEMENT_KIND ];
    t "do block" "DO $$ BEGIN END $$" [ E_STATEMENT_KIND ];
    t "call" "CALL proc()" [ E_STATEMENT_KIND ];
    t "truncate" "TRUNCATE orders" [ E_STATEMENT_KIND ];
    t "grant" "GRANT SELECT ON orders TO public" [ E_STATEMENT_KIND ];
    t "vacuum" "VACUUM orders" [ E_STATEMENT_KIND ];
    t "lock" "LOCK TABLE orders" [ E_STATEMENT_KIND ];
    t "prepare" "PREPARE p AS SELECT 1" [ E_STATEMENT_KIND ];
    t "notify" "NOTIFY ch" [ E_STATEMENT_KIND ];
    t "explain denied by default" "EXPLAIN SELECT code FROM currencies"
      [ E_STATEMENT_KIND ];
    t "explain allowed" ~policy:p_explain "EXPLAIN SELECT code FROM currencies" []
      ~kind:Policy.Select;
    t "explain analyze" ~policy:p_explain "EXPLAIN ANALYZE SELECT code FROM currencies"
      [ E_STATEMENT_KIND ];
    t "explain (analyze)" ~policy:p_explain
      "EXPLAIN (ANALYZE) SELECT code FROM currencies" [ E_STATEMENT_KIND ];
    t "explain inner analyzed" ~policy:p_explain "EXPLAIN SELECT id FROM orders"
      [ E_TENANT_MISSING ];
    t "explain of delete in select-only policy" ~policy:p_explain
      "EXPLAIN DELETE FROM orders WHERE tenant_id = $1" [ E_STATEMENT_KIND ];
    t "all kinds allowed: delete" ~policy:p_all "DELETE FROM orders WHERE tenant_id = $1"
      [] ~binds:b1 ~kind:Policy.Delete;
  ]

(* ===================================================================== B *)
let hygiene =
  [
    t "for update" "SELECT code FROM currencies FOR UPDATE" [ E_LOCKING_CLAUSE ];
    t "for share" "SELECT code FROM currencies FOR SHARE" [ E_LOCKING_CLAUSE ];
    t "for no key update" "SELECT code FROM currencies FOR NO KEY UPDATE"
      [ E_LOCKING_CLAUSE ];
    t "for update skip locked" "SELECT code FROM currencies FOR UPDATE SKIP LOCKED"
      [ E_LOCKING_CLAUSE ];
    t "nested locking"
      "SELECT code FROM currencies WHERE code IN (SELECT code FROM currencies FOR UPDATE)"
      [ E_LOCKING_CLAUSE ];
    t "locking in cte"
      "WITH x AS (SELECT code FROM currencies FOR UPDATE) SELECT code FROM x"
      [ E_LOCKING_CLAUSE ];
    t "select into" "SELECT code INTO newtable FROM currencies" [ E_SELECT_INTO ];
    t "tablesample" "SELECT code FROM currencies TABLESAMPLE SYSTEM (10)"
      [ E_UNSUPPORTED ];
    t "3-part table name" "SELECT 1 FROM db.app.currencies" [ E_UNSUPPORTED ];
    t "xml expr" "SELECT xmlelement(name foo)" [ E_UNSUPPORTED ];
    t "grouping sets" "SELECT code, count(*) FROM currencies GROUP BY ROLLUP (code)"
      [ E_UNSUPPORTED ];
  ]

(* ===================================================================== C *)
let limits =
  [
    t "limit required" ~policy:p_limit "SELECT code FROM currencies" [ E_LIMIT_REQUIRED ];
    t "limit ok" ~policy:p_limit "SELECT code FROM currencies LIMIT 10" [];
    t "limit at max" ~policy:p_limit "SELECT code FROM currencies LIMIT 100" [];
    t "limit zero" ~policy:p_limit "SELECT code FROM currencies LIMIT 0" [];
    t "limit too high" ~policy:p_limit "SELECT code FROM currencies LIMIT 101"
      [ E_LIMIT_TOO_HIGH ];
    t "limit huge" ~policy:p_limit
      "SELECT code FROM currencies LIMIT 99999999999999999999" [ E_LIMIT_TOO_HIGH ];
    t "limit all" ~policy:p_limit "SELECT code FROM currencies LIMIT ALL"
      [ E_LIMIT_REQUIRED ];
    t "limit null" ~policy:p_limit "SELECT code FROM currencies LIMIT NULL"
      [ E_LIMIT_REQUIRED ];
    t "limit param" ~policy:p_limit "SELECT code FROM currencies LIMIT $1"
      [ E_LIMIT_TOO_HIGH; E_PARAM_UNBOUND ];
    t "limit expression" ~policy:p_limit "SELECT code FROM currencies LIMIT 5 + 5"
      [ E_LIMIT_TOO_HIGH ];
    t "limit subquery" ~policy:p_limit "SELECT code FROM currencies LIMIT (SELECT 5)"
      [ E_LIMIT_TOO_HIGH ];
    t "limit cast int" ~policy:p_limit "SELECT code FROM currencies LIMIT 10::int" [];
    t "limit negative" ~policy:p_limit "SELECT code FROM currencies LIMIT -1"
      [ E_LIMIT_TOO_HIGH ];
    t "fetch first" ~policy:p_limit "SELECT code FROM currencies FETCH FIRST 10 ROWS ONLY"
      [];
    t "offset only" ~policy:p_limit "SELECT code FROM currencies OFFSET 5"
      [ E_LIMIT_REQUIRED ];
    t "inner subquery needs none" ~policy:p_limit
      "SELECT s.code FROM (SELECT code FROM currencies) s LIMIT 5" [];
    t "cte needs none" ~policy:p_limit
      "WITH x AS (SELECT code FROM currencies) SELECT code FROM x LIMIT 5" [];
    t "inner limit does not satisfy outer" ~policy:p_limit
      "SELECT s.code FROM (SELECT code FROM currencies LIMIT 5) s" [ E_LIMIT_REQUIRED ];
    t "union with outer limit" ~policy:p_limit
      "SELECT code FROM currencies UNION SELECT code FROM currencies LIMIT 10" [];
    t "union without limit" ~policy:p_limit
      "SELECT code FROM currencies UNION SELECT code FROM currencies" [ E_LIMIT_REQUIRED ];
    t "union branch limits only" ~policy:p_limit
      "(SELECT code FROM currencies LIMIT 5) UNION (SELECT code FROM currencies LIMIT 5)"
      [ E_LIMIT_REQUIRED ];
    t "set-op with limit and tenancy" ~policy:p_limit
      "SELECT id FROM orders WHERE tenant_id = $1 UNION ALL SELECT id FROM orders WHERE \
       tenant_id = $1 LIMIT 10"
      [] ~binds:b1;
    t "no require_limit" "SELECT code FROM currencies" [];
    t "limit not required for delete"
      ~policy:(policy ~require_limit:10 ~statements:[ Policy.Delete ] ())
      "DELETE FROM orders WHERE tenant_id = $1" [] ~binds:b1;
  ]

(* ===================================================================== D *)
let p_two_schemas = policy ~search_path:[ "public"; "app" ] ()

let p_two_schemas_cat =
  policy ~search_path:[ "public"; "app" ]
    ~catalog:
      {
        Catalog.tables =
          catalog.tables
          @ [
              {
                Catalog.schema = "public";
                name = "other";
                columns = [ { col_name = "x"; col_type = Some "int4" } ];
              };
            ];
      }
    ()

let tables =
  [
    t "pg_class" "SELECT relname FROM pg_class" [ E_TABLE_DENIED ];
    t "pg_catalog.pg_class" "SELECT * FROM pg_catalog.pg_class" [ E_TABLE_DENIED ];
    t "pg_authid" "SELECT rolpassword FROM pg_authid" [ E_TABLE_DENIED ];
    t "information_schema" "SELECT * FROM information_schema.tables" [ E_TABLE_DENIED ];
    t "listed system table unqualified" "SELECT name FROM pg_settings" []
      ~tables:[ "pg_catalog.pg_settings" ];
    t "listed system table qualified" "SELECT name, setting FROM pg_catalog.pg_settings"
      [];
    t "listed system table denied column" "SELECT source FROM pg_settings"
      [ E_COLUMN_DENIED ];
    t "other schema" "SELECT * FROM public.orders" [ E_TABLE_DENIED ];
    t "unknown table" "SELECT * FROM secrets" [ E_TABLE_DENIED ];
    t "quoted case differs" "SELECT * FROM \"Orders\"" [ E_TABLE_DENIED ];
    t "unquoted case folds" "SELECT ID FROM ORDERS WHERE TENANT_ID = $1" [] ~binds:b1;
    t "unicode escape name" "SELECT code FROM U&\"\\0063urrencies\"" [];
    t "schema qualified" "SELECT id FROM app.orders WHERE tenant_id = $1" [] ~binds:b1;
    t "pg_temp" "SELECT * FROM pg_temp.orders" [ E_TABLE_DENIED ];
    t "search path shadow risk" ~policy:p_two_schemas "SELECT code FROM currencies"
      [ E_TABLE_DENIED ];
    t "search path qualified ok" ~policy:p_two_schemas "SELECT code FROM app.currencies"
      [];
    t "search path catalog proves no shadow" ~policy:p_two_schemas_cat
      "SELECT code FROM currencies" [];
    t "cte shadows table (unqualified)"
      "WITH orders AS (SELECT 1 AS id) SELECT id FROM orders" [];
    t "qualified name bypasses cte"
      "WITH orders AS (SELECT 1 AS id) SELECT id FROM app.orders" [ E_TENANT_MISSING ];
    t "cte named like unknown table"
      "WITH secrets AS (SELECT code FROM currencies) SELECT code FROM secrets" [];
    t "cte not visible outside its subquery"
      "SELECT 1 FROM (WITH x AS (SELECT 1 AS a) SELECT a FROM x) s, x" [ E_TABLE_DENIED ];
    t "later cte sees earlier"
      "WITH a AS (SELECT code FROM currencies), b AS (SELECT code FROM a) SELECT code \
       FROM b"
      [];
    t "earlier cte does not see later"
      "WITH a AS (SELECT code FROM b), b AS (SELECT code FROM currencies) SELECT code \
       FROM a"
      [ E_TABLE_DENIED ];
    t "recursive cte"
      "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 10) \
       SELECT n FROM r"
      [ E_UNSUPPORTED ];
    t "recursive cte without colnames"
      "WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM r WHERE n < 10) \
       SELECT n FROM r"
      [ E_UNSUPPORTED ];
    t "recursive term unfiltered"
      "WITH RECURSIVE r AS (SELECT id, customer_id FROM orders WHERE tenant_id = $1 \
       UNION ALL SELECT o.id, o.customer_id FROM orders o JOIN r ON o.customer_id = \
       r.id) SELECT id FROM r"
      [ E_UNSUPPORTED; E_TENANT_MISSING ];
    t "recursive term filtered"
      "WITH RECURSIVE r AS (SELECT id, customer_id FROM orders WHERE tenant_id = $1 \
       UNION ALL SELECT o.id, o.customer_id FROM orders o JOIN r ON o.customer_id = r.id \
       WHERE o.tenant_id = $1) SELECT id FROM r"
      (* WITH RECURSIVE is always denied (unbounded work); the body is still
         analyzed, and here it is otherwise clean. *)
      [ E_UNSUPPORTED ];
    t "only" "SELECT code FROM ONLY currencies" [];
    t "tables recorded sorted"
      "SELECT c.code, o.id FROM orders o, currencies c WHERE o.tenant_id = $1" []
      ~tables:[ "app.currencies"; "app.orders" ];
  ]

(* ===================================================================== E *)
let p_rtj = policy ~functions:("row_to_json" :: default_functions) ()

let columns =
  [
    t "denied column in select" "SELECT email FROM customers WHERE tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "denied qualified" "SELECT c.email FROM customers c WHERE c.tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "denied only in where"
      "SELECT name FROM customers WHERE tenant_id = $1 AND email = 'x'"
      [ E_COLUMN_DENIED ];
    t "denied only in order by"
      "SELECT name FROM customers WHERE tenant_id = $1 ORDER BY email" [ E_COLUMN_DENIED ];
    t "denied only in group by"
      "SELECT count(*) FROM customers WHERE tenant_id = $1 GROUP BY email"
      [ E_COLUMN_DENIED ];
    t "denied only in having"
      "SELECT count(*) FROM customers WHERE tenant_id = $1 HAVING max(email) > ''"
      [ E_COLUMN_DENIED ];
    t "denied only in join on"
      "SELECT o.id FROM orders o JOIN customers c ON c.email = o.status WHERE \
       o.tenant_id = $1 AND c.tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "denied in function arg" "SELECT lower(ssn) FROM customers WHERE tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "denied in window"
      "SELECT row_number() OVER (PARTITION BY email) FROM customers WHERE tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "denied in case"
      "SELECT CASE WHEN ssn IS NULL THEN 1 END FROM customers WHERE tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "denied in distinct on"
      "SELECT DISTINCT ON (email) name FROM customers WHERE tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "denied in aggregate filter"
      "SELECT count(*) FILTER (WHERE email LIKE '%x') FROM customers WHERE tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "star with denied columns" "SELECT * FROM customers WHERE tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "t.* with denied columns" "SELECT c.* FROM customers c WHERE c.tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "whole-row ref" "SELECT c FROM customers c WHERE c.tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "whole-row in function, fn denied"
      "SELECT row_to_json(c) FROM customers c WHERE c.tenant_id = $1"
      [ E_FUNCTION_DENIED; E_COLUMN_DENIED ];
    t "whole-row in function, fn allowed" ~policy:p_rtj
      "SELECT row_to_json(c) FROM customers c WHERE c.tenant_id = $1" [ E_COLUMN_DENIED ];
    t "whole-row on allowed table" ~policy:p_rtj
      "SELECT row_to_json(o) FROM orders o WHERE o.tenant_id = $1" [] ~binds:b1;
    t "composite field access" "SELECT (c).email FROM customers c WHERE c.tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "whole-row cast to text" "SELECT c::text FROM customers c WHERE c.tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "whole-row in where"
      "SELECT c.id FROM customers c WHERE c.tenant_id = $1 AND c IS NOT NULL"
      [ E_COLUMN_DENIED ];
    t "count(c.*)" "SELECT count(c.*) FROM customers c WHERE c.tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "count(*) fine" "SELECT count(*) FROM customers WHERE tenant_id = $1" [] ~binds:b1;
    t "star allowed when catalog covers only-list"
      "SELECT * FROM orders WHERE tenant_id = $1" []
      ~columns:
        [
          "app.orders.created_at";
          "app.orders.customer_id";
          "app.orders.id";
          "app.orders.status";
          "app.orders.tenant_id";
          "app.orders.total_cents";
        ];
    t "derived (untyped) catalog does not license star"
      ~policy:
        (policy
           ~catalog:
             {
               Catalog.tables =
                 [
                   {
                     Catalog.schema = "app";
                     name = "orders";
                     columns =
                       List.map
                         (fun c -> { Catalog.col_name = c; col_type = None })
                         [
                           "id";
                           "tenant_id";
                           "status";
                           "total_cents";
                           "created_at";
                           "customer_id";
                         ];
                   };
                 ];
             }
           ())
      "SELECT * FROM orders WHERE tenant_id = $1" [ E_COLUMN_DENIED ];
    t "derived catalog does not prove absence of shadowing"
      ~policy:
        (policy ~search_path:[ "public"; "app" ]
           ~tables:[ currencies; table ~schema:"public" "x" ~columns:(only [ "a" ]) ]
           ~catalog:
             {
               Catalog.tables =
                 [
                   {
                     Catalog.schema = "public";
                     name = "x";
                     columns = [ { Catalog.col_name = "a"; col_type = None } ];
                   };
                 ];
             }
           ())
      "SELECT code FROM currencies" [ E_TABLE_DENIED ];
    t "star on only-table without catalog" "SELECT * FROM notes WHERE tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "star on all-table without catalog" "SELECT * FROM items WHERE tenant_id = $1" []
      ~columns:[ "app.items.*"; "app.items.tenant_id" ];
    t "star on all-table with catalog" "SELECT * FROM currencies" []
      ~columns:[ "app.currencies.code"; "app.currencies.name"; "app.currencies.rate" ];
    t "allowed columns recorded" "SELECT id, name FROM customers WHERE tenant_id = $1" []
      ~columns:[ "app.customers.id"; "app.customers.name"; "app.customers.tenant_id" ];
    t "correlated subquery reads denied inner column"
      "SELECT o.id FROM orders o WHERE o.tenant_id = $1 AND EXISTS (SELECT 1 FROM \
       customers c WHERE c.tenant_id = $1 AND c.id = o.customer_id AND c.email = 'x')"
      [ E_COLUMN_DENIED ];
    t "correlated subquery reads denied outer column"
      "SELECT c.id FROM customers c WHERE c.tenant_id = $1 AND EXISTS (SELECT 1 FROM \
       orders o WHERE o.tenant_id = $1 AND o.status = c.email)"
      [ E_COLUMN_DENIED ];
    t "unqualified correlated name is ambiguous"
      "SELECT c.id FROM customers c WHERE c.tenant_id = $1 AND EXISTS (SELECT 1 FROM \
       orders o WHERE o.tenant_id = $1 AND o.status = ssn)"
      [ E_COLUMN_UNRESOLVED ];
    t "scalar subquery in select reads denied outer"
      "SELECT (SELECT max(o.id) FROM orders o WHERE o.tenant_id = $1 AND o.status = \
       c.ssn) FROM customers c WHERE c.tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "unknown column" "SELECT nonexistent FROM currencies" [ E_COLUMN_UNRESOLVED ];
    t "attribute notation on known table" "SELECT c.nonexistent FROM currencies c"
      [ E_COLUMN_UNRESOLVED ];
    t "unknown qualifier" "SELECT x.code FROM currencies c" [ E_COLUMN_UNRESOLVED ];
    t "ambiguous column" "SELECT name FROM currencies, products" [ E_COLUMN_UNRESOLVED ];
    t "unique across items" "SELECT code, price FROM currencies, products" [];
    t "products denied column" "SELECT cost FROM products" [ E_COLUMN_DENIED ];
    t "derived table column" "SELECT s.n FROM (SELECT name AS n FROM products) s" [];
    t "derived table hides columns"
      "SELECT s.email FROM (SELECT name FROM customers WHERE tenant_id = $1) s"
      [ E_COLUMN_UNRESOLVED ];
    t "derived table exposes denied column"
      "SELECT s.e FROM (SELECT email AS e FROM customers WHERE tenant_id = $1) s"
      [ E_COLUMN_DENIED ];
    t "derived star over allowed" "SELECT s.code FROM (SELECT * FROM currencies) s" [];
    t "derived star over denied"
      "SELECT s.name FROM (SELECT * FROM customers WHERE tenant_id = $1) s"
      [ E_COLUMN_DENIED ];
    t "column alias list on base table"
      "SELECT x.a FROM customers x(a) WHERE x.tenant_id = $1"
      [ E_UNSUPPORTED; E_COLUMN_DENIED ];
    t "column alias list on derived" "SELECT s.a FROM (SELECT code FROM currencies) s(a)"
      [];
    t "values derived" "SELECT v.column1 FROM (VALUES (1), (2)) v" [];
    t "values derived with colnames" "SELECT v.x FROM (VALUES (1)) v(x)" [];
    t "function in from" "SELECT g FROM generate_series(1, 3) g" [];
    t "function in from star" "SELECT * FROM generate_series(1, 3)" [];
    t "function in from denied" "SELECT * FROM pg_ls_dir('.')" [ E_FUNCTION_DENIED ];
    t "cte column list" "WITH x(a) AS (SELECT code FROM currencies) SELECT a FROM x" [];
    t "cte hides original names"
      "WITH x(a) AS (SELECT code FROM currencies) SELECT code FROM x"
      [ E_COLUMN_UNRESOLVED ];
    t "order by output alias" "SELECT code AS k FROM currencies ORDER BY k" [];
    t "group by output alias"
      "SELECT lower(code) AS k, count(*) FROM currencies GROUP BY k" [];
    t "order by ordinal" "SELECT code FROM currencies ORDER BY 1" [];
    t "using join merges column"
      "SELECT tenant_id FROM orders JOIN items USING (tenant_id) WHERE orders.tenant_id \
       = $1 AND items.tenant_id = $1"
      [] ~binds:b1;
    t "natural join unsupported"
      "SELECT o.id FROM orders o NATURAL JOIN items i WHERE o.tenant_id = $1 AND \
       i.tenant_id = $1"
      [ E_UNSUPPORTED ];
    t "schema-qualified column ref"
      "SELECT app.orders.id FROM app.orders WHERE app.orders.tenant_id = $1" [] ~binds:b1;
    t "too many qualifiers" "SELECT db.app.currencies.code FROM currencies"
      [ E_COLUMN_UNRESOLVED ];
    t "set-op order by output"
      "SELECT code FROM currencies UNION SELECT name FROM currencies ORDER BY code" [];
    t "set-op order by non-output"
      "SELECT code FROM currencies UNION SELECT name FROM currencies ORDER BY rate"
      [ E_COLUMN_UNRESOLVED ];
    t "whole-row of all-table" "SELECT c FROM currencies c" []
      ~columns:[ "app.currencies.code"; "app.currencies.name"; "app.currencies.rate" ];
    t "column beats whole-row (catalog knows column)"
      "SELECT email FROM customers c JOIN currencies email ON true WHERE c.tenant_id = $1"
      [ E_COLUMN_DENIED ];
    t "whole-row ambiguity with only-table candidate"
      "SELECT secret FROM notes n JOIN currencies secret ON true WHERE n.tenant_id = $1"
      [ E_COLUMN_UNRESOLVED ];
    t "whole-row with harmless candidate"
      "SELECT x FROM items i JOIN currencies x ON true WHERE i.tenant_id = $1" []
      ~binds:b1;
  ]

(* ===================================================================== F/G/H *)
let p_myfn = policy ~functions:("myschema.fn" :: default_functions) ()

(* A hand-written allowlist cannot enable functions that run a SQL string themselves:
   the analyzer never sees the tables of that string (regression: ts_rewrite). *)
let p_dynsql =
  policy
    ~functions:
      ([
         "ts_rewrite";
         "to_tsquery";
         "ts_stat";
         "query_to_xml";
         "table_to_xml";
         "cursor_to_xml";
         "database_to_xml";
         "schema_to_xml";
         "dblink";
       ]
      @ default_functions)
    ()

let p_eq_only = policy ~operators:[ "=" ] ()
let p_regex = policy ~operators:[ "="; "~"; "!~" ] ()

let functions =
  [
    t "pg_sleep" "SELECT pg_sleep(1)" [ E_FUNCTION_DENIED ];
    t "count star" "SELECT count(*) FROM currencies" [];
    t "pg_catalog qualified allowed" "SELECT pg_catalog.lower(code) FROM currencies" [];
    t "other schema denied" "SELECT public.lower(code) FROM currencies"
      [ E_FUNCTION_DENIED ];
    t "set_config" "SELECT set_config('a', 'b', false)" [ E_FUNCTION_DENIED ];
    t "nextval" "SELECT nextval('s')" [ E_FUNCTION_DENIED ];
    t "dblink" "SELECT dblink('x', 'y')" [ E_FUNCTION_DENIED ];
    t "coldeflist unsupported" "SELECT * FROM dblink('x', 'y') AS t(a int)"
      [ E_UNSUPPORTED ];
    t "lo_import" "SELECT lo_import('/etc/passwd')" [ E_FUNCTION_DENIED ];
    t "ts_rewrite allowlisted still denied" ~policy:p_dynsql
      "SELECT ts_rewrite(to_tsquery('a'), 'SELECT to_tsquery(''a''), to_tsquery(code) \
       FROM currencies')"
      [ E_FUNCTION_DENIED ];
    t "pg_catalog.ts_rewrite allowlisted still denied" ~policy:p_dynsql
      "SELECT pg_catalog.ts_rewrite(to_tsquery('a'), 'SELECT 1')" [ E_FUNCTION_DENIED ];
    t "ts_stat allowlisted still denied" ~policy:p_dynsql
      "SELECT * FROM ts_stat('SELECT 1') LIMIT 1" [ E_FUNCTION_DENIED ];
    t "query_to_xml allowlisted still denied" ~policy:p_dynsql
      "SELECT query_to_xml('SELECT 1', true, false, '')" [ E_FUNCTION_DENIED ];
    t "table_to_xml allowlisted still denied" ~policy:p_dynsql
      "SELECT table_to_xml('app.notes', true, false, '')" [ E_FUNCTION_DENIED ];
    t "dblink allowlisted still denied" ~policy:p_dynsql "SELECT dblink('x', 'y')"
      [ E_FUNCTION_DENIED ];
    t "to_tsquery allowlisted is allowed" ~policy:p_dynsql
      "SELECT to_tsquery(code) FROM currencies" [];
    t "pg_read_file" "SELECT pg_read_file('/etc/passwd')" [ E_FUNCTION_DENIED ];
    t "function in where" "SELECT code FROM currencies WHERE pg_sleep(10) IS NOT NULL"
      [ E_FUNCTION_DENIED ];
    t "nested denied" "SELECT lower(upper(md5(code))) FROM currencies"
      [ E_FUNCTION_DENIED ];
    t "aggregate filter denied"
      "SELECT count(*) FILTER (WHERE pg_sleep(1) IS NULL) FROM currencies"
      [ E_FUNCTION_DENIED ];
    t "window function allowed" "SELECT row_number() OVER (ORDER BY code) FROM currencies"
      [];
    t "window function denied" "SELECT ntile(2) OVER () FROM currencies"
      [ E_FUNCTION_DENIED ];
    t "window order denied fn"
      "SELECT row_number() OVER (ORDER BY md5(code)) FROM currencies"
      [ E_FUNCTION_DENIED ];
    t "agg order denied" "SELECT array_agg(code ORDER BY md5(code)) FROM currencies"
      [ E_FUNCTION_DENIED ];
    t "quoted function name" "SELECT \"LOWER\"(code) FROM currencies"
      [ E_FUNCTION_DENIED ];
    t "schema fn allowed" ~policy:p_myfn "SELECT myschema.fn(code) FROM currencies" [];
    t "schema fn unqualified denied" ~policy:p_myfn "SELECT fn(code) FROM currencies"
      [ E_FUNCTION_DENIED ];
    t "version" "SELECT version()" [ E_FUNCTION_DENIED ];
    t "current_setting" "SELECT current_setting('x')" [ E_FUNCTION_DENIED ];
    t "now allowed" "SELECT now()" [];
    t "srf in select denied" "SELECT generate_subscripts(ARRAY[1], 1)"
      [ E_FUNCTION_DENIED ];
    t "function in subquery" "SELECT code FROM currencies WHERE code = (SELECT md5('x'))"
      [ E_FUNCTION_DENIED ];
    t "function in cte" "WITH x AS (SELECT pg_sleep(1) AS a) SELECT a FROM x"
      [ E_FUNCTION_DENIED ];
    t "function in order by" "SELECT code FROM currencies ORDER BY random()"
      [ E_FUNCTION_DENIED ];
    t "function in lateral from" "SELECT x FROM currencies c, LATERAL pg_ls_dir(c.code) x"
      [ E_FUNCTION_DENIED ];
    t "current_date" "SELECT CURRENT_DATE" [];
    t "current_timestamp" "SELECT CURRENT_TIMESTAMP" [];
    t "current_time" "SELECT CURRENT_TIME" [];
    t "localtime" "SELECT LOCALTIME" [];
    t "localtimestamp" "SELECT LOCALTIMESTAMP" [];
    t "current_user" "SELECT CURRENT_USER" [ E_FUNCTION_DENIED ];
    t "session_user" "SELECT SESSION_USER" [ E_FUNCTION_DENIED ];
    t "user" "SELECT USER" [ E_FUNCTION_DENIED ];
    t "current_role" "SELECT CURRENT_ROLE" [ E_FUNCTION_DENIED ];
    t "current_catalog" "SELECT CURRENT_CATALOG" [ E_FUNCTION_DENIED ];
    t "current_schema" "SELECT CURRENT_SCHEMA" [ E_FUNCTION_DENIED ];
  ]

let operators =
  [
    t "regex operator denied" "SELECT code FROM currencies WHERE code ~ 'x'"
      [ E_OPERATOR_DENIED ];
    t "pg_catalog operator" "SELECT 1 OPERATOR(pg_catalog.+) 1" [];
    t "other schema operator" "SELECT 1 OPERATOR(public.+) 1" [ E_OPERATOR_DENIED ];
    t "in list" "SELECT code FROM currencies WHERE code IN ('a', 'b')" [];
    t "not in needs <>" ~policy:p_eq_only
      "SELECT code FROM currencies WHERE code NOT IN ('a')" [ E_OPERATOR_DENIED ];
    t "in with eq only" ~policy:p_eq_only
      "SELECT code FROM currencies WHERE code IN ('a')" [];
    t "between" "SELECT code FROM currencies WHERE rate BETWEEN 1 AND 2" [];
    t "is distinct from" "SELECT code FROM currencies WHERE code IS DISTINCT FROM 'x'" [];
    t "nullif" "SELECT NULLIF(code, 'x') FROM currencies" [];
    t "any array" "SELECT code FROM currencies WHERE code = ANY (ARRAY['a'])" [];
    t "text search op" "SELECT code FROM currencies WHERE code @@ 'x'"
      [ E_OPERATOR_DENIED ];
    t "ilike" "SELECT code FROM currencies WHERE code ILIKE 'a%'" [];
    t "like" "SELECT code FROM currencies WHERE code LIKE 'a%'" [];
    t "similar to" ~policy:p_regex "SELECT code FROM currencies WHERE code SIMILAR TO 'a'"
      [];
    t "similar to needs ~" "SELECT code FROM currencies WHERE code SIMILAR TO 'a'"
      [ E_OPERATOR_DENIED ];
    t "like operator denied when ~~ not allowed" ~policy:p_eq_only
      "SELECT code FROM currencies WHERE code LIKE 'a%'" [ E_OPERATOR_DENIED ];
    t "all sublink"
      "SELECT code FROM currencies WHERE rate > ALL (SELECT rate FROM currencies)" [];
    t "all sublink op denied" ~policy:p_eq_only
      "SELECT code FROM currencies WHERE rate > ALL (SELECT rate FROM currencies)"
      [ E_OPERATOR_DENIED ];
    t "caret denied" "SELECT 2 ^ 2" [ E_OPERATOR_DENIED ];
    t "unary minus" "SELECT -rate FROM currencies" [];
    t "distance op denied" "SELECT code FROM currencies WHERE code <-> 'x' < 1"
      [ E_OPERATOR_DENIED ];
    t "concat" "SELECT code || name FROM currencies" [];
    t "comparison in subquery"
      "SELECT code FROM currencies WHERE EXISTS (SELECT 1 WHERE 1 # 2 = 3)"
      [ E_OPERATOR_DENIED ];
  ]

let casts =
  [
    t "regclass" "SELECT 'orders'::regclass" [ E_CAST_DENIED ];
    t "cast as regproc" "SELECT CAST('x' AS regproc)" [ E_CAST_DENIED ];
    t "oid" "SELECT 1::oid" [ E_CAST_DENIED ];
    t "qualified regtype" "SELECT 'int4'::pg_catalog.regtype" [ E_CAST_DENIED ];
    t "array of regclass" "SELECT '{x}'::regclass[]" [ E_CAST_DENIED ];
    t "uppercase regclass" "SELECT 'x'::REGCLASS" [ E_CAST_DENIED ];
    t "text cast fine" "SELECT code::text FROM currencies" [];
    t "regclass function" "SELECT regclass('x')" [ E_FUNCTION_DENIED ];
    t "cast in where" "SELECT code FROM currencies WHERE 'x'::regtype IS NOT NULL"
      [ E_CAST_DENIED ];
    t "typed literal" "SELECT interval '1 day'" [];
    t "regrole" "SELECT 'postgres'::regrole" [ E_CAST_DENIED ];
  ]

(* ===================================================================== I/J *)
let joins =
  [
    t "two joins ok" ~policy:p_joins2
      "SELECT a.code FROM currencies a, currencies b, currencies c" [];
    t "three comma joins" ~policy:p_joins2
      "SELECT a.code FROM currencies a, currencies b, currencies c, currencies d"
      [ E_JOIN_BUDGET ];
    t "three explicit joins" ~policy:p_joins2
      "SELECT a.code FROM currencies a JOIN currencies b ON true JOIN currencies c ON \
       true JOIN currencies d ON true"
      [ E_JOIN_BUDGET ];
    t "joins summed over subqueries" ~policy:p_joins2
      "SELECT a.code FROM currencies a, currencies b, currencies e WHERE EXISTS (SELECT \
       1 FROM currencies c, currencies d)"
      [ E_JOIN_BUDGET ];
    t "cross join counts" ~policy:p_joins2
      "SELECT a.code FROM currencies a CROSS JOIN currencies b CROSS JOIN currencies c \
       CROSS JOIN currencies d"
      [ E_JOIN_BUDGET ];
    t "joins in union branches" ~policy:p_joins2
      "SELECT a.code FROM currencies a, currencies b UNION SELECT a.code FROM currencies \
       a, currencies b"
      [];
  ]

let params =
  [
    t "param outside tenancy" "SELECT code FROM currencies WHERE code = $1"
      [ E_PARAM_UNBOUND ];
    t "second param unbound" "SELECT id FROM orders WHERE tenant_id = $1 AND status = $2"
      [ E_PARAM_UNBOUND ];
    t "param in select list" "SELECT $1" [ E_PARAM_UNBOUND ];
    t "tenant param reused elsewhere"
      "SELECT id FROM orders WHERE tenant_id = $1 AND status <> $1" [ E_PARAM_UNBOUND ];
    t "literal mode param" ~policy:p_lit
      "SELECT id FROM orders WHERE tenant_id = 'acme' AND status = $1" [ E_PARAM_UNBOUND ];
    t "literal mode tenant param" ~policy:p_lit
      "SELECT id FROM orders WHERE tenant_id = $1"
      [ E_PARAM_UNBOUND; E_TENANT_MISSING ];
    t "param in subquery outside tenancy"
      "SELECT id FROM orders WHERE tenant_id = $1 AND id IN (SELECT i.order_id FROM \
       items i WHERE i.tenant_id = $1 AND i.qty > $3)"
      [ E_PARAM_UNBOUND ];
  ]

(* ===================================================================== K *)
let ctx_none = Context.empty
let many = Context.Many [ "acme"; "acme-eu" ]

let tenancy =
  [
    t "basic" "SELECT id FROM orders WHERE tenant_id = $1" [] ~binds:b1;
    t "reversed operands" "SELECT id FROM orders WHERE $1 = tenant_id" [] ~binds:b1;
    t "alias qualified" "SELECT o.id FROM orders o WHERE o.tenant_id = $1" [] ~binds:b1;
    t "table-name qualified" "SELECT orders.id FROM orders WHERE orders.tenant_id = $1" []
      ~binds:b1;
    t "pg_catalog equals"
      "SELECT id FROM orders WHERE tenant_id OPERATOR(pg_catalog.=) $1" [] ~binds:b1;
    t "hidden table name behind alias"
      "SELECT o.id FROM orders o WHERE orders.tenant_id = $1"
      [ E_COLUMN_UNRESOLVED; E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "no where" "SELECT id FROM orders" [ E_TENANT_MISSING ];
    t "or 1=1" "SELECT id FROM orders WHERE tenant_id = $1 OR 1 = 1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "or tenant = $1" "SELECT id FROM orders WHERE tenant_id = $1 OR tenant_id = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "not" "SELECT id FROM orders WHERE NOT (tenant_id <> $1)"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "nested and chain"
      "SELECT id FROM orders WHERE status = 'x' AND (total_cents > 1 AND tenant_id = $1)"
      [] ~binds:b1;
    t "or of two filtered branches"
      "SELECT id FROM orders WHERE (tenant_id = $1 AND status = 'x') OR (tenant_id = $1 \
       AND status = 'y')"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "case"
      "SELECT id FROM orders WHERE CASE WHEN true THEN tenant_id = $1 ELSE true END"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "is true wrapper" "SELECT id FROM orders WHERE (tenant_id = $1) IS TRUE"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "predicate in outer only"
      "SELECT s.id FROM (SELECT id, tenant_id FROM orders) s WHERE s.tenant_id = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "predicate only in having"
      "SELECT tenant_id, count(*) FROM orders GROUP BY tenant_id HAVING tenant_id = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "union branch without filter"
      "SELECT id FROM orders WHERE tenant_id = $1 UNION SELECT id FROM orders"
      [ E_TENANT_MISSING ];
    t "union both filtered"
      "SELECT id FROM orders WHERE tenant_id = $1 UNION SELECT id FROM orders WHERE \
       tenant_id = $1"
      [] ~binds:b1;
    t "intersect branch unfiltered"
      "SELECT id FROM orders WHERE tenant_id = $1 INTERSECT SELECT id FROM orders"
      [ E_TENANT_MISSING ];
    t "except branch unfiltered"
      "SELECT id FROM orders EXCEPT SELECT id FROM orders WHERE tenant_id = $1"
      [ E_TENANT_MISSING ];
    t "cte without filter, outer filtered"
      "WITH x AS (SELECT id, tenant_id FROM orders) SELECT id FROM x WHERE tenant_id = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "cte filtered"
      "WITH x AS (SELECT id FROM orders WHERE tenant_id = $1) SELECT id FROM x" []
      ~binds:b1;
    t "unreferenced cte still checked" "WITH x AS (SELECT id FROM orders) SELECT 1"
      [ E_TENANT_MISSING ];
    t "scalar subquery in select list unfiltered"
      "SELECT o.id, (SELECT count(*) FROM items) FROM orders o WHERE o.tenant_id = $1"
      [ E_TENANT_MISSING ];
    t "scalar subquery in select list filtered"
      "SELECT o.id, (SELECT count(*) FROM items i WHERE i.tenant_id = $1) FROM orders o \
       WHERE o.tenant_id = $1"
      [] ~binds:b1;
    t "exists unfiltered"
      "SELECT o.id FROM orders o WHERE o.tenant_id = $1 AND EXISTS (SELECT 1 FROM items \
       i WHERE i.order_id = o.id)"
      [ E_TENANT_MISSING ];
    t "exists filtered"
      "SELECT o.id FROM orders o WHERE o.tenant_id = $1 AND EXISTS (SELECT 1 FROM items \
       i WHERE i.order_id = o.id AND i.tenant_id = $1)"
      [] ~binds:b1;
    t "no equality propagation"
      "SELECT o.id FROM orders o WHERE o.tenant_id = $1 AND EXISTS (SELECT 1 FROM items \
       i WHERE i.tenant_id = o.tenant_id)"
      [ E_TENANT_MISSING ];
    t "in subquery unfiltered"
      "SELECT o.id FROM orders o WHERE o.tenant_id = $1 AND o.id IN (SELECT i.order_id \
       FROM items i)"
      [ E_TENANT_MISSING ];
    t "not exists unfiltered"
      "SELECT o.id FROM orders o WHERE o.tenant_id = $1 AND NOT EXISTS (SELECT 1 FROM \
       items i)"
      [ E_TENANT_MISSING ];
    t "outer predicate placed in inner subquery"
      "SELECT o.id FROM orders o WHERE EXISTS (SELECT 1 FROM items i WHERE o.tenant_id = \
       $1 AND i.tenant_id = $1)"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "left join preserved side unfiltered"
      "SELECT o.id FROM orders o LEFT JOIN items i ON i.order_id = o.id AND i.tenant_id \
       = $1 AND o.tenant_id = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "left join nullable side filtered in on"
      "SELECT o.id FROM orders o LEFT JOIN items i ON i.order_id = o.id AND i.tenant_id \
       = $1 WHERE o.tenant_id = $1"
      [] ~binds:b1;
    t "right join nullable side filtered in on"
      "SELECT o.id FROM items i RIGHT JOIN orders o ON i.order_id = o.id AND i.tenant_id \
       = $1 WHERE o.tenant_id = $1"
      [] ~binds:b1;
    t "right join preserved side in on"
      "SELECT o.id FROM orders o RIGHT JOIN items i ON o.tenant_id = $1 AND i.tenant_id \
       = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "full join on quals"
      "SELECT o.id FROM orders o FULL JOIN items i ON i.order_id = o.id AND o.tenant_id \
       = $1 AND i.tenant_id = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "full join filtered in where"
      "SELECT o.id FROM orders o FULL JOIN items i ON i.order_id = o.id WHERE \
       o.tenant_id = $1 AND i.tenant_id = $1"
      [] ~binds:b1;
    t "inner join on filter"
      "SELECT o.id FROM orders o JOIN items i ON i.order_id = o.id AND i.tenant_id = $1 \
       WHERE o.tenant_id = $1"
      [] ~binds:b1;
    t "inner join on filters both"
      "SELECT o.id FROM orders o JOIN items i ON i.order_id = o.id AND i.tenant_id = $1 \
       AND o.tenant_id = $1"
      [] ~binds:b1;
    t "self join one alias filtered"
      "SELECT a.id FROM orders a JOIN orders b ON a.id = b.id WHERE a.tenant_id = $1"
      [ E_TENANT_MISSING ];
    t "self join both filtered"
      "SELECT a.id FROM orders a JOIN orders b ON a.id = b.id WHERE a.tenant_id = $1 AND \
       b.tenant_id = $1"
      [] ~binds:b1;
    t "same table twice comma"
      "SELECT a.id FROM orders a, orders b WHERE a.tenant_id = $1 AND b.tenant_id = $1" []
      ~binds:b1;
    t "same table twice one filtered"
      "SELECT a.id FROM orders a, orders b WHERE a.tenant_id = $1" [ E_TENANT_MISSING ];
    t "alias shadowing in subquery"
      "SELECT o.id FROM orders o WHERE o.tenant_id = $1 AND EXISTS (SELECT 1 FROM items \
       o WHERE o.tenant_id = $1)"
      [] ~binds:b1;
    t "filter on wrong table"
      "SELECT o.id FROM orders o JOIN items i ON true WHERE i.tenant_id = $1"
      [ E_TENANT_MISSING ];
    t "ambiguous unqualified tenant column"
      "SELECT o.id FROM orders o, items i WHERE tenant_id = $1"
      [ E_COLUMN_UNRESOLVED; E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "nested joins with on filters"
      "SELECT o.id FROM orders o JOIN (items i LEFT JOIN notes n ON n.tenant_id = $1) ON \
       i.tenant_id = $1 WHERE o.tenant_id = $1"
      [] ~binds:b1;
    t "inner join nested under nullable side"
      "SELECT o.id FROM orders o LEFT JOIN (items i JOIN notes n ON n.tenant_id = $1 AND \
       i.tenant_id = $1) ON true WHERE o.tenant_id = $1"
      [] ~binds:b1;
    t "preserved side of nested left join"
      "SELECT o.id FROM (orders o LEFT JOIN items i ON i.tenant_id = $1) LEFT JOIN notes \
       n ON o.tenant_id = $1 AND n.tenant_id = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "using does not prove"
      "SELECT o.id FROM orders o JOIN items i USING (tenant_id) WHERE tenant_id = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "composite keys" "SELECT id FROM memberships WHERE org_id = $1 AND user_id = $2" []
      ~binds:[ (1, Context.One "o1"); (2, Context.One "u1") ];
    t "composite key missing one" "SELECT id FROM memberships WHERE org_id = $1"
      [ E_TENANT_MISSING ];
    t "same param for two keys"
      "SELECT id FROM memberships WHERE org_id = $1 AND user_id = $1"
      [ E_TENANT_MISMATCH ];
    t "same param two tables different values"
      "SELECT o.id FROM orders o, memberships m WHERE o.tenant_id = $1 AND m.org_id = $1 \
       AND m.user_id = $2"
      [ E_TENANT_MISMATCH ];
    t "same param two keys identical values" ~ctx:ctx_int
      "SELECT o.id FROM orders o, items i WHERE o.tenant_id = $1 AND i.tenant_id = $1" []
      ~binds:[ (1, Context.One "42") ];
    t "many with any" ~ctx:ctx_many "SELECT id FROM orders WHERE tenant_id = ANY ($1)" []
      ~binds:[ (1, many) ];
    t "many with equals" ~ctx:ctx_many "SELECT id FROM orders WHERE tenant_id = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "one with any" "SELECT id FROM orders WHERE tenant_id = ANY ($1)" []
      ~binds:[ (1, Context.Many [ "acme" ]) ];
    t "in single param" "SELECT id FROM orders WHERE tenant_id IN ($1)" [] ~binds:b1;
    t "in single param many" ~ctx:ctx_many "SELECT id FROM orders WHERE tenant_id IN ($1)"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "any and equals conflict"
      "SELECT o.id FROM orders o, items i WHERE o.tenant_id = $1 AND i.tenant_id = ANY \
       ($1)"
      [ E_TENANT_MISMATCH ];
    t "cast on column side" "SELECT id FROM orders WHERE tenant_id::text = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "cast on value side" "SELECT id FROM orders WHERE tenant_id = $1::text" [] ~binds:b1;
    t "cast to bigint on value side"
      "SELECT id FROM orders WHERE tenant_id = CAST($1 AS bigint)" [] ~binds:b1;
    t "truncating cast on value side"
      "SELECT id FROM orders WHERE tenant_id = $1::varchar(3)"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "collate on value side" "SELECT id FROM orders WHERE tenant_id = $1 COLLATE \"C\""
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "collate on column side" "SELECT id FROM orders WHERE tenant_id COLLATE \"C\" = $1"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "bound mode literal" "SELECT id FROM orders WHERE tenant_id = 'acme'"
      [ E_TENANT_MISMATCH ];
    t "bound mode literal in list"
      "SELECT id FROM orders WHERE tenant_id IN ('acme', 'x')" [ E_TENANT_MISMATCH ];
    t "context missing" ~ctx:ctx_none "SELECT id FROM orders WHERE tenant_id = $1"
      [ E_CONTEXT_MISSING; E_PARAM_UNBOUND ];
    t "empty tenant set"
      ~ctx:(Context.make [ ("tenant_id", Context.Many []) ])
      "SELECT id FROM orders WHERE tenant_id = ANY ($1)"
      [ E_CONTEXT_MISSING; E_PARAM_UNBOUND ];
    t "context missing global table fine" ~ctx:ctx_none "SELECT code FROM currencies" [];
    t "subquery as value" "SELECT id FROM orders WHERE tenant_id = (SELECT $1)"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "column equals itself" "SELECT id FROM orders WHERE tenant_id = tenant_id"
      [ E_TENANT_MISSING ];
    t "true and filter" "SELECT id FROM orders WHERE true AND tenant_id = $1" [] ~binds:b1;
    t "function on value" "SELECT id FROM orders WHERE tenant_id = lower($1)"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "lateral filtered"
      "SELECT o.id, x.n FROM orders o, LATERAL (SELECT count(*) AS n FROM items i WHERE \
       i.tenant_id = $1 AND i.order_id = o.id) x WHERE o.tenant_id = $1"
      [] ~binds:b1;
    t "lateral unfiltered"
      "SELECT o.id, x.n FROM orders o, LATERAL (SELECT count(*) AS n FROM items i WHERE \
       i.order_id = o.id) x WHERE o.tenant_id = $1"
      [ E_TENANT_MISSING ];
    t "lateral join unfiltered"
      "SELECT o.id FROM orders o LEFT JOIN LATERAL (SELECT i.qty FROM items i WHERE \
       i.order_id = o.id) x ON true WHERE o.tenant_id = $1"
      [ E_TENANT_MISSING ];
    t "global table needs no filter" "SELECT code FROM currencies" [];
    t "tenant table joined to global"
      "SELECT o.id, c.code FROM orders o JOIN currencies c ON c.code = o.status WHERE \
       o.tenant_id = $1"
      [] ~binds:b1;
    t "array sublink unfiltered" "SELECT ARRAY(SELECT id FROM orders) FROM currencies"
      [ E_TENANT_MISSING ];
    t "subquery in order by unfiltered"
      "SELECT o.id FROM orders o WHERE o.tenant_id = $1 ORDER BY (SELECT max(i.qty) FROM \
       items i)"
      [ E_TENANT_MISSING ];
    t "subquery in join on unfiltered"
      "SELECT o.id FROM orders o JOIN items i ON i.order_id IN (SELECT n.id FROM notes \
       n) WHERE o.tenant_id = $1 AND i.tenant_id = $1"
      [ E_TENANT_MISSING ];
    t "derived table in from filtered inside"
      "SELECT s.id FROM (SELECT id FROM orders WHERE tenant_id = $1) s" [] ~binds:b1;
  ]

let literal_mode =
  [
    t "literal ok" ~policy:p_lit "SELECT id FROM orders WHERE tenant_id = 'acme'" []
      ~binds:[];
    t "literal reversed" ~policy:p_lit "SELECT id FROM orders WHERE 'acme' = tenant_id" [];
    t "literal mismatch" ~policy:p_lit "SELECT id FROM orders WHERE tenant_id = 'evil'"
      [ E_TENANT_MISMATCH ];
    t "literal or" ~policy:p_lit "SELECT id FROM orders WHERE tenant_id = 'acme' OR true"
      [ E_TENANT_MISSING ];
    t "literal int" ~policy:p_lit ~ctx:ctx_int
      "SELECT id FROM orders WHERE tenant_id = 42" [];
    t "literal int mismatch" ~policy:p_lit ~ctx:ctx_int
      "SELECT id FROM orders WHERE tenant_id = 43" [ E_TENANT_MISMATCH ];
    t "literal string of int" ~policy:p_lit ~ctx:ctx_int
      "SELECT id FROM orders WHERE tenant_id = '42'" [];
    t "literal string with leading zero is not normalized" ~policy:p_lit ~ctx:ctx_int
      "SELECT id FROM orders WHERE tenant_id = '042'" [ E_TENANT_MISMATCH ];
    t "literal many in list" ~policy:p_lit ~ctx:ctx_many
      "SELECT id FROM orders WHERE tenant_id IN ('acme', 'acme-eu')" [];
    t "literal many in list subset" ~policy:p_lit ~ctx:ctx_many
      "SELECT id FROM orders WHERE tenant_id IN ('acme-eu')" [];
    t "literal many in list with foreign" ~policy:p_lit ~ctx:ctx_many
      "SELECT id FROM orders WHERE tenant_id IN ('acme', 'evil')" [ E_TENANT_MISMATCH ];
    t "literal many any array" ~policy:p_lit ~ctx:ctx_many
      "SELECT id FROM orders WHERE tenant_id = ANY (ARRAY['acme', 'acme-eu'])" [];
    t "literal many any array foreign" ~policy:p_lit ~ctx:ctx_many
      "SELECT id FROM orders WHERE tenant_id = ANY (ARRAY['evil'])" [ E_TENANT_MISMATCH ];
    t "literal many equals member" ~policy:p_lit ~ctx:ctx_many
      "SELECT id FROM orders WHERE tenant_id = 'acme-eu'" [];
    t "literal cast on column" ~policy:p_lit
      "SELECT id FROM orders WHERE tenant_id::text = 'acme'" [ E_TENANT_MISSING ];
    t "literal truncating cast" ~policy:p_lit
      "SELECT id FROM orders WHERE tenant_id = 'acmex'::char(4)" [ E_TENANT_MISSING ];
    t "literal match and mismatch" ~policy:p_lit
      "SELECT id FROM orders WHERE tenant_id = 'acme' AND tenant_id = 'evil'"
      [ E_TENANT_MISMATCH ];
    t "literal composite" ~policy:p_lit
      "SELECT id FROM memberships WHERE org_id = 'o1' AND user_id = 'u1'" [];
    t "literal composite wrong user" ~policy:p_lit
      "SELECT id FROM memberships WHERE org_id = 'o1' AND user_id = 'u2'"
      [ E_TENANT_MISMATCH ];
    t "literal subquery unfiltered" ~policy:p_lit
      "SELECT id FROM orders WHERE tenant_id = 'acme' AND id IN (SELECT i.order_id FROM \
       items i)"
      [ E_TENANT_MISSING ];
  ]

(* ===================================================================== L/M *)
let writes =
  [
    t "delete filtered" ~policy:p_all "DELETE FROM orders WHERE tenant_id = $1 AND id = 5"
      [] ~binds:b1 ~tables:[ "app.orders" ];
    t "delete unfiltered" ~policy:p_all "DELETE FROM orders WHERE id = 5"
      [ E_TENANT_MISSING ];
    t "delete no where" ~policy:p_all "DELETE FROM orders" [ E_TENANT_MISSING ];
    t "delete or" ~policy:p_all "DELETE FROM orders WHERE tenant_id = $1 OR id = 5"
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "delete denied table" ~policy:p_all "DELETE FROM items WHERE tenant_id = $1"
      [ E_WRITE_DENIED ];
    t "delete no-write table" ~policy:p_all "DELETE FROM customers WHERE tenant_id = $1"
      [ E_WRITE_DENIED ];
    t "delete unknown table" ~policy:p_all "DELETE FROM secrets" [ E_TABLE_DENIED ];
    t "delete using unfiltered" ~policy:p_all
      "DELETE FROM orders o USING items i WHERE o.tenant_id = $1 AND i.order_id = o.id"
      [ E_TENANT_MISSING ];
    t "delete using filtered" ~policy:p_all
      "DELETE FROM orders o USING items i WHERE o.tenant_id = $1 AND i.order_id = o.id \
       AND i.tenant_id = $1"
      [] ~binds:b1;
    t "delete returning" ~policy:p_all
      "DELETE FROM orders WHERE tenant_id = $1 RETURNING id" [] ~binds:b1;
    t "delete returning star unknown cols" ~policy:p_notes
      "DELETE FROM notes WHERE tenant_id = $1 RETURNING *" [ E_COLUMN_DENIED ];
    t "delete returning denied col" ~policy:p_notes
      "DELETE FROM notes WHERE tenant_id = $1 RETURNING secret" [ E_COLUMN_DENIED ];
    t "delete where reads denied col" ~policy:p_notes
      "DELETE FROM notes WHERE tenant_id = $1 AND secret = 'x'" [ E_COLUMN_DENIED ];
    t "delete subquery unfiltered" ~policy:p_all
      "DELETE FROM orders WHERE tenant_id = $1 AND id IN (SELECT i.order_id FROM items i)"
      [ E_TENANT_MISSING ];
    t "update filtered" ~policy:p_all
      "UPDATE orders SET status = 'x' WHERE tenant_id = $1" [] ~binds:b1;
    t "update unfiltered" ~policy:p_all "UPDATE orders SET status = 'x'"
      [ E_TENANT_MISSING ];
    t "update sets tenant" ~policy:p_all
      "UPDATE orders SET tenant_id = 'evil' WHERE tenant_id = $1" [ E_TENANT_WRITE ];
    t "update column not allowed" ~policy:p_all
      "UPDATE orders SET customer_id = 1 WHERE tenant_id = $1" [ E_WRITE_DENIED ];
    t "update all columns allowed" ~policy:p_all
      "UPDATE items SET qty = 1 WHERE tenant_id = $1" [] ~binds:b1;
    t "update table not writable" ~policy:p_all
      "UPDATE customers SET name = 'x' WHERE tenant_id = $1" [ E_WRITE_DENIED ];
    t "update from unfiltered" ~policy:p_all
      "UPDATE orders o SET status = 'x' FROM items i WHERE o.tenant_id = $1 AND \
       i.order_id = o.id"
      [ E_TENANT_MISSING ];
    t "update from filtered" ~policy:p_all
      "UPDATE orders o SET status = 'x' FROM items i WHERE o.tenant_id = $1 AND \
       i.order_id = o.id AND i.tenant_id = $1"
      [] ~binds:b1;
    t "update set expr reads denied" ~policy:p_notes
      "UPDATE notes SET body = secret WHERE tenant_id = $1" [ E_COLUMN_DENIED ];
    t "update set expr denied fn" ~policy:p_all
      "UPDATE orders SET status = md5(status) WHERE tenant_id = $1" [ E_FUNCTION_DENIED ];
    t "update returning star" ~policy:p_all
      "UPDATE orders SET status = 'x' WHERE tenant_id = $1 RETURNING *" [] ~binds:b1;
    t "update set subquery unfiltered" ~policy:p_all
      "UPDATE orders SET status = (SELECT max(n.body) FROM notes n) WHERE tenant_id = $1"
      [ E_TENANT_MISSING ];
    t "insert ok" ~policy:p_all
      "INSERT INTO orders (tenant_id, status) VALUES ($1, 'new')" [] ~binds:b1
      ~kind:Policy.Insert ~tables:[ "app.orders" ];
    t "insert missing tenant column" ~policy:p_all
      "INSERT INTO orders (status) VALUES ('new')" [ E_TENANT_WRITE ];
    t "insert literal tenant in bound mode" ~policy:p_all
      "INSERT INTO orders (tenant_id, status) VALUES ('evil', 'new')" [ E_TENANT_WRITE ];
    t "insert multirow one bad" ~policy:p_all
      "INSERT INTO orders (tenant_id, status) VALUES ($1, 'a'), ('x', 'b')"
      [ E_TENANT_WRITE ];
    t "insert multirow ok" ~policy:p_all
      "INSERT INTO orders (tenant_id, status) VALUES ($1, 'a'), ($1, 'b')" [] ~binds:b1;
    t "insert no column list" ~policy:p_all "INSERT INTO orders VALUES ($1)"
      [ E_WRITE_DENIED; E_TENANT_WRITE; E_PARAM_UNBOUND ];
    t "insert default values tenant table" ~policy:p_all
      "INSERT INTO orders DEFAULT VALUES" [ E_TENANT_WRITE ];
    t "insert default values non-writable" ~policy:p_all
      "INSERT INTO currencies DEFAULT VALUES" [ E_WRITE_DENIED ];
    t "insert select unsupported" ~policy:p_all
      "INSERT INTO orders (tenant_id, status) SELECT tenant_id, status FROM orders WHERE \
       tenant_id = $1"
      [ E_UNSUPPORTED ];
    t "insert on conflict" ~policy:p_all
      "INSERT INTO orders (tenant_id, status) VALUES ($1, 'x') ON CONFLICT DO NOTHING"
      [ E_UNSUPPORTED ];
    t "insert denied function" ~policy:p_all
      "INSERT INTO orders (tenant_id, status) VALUES ($1, md5('x'))" [ E_FUNCTION_DENIED ];
    t "insert literal mode ok" ~policy:p_lit_all
      "INSERT INTO orders (tenant_id, status) VALUES ('acme', 'x')" [];
    t "insert literal mode wrong" ~policy:p_lit_all
      "INSERT INTO orders (tenant_id, status) VALUES ('evil', 'x')" [ E_TENANT_WRITE ];
    t "insert literal mode param" ~policy:p_lit_all
      "INSERT INTO orders (tenant_id, status) VALUES ($1, 'x')"
      [ E_TENANT_WRITE; E_PARAM_UNBOUND ];
    t "insert many context bound" ~policy:p_all ~ctx:ctx_many
      "INSERT INTO orders (tenant_id, status) VALUES ($1, 'x')"
      [ E_TENANT_WRITE; E_PARAM_UNBOUND ];
    t "insert returning" ~policy:p_all
      "INSERT INTO orders (tenant_id, status) VALUES ($1, 'x') RETURNING id" [] ~binds:b1;
    t "insert unknown table" ~policy:p_all "INSERT INTO secrets (a) VALUES (1)"
      [ E_TABLE_DENIED ];
    t "insert items" ~policy:p_all
      "INSERT INTO items (tenant_id, order_id) VALUES ($1, 5)" [] ~binds:b1;
    t "insert values subquery unfiltered" ~policy:p_all
      "INSERT INTO items (tenant_id, order_id) VALUES ($1, (SELECT max(id) FROM orders))"
      [ E_TENANT_MISSING ];
    t "insert short row" ~policy:p_all
      "INSERT INTO orders (status, tenant_id) VALUES ('x')" [ E_TENANT_WRITE ];
    t "insert tenant via expression" ~policy:p_all
      "INSERT INTO orders (tenant_id, status) VALUES (lower($1), 'x')"
      [ E_TENANT_WRITE; E_PARAM_UNBOUND ];
    t "insert insert-denied table" ~policy:p_all
      "INSERT INTO customers (tenant_id, name) VALUES ($1, 'x')" [ E_WRITE_DENIED ]
      ~binds:b1;
    t "dm cte in select-only"
      "WITH d AS (DELETE FROM orders WHERE tenant_id = $1 RETURNING id) SELECT id FROM d"
      [ E_DATA_MODIFYING_CTE ];
    t "dm cte allowed" ~policy:p_all
      "WITH d AS (DELETE FROM orders WHERE tenant_id = $1 RETURNING id) SELECT id FROM d"
      [] ~binds:b1;
    t "dm cte allowed but unfiltered" ~policy:p_all
      "WITH d AS (DELETE FROM orders RETURNING id) SELECT id FROM d" [ E_TENANT_MISSING ];
    t "dm update cte returning star" ~policy:p_all
      "WITH u AS (UPDATE orders SET status = 'x' WHERE tenant_id = $1 RETURNING *) \
       SELECT status FROM u"
      [] ~binds:b1;
    t "dm insert cte in select-only"
      "WITH i AS (INSERT INTO orders (tenant_id, status) VALUES ($1, 'x') RETURNING id) \
       SELECT id FROM i"
      [ E_DATA_MODIFYING_CTE ];
    t "dm cte nested in subquery"
      "SELECT * FROM (WITH d AS (DELETE FROM orders RETURNING id) SELECT id FROM d) s"
      [ E_DATA_MODIFYING_CTE ];
    t "dm cte update kind denied"
      ~policy:(policy ~statements:[ Policy.Select; Policy.Delete ] ())
      "WITH u AS (UPDATE orders SET status = 'x' WHERE tenant_id = $1 RETURNING id) \
       SELECT id FROM u"
      [ E_DATA_MODIFYING_CTE ];
  ]

(* ===================================================================== misc *)
let misc =
  [
    t "collects several violations"
      "SELECT email, pg_sleep(1) FROM customers, secrets WHERE 'x'::regclass IS NULL"
      [
        E_COLUMN_DENIED;
        E_FUNCTION_DENIED;
        E_TABLE_DENIED;
        E_CAST_DENIED;
        E_TENANT_MISSING;
      ];
    t "complex allowed query" ~policy:p_limit
      "WITH recent AS (SELECT o.id, o.customer_id, o.total_cents FROM orders o WHERE \
       o.tenant_id = $1 AND o.created_at > now() - interval '7 days') SELECT c.name, \
       sum(r.total_cents) AS total FROM recent r JOIN customers c ON c.id = \
       r.customer_id AND c.tenant_id = $1 GROUP BY c.name ORDER BY total DESC LIMIT 10"
      [] ~binds:b1;
    t "coalesce greatest least"
      "SELECT coalesce(o.status, 'x'), GREATEST(o.total_cents, 1), LEAST(o.total_cents, \
       2) FROM orders o WHERE o.tenant_id = $1"
      [] ~binds:b1;
    t "row and array constructors" "SELECT ROW(code, name), ARRAY[code] FROM currencies"
      [];
    t "subscript" "SELECT (ARRAY[code])[1] FROM currencies" [];
    t "boolean test" "SELECT code FROM currencies WHERE (rate > 1) IS NOT FALSE" [];
    t "null test" "SELECT code FROM currencies WHERE rate IS NULL" [];
    t "values top-level" "VALUES (1, 'a')" [];
    t "values top-level limit" ~policy:p_limit "VALUES (1, 'a')" [ E_LIMIT_REQUIRED ];
    t "values top-level denied fn" "VALUES (pg_sleep(1))" [ E_FUNCTION_DENIED ];
    t "named window"
      "SELECT row_number() OVER w FROM currencies WINDOW w AS (ORDER BY code)" [];
    t "named window reads denied"
      "SELECT row_number() OVER w FROM customers WHERE tenant_id = $1 WINDOW w AS (ORDER \
       BY ssn)"
      [ E_COLUMN_DENIED ];
    t "distinct" "SELECT DISTINCT code FROM currencies" [];
    t "group by having"
      "SELECT code, count(*) FROM currencies GROUP BY code HAVING count(*) > 1" [];
    t "exists correlated to global"
      "SELECT c.code FROM currencies c WHERE EXISTS (SELECT 1 FROM orders o WHERE \
       o.status = c.code AND o.tenant_id = $1)"
      [] ~binds:b1;
    t "dedupes identical reasons" "SELECT pg_sleep(1), pg_sleep(1)" [ E_FUNCTION_DENIED ];
  ]

let suites =
  [
    ("sql.A.statement_kind", statement_kinds);
    ("sql.B.hygiene", hygiene);
    ("sql.C.limit", limits);
    ("sql.D.tables", tables);
    ("sql.E.columns", columns);
    ("sql.F.functions", functions);
    ("sql.G.operators", operators);
    ("sql.H.casts", casts);
    ("sql.I.joins", joins);
    ("sql.J.params", params);
    ("sql.K.tenancy", tenancy);
    ("sql.K.literal", literal_mode);
    ("sql.LM.writes", writes);
    ("sql.misc", misc);
  ]
