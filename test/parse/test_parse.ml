(* Tests for Haltsql_parse.Pg_parse: libpg_query JSON -> Haltsql_core.Ast. *)
open Haltsql_core
open Ast
module P = Haltsql_parse.Pg_parse

let limits = Policy.default_limits

let big =
  { limits with max_bytes = 10_000_000; max_depth = 10_000_000; max_nodes = 100_000_000 }

let parse ?(limits = limits) sql =
  match P.parse ~limits sql with
  | Ok l -> l
  | Error r ->
      Alcotest.failf "parse failed for %S: %s" sql (Format.asprintf "%a" Reason.pp r)

let one sql =
  match parse sql with
  | [ s ] -> s
  | l -> Alcotest.failf "expected 1 statement for %S, got %d" sql (List.length l)

let sel sql =
  match one sql with
  | Select s -> s
  | s -> Alcotest.failf "expected SELECT for %S, got %s" sql (Ast_debug.stmt s)

let simple sql =
  match (sel sql).body with
  | Simple s -> s
  | _ -> Alcotest.failf "expected simple select for %S" sql

(** first target expression of "SELECT <e>" *)
let e text =
  match (simple ("SELECT " ^ text)).targets with
  | t :: _ -> t.expr
  | [] -> Alcotest.failf "no targets for %S" text

let where sql =
  match (simple sql).where with
  | Some w -> w
  | None -> Alcotest.failf "no WHERE in %S" sql

let from1 sql =
  match (simple sql).from with f :: _ -> f | [] -> Alcotest.failf "no FROM in %S" sql

let fail_expr what x = Alcotest.failf "%s: unexpected %s" what (Ast_debug.expr x)
let fail_from what x = Alcotest.failf "%s: unexpected %s" what (Ast_debug.from x)
let fail_stmt what x = Alcotest.failf "%s: unexpected %s" what (Ast_debug.stmt x)

let err ?(limits = limits) sql =
  match P.parse ~limits sql with
  | Ok l ->
      Alcotest.failf "expected error for %S, got %s" sql
        (String.concat "; " (List.map Ast_debug.stmt l))
  | Error r -> r

let code_is c (r : Reason.t) =
  Alcotest.(check string) "code" (Reason.code_to_string c) (Reason.code_to_string r.code)

let tc name f = Alcotest.test_case name `Quick f
let col n = Column_ref { fields = [ Name n ]; loc = 0 }
let _ = col

(* ------------------------------------------------------------------------ *)
(* Constants *)

let const_cases =
  let c text expected () =
    match e text with
    | Const { value; _ } when value = expected -> ()
    | x -> fail_expr text x
  in
  [
    tc "int" (c "42" (Int "42"));
    tc "int zero" (c "0" (Int "0"));
    tc "negative int" (c "-7" (Int "-7"));
    tc "bigint literal is Float text" (c "12345678901234" (Float "12345678901234"));
    tc "float" (c "1.5" (Float "1.5"));
    tc "float exp" (c "1e10" (Float "1e10"));
    tc "string" (c "'abc'" (String "abc"));
    tc "string escaped quote" (c "'it''s'" (String "it's"));
    tc "empty string" (c "''" (String ""));
    tc "E string" (c "E'a\\nb'" (String "a\nb"));
    tc "dollar quoted" (c "$$it's$$" (String "it's"));
    tc "tagged dollar quoted" (c "$tag$x$$y$tag$" (String "x$$y"));
    tc "U& string" (c "U&'d\\0061t\\+000061'" (String "data"));
    tc "true" (c "true" (Bool true));
    tc "false" (c "false" (Bool false));
    tc "null" (c "NULL" Null);
    tc "bit string" (c "B'101'" (Bit_string "b101"));
    tc "hex string" (c "X'ff'" (Bit_string "xff"));
    tc "const location" (fun () ->
        match e "  42" with
        | Const { loc = 9; _ } -> ()
        | Const { loc; _ } -> Alcotest.failf "loc %d" loc
        | x -> fail_expr "loc" x);
  ]

(* ------------------------------------------------------------------------ *)
(* Column refs, params, identifiers *)

let column_cases =
  let cr text fields () =
    match e text with
    | Column_ref { fields = f; _ } when f = fields -> ()
    | x -> fail_expr text x
  in
  [
    tc "bare column" (cr "a" [ Name "a" ]);
    tc "qualified column" (cr "t.a" [ Name "t"; Name "a" ]);
    tc "3-part column keeps all fields" (cr "s.t.a" [ Name "s"; Name "t"; Name "a" ]);
    tc "4-part column keeps all fields"
      (cr "d.s.t.a" [ Name "d"; Name "s"; Name "t"; Name "a" ]);
    tc "t.*" (cr "t.*" [ Name "t"; Star ]);
    tc "*" (cr "*" [ Star ]);
    tc "unquoted identifiers fold to lower case" (cr "MyCol" [ Name "mycol" ]);
    tc "quoted identifier keeps case" (cr "\"MyCol\"" [ Name "MyCol" ]);
    tc "quoted identifier with spaces" (cr "\"my col\"" [ Name "my col" ]);
    tc "U& identifier decoded" (cr "U&\"\\0075sers\"" [ Name "users" ]);
    tc "U& identifier with UESCAPE" (cr "U&\"!0075sers\" UESCAPE '!'" [ Name "users" ]);
    tc "column location" (fun () ->
        match e "abc" with Column_ref { loc = 7; _ } -> () | x -> fail_expr "loc" x);
    tc "param $1" (fun () ->
        match e "$1" with Param { number = 1; loc = 7 } -> () | x -> fail_expr "$1" x);
    tc "param $12" (fun () ->
        match e "$12" with Param { number = 12; _ } -> () | x -> fail_expr "$12" x);
    tc "quoted relation name" (fun () ->
        match from1 "SELECT 1 FROM \"MyTable\"" with
        | Relation { rel = { schema = None; name = "MyTable" }; _ } -> ()
        | x -> fail_from "rel" x);
    tc "mixed case relation folds" (fun () ->
        match from1 "SELECT 1 FROM Public.Users" with
        | Relation { rel = { schema = Some "public"; name = "users" }; _ } -> ()
        | x -> fail_from "rel" x);
    tc "U& relation name decoded" (fun () ->
        match from1 "SELECT 1 FROM U&\"\\0075sers\"" with
        | Relation { rel = { schema = None; name = "users" }; _ } -> ()
        | x -> fail_from "rel" x);
  ]

(* ------------------------------------------------------------------------ *)
(* A_Expr kinds *)

let aexpr_cases =
  let k text kind name () =
    match e text with
    | A_expr { kind = k; name = n; lexpr = Some _; rexpr = Some _; _ }
      when k = kind && n = name ->
        ()
    | x -> fail_expr text x
  in
  [
    tc "Op =" (k "a = 1" Op [ "=" ]);
    tc "Op +" (k "a + 1" Op [ "+" ]);
    tc "Op ||" (k "a || 'x'" Op [ "||" ]);
    tc "Op ~" (k "a ~ 'x'" Op [ "~" ]);
    tc "Op qualified OPERATOR()" (k "a OPERATOR(pg_catalog.+) b" Op [ "pg_catalog"; "+" ]);
    tc "Op_any array" (k "a = ANY(ARRAY[1,2])" Op_any [ "=" ]);
    tc "Op_all array" (k "a > ALL(ARRAY[1])" Op_all [ ">" ]);
    tc "Distinct" (k "a IS DISTINCT FROM b" Distinct [ "=" ]);
    tc "Not_distinct" (k "a IS NOT DISTINCT FROM b" Not_distinct [ "=" ]);
    tc "Nullif" (k "NULLIF(a, b)" Nullif [ "=" ]);
    tc "In" (k "a IN (1, 2)" In [ "=" ]);
    tc "Not in" (k "a NOT IN (1, 2)" In [ "<>" ]);
    tc "Like" (k "a LIKE 'x%'" Like [ "~~" ]);
    tc "Not like" (k "a NOT LIKE 'x%'" Like [ "!~~" ]);
    tc "Ilike" (k "a ILIKE 'x'" Ilike [ "~~*" ]);
    tc "Not ilike" (k "a NOT ILIKE 'x'" Ilike [ "!~~*" ]);
    tc "Similar" (k "a SIMILAR TO 'x'" Similar [ "~" ]);
    tc "Between" (k "a BETWEEN 1 AND 2" Between [ "BETWEEN" ]);
    tc "Not_between" (k "a NOT BETWEEN 1 AND 2" Not_between [ "NOT BETWEEN" ]);
    tc "Between_sym" (k "a BETWEEN SYMMETRIC 1 AND 2" Between_sym [ "BETWEEN SYMMETRIC" ]);
    tc "Not_between_sym"
      (k "a NOT BETWEEN SYMMETRIC 1 AND 2" Not_between_sym [ "NOT BETWEEN SYMMETRIC" ]);
    tc "prefix operator has no lexpr" (fun () ->
        match e "-a" with
        | A_expr
            { kind = Op; name = [ "-" ]; lexpr = None; rexpr = Some (Column_ref _); _ } ->
            ()
        | x -> fail_expr "-a" x);
    tc "IN list rexpr is a Row of the items" (fun () ->
        match e "a IN (1, 2, 3)" with
        | A_expr { rexpr = Some (Row { args = [ Const _; Const _; Const _ ]; _ }); _ } ->
            ()
        | x -> fail_expr "in list" x);
    tc "BETWEEN bounds are a Row" (fun () ->
        match e "a BETWEEN 1 AND 2" with
        | A_expr
            {
              rexpr =
                Some
                  (Row
                     {
                       args =
                         [ Const { value = Int "1"; _ }; Const { value = Int "2"; _ } ];
                       _;
                     });
              _;
            } ->
            ()
        | x -> fail_expr "between" x);
    tc "LIKE ESCAPE keeps escape as function" (fun () ->
        match e "a LIKE 'x' ESCAPE '!'" with
        | A_expr
            {
              kind = Like;
              rexpr = Some (Func_call { fname = { name = "like_escape"; _ }; _ });
              _;
            } ->
            ()
        | x -> fail_expr "escape" x);
    tc "operator location" (fun () ->
        match e "a = 1" with A_expr { loc = 9; _ } -> () | x -> fail_expr "loc" x);
  ]

(* ------------------------------------------------------------------------ *)
(* Bool, tests, misc expressions *)

let expr_cases =
  [
    tc "AND" (fun () ->
        match e "a AND b AND c" with
        | Bool_expr { op = And; args = [ _; _; _ ]; _ } -> ()
        | x -> fail_expr "and" x);
    tc "OR" (fun () ->
        match e "a OR b" with
        | Bool_expr { op = Or; args = [ _; _ ]; _ } -> ()
        | x -> fail_expr "or" x);
    tc "NOT" (fun () ->
        match e "NOT a" with
        | Bool_expr { op = Not; args = [ _ ]; _ } -> ()
        | x -> fail_expr "not" x);
    tc "IS NULL" (fun () ->
        match e "a IS NULL" with
        | Null_test { is_null = true; _ } -> ()
        | x -> fail_expr "isnull" x);
    tc "IS NOT NULL" (fun () ->
        match e "a IS NOT NULL" with
        | Null_test { is_null = false; _ } -> ()
        | x -> fail_expr "notnull" x);
    tc "ISNULL postfix" (fun () ->
        match e "a ISNULL" with
        | Null_test { is_null = true; _ } -> ()
        | x -> fail_expr "isnull" x);
    tc "IS TRUE" (fun () ->
        match e "a IS TRUE" with
        | Boolean_test { test = "IS_TRUE"; _ } -> ()
        | x -> fail_expr "t" x);
    tc "IS NOT FALSE" (fun () ->
        match e "a IS NOT FALSE" with
        | Boolean_test { test = "IS_NOT_FALSE"; _ } -> ()
        | x -> fail_expr "t" x);
    tc "IS NOT UNKNOWN" (fun () ->
        match e "a IS NOT UNKNOWN" with
        | Boolean_test { test = "IS_NOT_UNKNOWN"; _ } -> ()
        | x -> fail_expr "t" x);
    tc "searched CASE" (fun () ->
        match e "CASE WHEN a THEN 1 WHEN b THEN 2 ELSE 3 END" with
        | Case
            {
              arg = None;
              whens = [ (Column_ref _, Const _); (Column_ref _, Const _) ];
              default = Some (Const _);
              _;
            } ->
            ()
        | x -> fail_expr "case" x);
    tc "simple CASE without ELSE" (fun () ->
        match e "CASE x WHEN 1 THEN 2 END" with
        | Case { arg = Some (Column_ref _); whens = [ _ ]; default = None; _ } -> ()
        | x -> fail_expr "case" x);
    tc "COALESCE" (fun () ->
        match e "COALESCE(a, b, 1)" with
        | Coalesce { args = [ _; _; _ ]; _ } -> ()
        | x -> fail_expr "c" x);
    tc "GREATEST" (fun () ->
        match e "GREATEST(1, 2)" with
        | Min_max { greatest = true; args = [ _; _ ]; _ } -> ()
        | x -> fail_expr "g" x);
    tc "LEAST" (fun () ->
        match e "LEAST(1)" with
        | Min_max { greatest = false; _ } -> ()
        | x -> fail_expr "l" x);
    tc "ROW()" (fun () ->
        match e "ROW(1, 2)" with
        | Row { args = [ _; _ ]; _ } -> ()
        | x -> fail_expr "row" x);
    tc "implicit row" (fun () ->
        match e "(1, 2)" with Row { args = [ _; _ ]; _ } -> () | x -> fail_expr "row" x);
    tc "ARRAY[]" (fun () ->
        match e "ARRAY[1, 2]" with
        | Array { elements = [ _; _ ]; _ } -> ()
        | x -> fail_expr "arr" x);
    tc "nested ARRAY[[..]]" (fun () ->
        match e "ARRAY[[1], [2]]" with
        | Array { elements = [ Array _; Array _ ]; _ } -> ()
        | x -> fail_expr "arr" x);
    tc "field selection (a).b" (fun () ->
        match e "(a).b" with
        | Indirection { arg = Column_ref _; subscripts = []; fields = [ Name "b" ]; _ } ->
            ()
        | x -> fail_expr "ind" x);
    tc "(a).*" (fun () ->
        match e "(a).*" with
        | Indirection { fields = [ Star ]; _ } -> ()
        | x -> fail_expr "ind" x);
    tc "subscript a[1]" (fun () ->
        match e "a[1]" with
        | Indirection
            {
              arg = Column_ref _;
              subscripts = [ Const { value = Int "1"; _ } ];
              fields = [];
              _;
            } ->
            ()
        | x -> fail_expr "ind" x);
    tc "subscript then field (a[1]).b... a[1].b" (fun () ->
        match e "(a[1]).b" with Indirection _ -> () | x -> fail_expr "ind" x);
    tc "array slice is Unsupported" (fun () ->
        match e "a[1:2]" with
        | Unsupported { node = "A_Indices (array slice)"; _ } -> ()
        | x -> fail_expr "slice" x);
    tc "COLLATE" (fun () ->
        match e "x COLLATE \"C\"" with
        | Collate { arg = Column_ref _; collation = [ "C" ]; _ } -> ()
        | x -> fail_expr "coll" x);
    tc "scalar subquery" (fun () ->
        match e "(SELECT 1)" with
        | Sub_link { kind = Expr; testexpr = None; oper = []; _ } -> ()
        | x -> fail_expr "sub" x);
    tc "nested expressions keep structure" (fun () ->
        match e "(a + 1) * 2 > 3 AND NOT b IS NULL" with
        | Bool_expr
            {
              op = And;
              args =
                [
                  A_expr
                    {
                      name = [ ">" ];
                      lexpr =
                        Some
                          (A_expr
                             {
                               name = [ "*" ];
                               lexpr = Some (A_expr { name = [ "+" ]; _ });
                               _;
                             });
                      _;
                    };
                  Bool_expr { op = Not; args = [ Null_test _ ]; _ };
                ];
              _;
            } ->
            ()
        | x -> fail_expr "nested" x);
  ]

let sqlvalue_cases =
  List.map
    (fun (text, op) ->
      tc ("SQLValueFunction " ^ text) (fun () ->
          match e text with
          | Sql_value { op = o; _ } when o = op -> ()
          | x -> fail_expr text x))
    [
      ("CURRENT_DATE", "CURRENT_DATE");
      ("CURRENT_TIME", "CURRENT_TIME");
      ("CURRENT_TIME(2)", "CURRENT_TIME");
      ("CURRENT_TIMESTAMP", "CURRENT_TIMESTAMP");
      ("CURRENT_TIMESTAMP(3)", "CURRENT_TIMESTAMP");
      ("LOCALTIME", "LOCALTIME");
      ("LOCALTIMESTAMP", "LOCALTIMESTAMP");
      ("CURRENT_USER", "CURRENT_USER");
      ("SESSION_USER", "SESSION_USER");
      ("USER", "USER");
      ("CURRENT_ROLE", "CURRENT_ROLE");
      ("CURRENT_CATALOG", "CURRENT_CATALOG");
      ("CURRENT_SCHEMA", "CURRENT_SCHEMA");
    ]

(* ------------------------------------------------------------------------ *)
(* Casts *)

let cast_cases =
  let cast text names bounds () =
    match e text with
    | Type_cast { type_name = { type_names; array_bounds; _ }; _ }
      when type_names = names && array_bounds = bounds ->
        ()
    | x -> fail_expr text x
  in
  [
    tc ":: int" (cast "x::int" [ "pg_catalog"; "int4" ] 0);
    tc "CAST AS text" (cast "CAST(x AS text)" [ "text" ] 0);
    tc "CAST AS varchar(10)[]"
      (cast "CAST(y AS varchar(10)[])" [ "pg_catalog"; "varchar" ] 1);
    tc "::regclass" (cast "'users'::regclass" [ "regclass" ] 0);
    tc "::pg_catalog.regclass"
      (cast "'users'::pg_catalog.regclass" [ "pg_catalog"; "regclass" ] 0);
    tc "::regproc" (cast "'f'::regproc" [ "regproc" ] 0);
    tc "2-dim array" (cast "z::int4[][]" [ "int4" ] 2);
    tc "2-dim array of int" (cast "z::int[][]" [ "pg_catalog"; "int4" ] 2);
    tc "typed literal interval" (cast "interval '1 day'" [ "pg_catalog"; "interval" ] 0);
    tc "typed literal date" (cast "DATE '2024-01-01'" [ "date" ] 0);
    tc "quoted type name keeps case" (cast "x::\"MyType\"" [ "MyType" ] 0);
    tc "numeric(10,2)" (cast "x::numeric(10,2)" [ "pg_catalog"; "numeric" ] 0);
    tc "cast keeps argument" (fun () ->
        match e "'t'::regclass" with
        | Type_cast { arg = Const { value = String "t"; _ }; _ } -> ()
        | x -> fail_expr "arg" x);
    tc "non-constant type modifier is Unsupported" (fun () ->
        match e "x::mytype(a)" with
        | Unsupported { node = "TypeName.typmods"; _ } -> ()
        | x -> fail_expr "typmod" x);
  ]

(* ------------------------------------------------------------------------ *)
(* Functions *)

let func_cases =
  [
    tc "plain call" (fun () ->
        match e "lower(a)" with
        | Func_call
            {
              fname = { schema = None; name = "lower" };
              args = [ Column_ref _ ];
              agg_star = false;
              agg_distinct = false;
              agg_filter = None;
              agg_order = [];
              over = None;
              variadic = false;
              _;
            } ->
            ()
        | x -> fail_expr "f" x);
    tc "schema-qualified call" (fun () ->
        match e "pg_catalog.lower(a)" with
        | Func_call { fname = { schema = Some "pg_catalog"; name = "lower" }; _ } -> ()
        | x -> fail_expr "f" x);
    tc "3-part function name is Unsupported" (fun () ->
        match e "a.b.c(1)" with Unsupported _ -> () | x -> fail_expr "f" x);
    tc "count(*)" (fun () ->
        match e "count(*)" with
        | Func_call { fname = { name = "count"; _ }; agg_star = true; args = []; _ } -> ()
        | x -> fail_expr "f" x);
    tc "count(DISTINCT a) FILTER" (fun () ->
        match e "count(DISTINCT a) FILTER (WHERE b > 1)" with
        | Func_call { agg_distinct = true; agg_filter = Some (A_expr _); _ } -> ()
        | x -> fail_expr "f" x);
    tc "aggregate ORDER BY" (fun () ->
        match e "string_agg(a, ',' ORDER BY b)" with
        | Func_call { agg_order = [ { sort_expr = Column_ref _; _ } ]; _ } -> ()
        | x -> fail_expr "f" x);
    tc "window OVER (PARTITION BY ORDER BY)" (fun () ->
        match e "rank() OVER (PARTITION BY a ORDER BY b DESC)" with
        | Func_call
            {
              over =
                Some { win_name = None; partition_by = [ _ ]; win_order_by = [ _ ]; _ };
              _;
            } ->
            ()
        | x -> fail_expr "f" x);
    tc "OVER named window" (fun () ->
        match e "avg(x) OVER w" with
        | Func_call { over = Some { win_name = Some "w"; partition_by = []; _ }; _ } -> ()
        | x -> fail_expr "f" x);
    tc "frame with constant offset accepted" (fun () ->
        match e "sum(x) OVER (ORDER BY y ROWS BETWEEN 6 PRECEDING AND CURRENT ROW)" with
        | Func_call { over = Some _; _ } -> ()
        | x -> fail_expr "f" x);
    tc "frame with subquery offset is Unsupported" (fun () ->
        match
          e "sum(x) OVER (ORDER BY y ROWS BETWEEN (SELECT 1) PRECEDING AND CURRENT ROW)"
        with
        | Unsupported _ -> ()
        | x -> fail_expr "f" x);
    tc "OVER (w ORDER BY) referencing window is Unsupported" (fun () ->
        match e "sum(x) OVER (w ORDER BY z)" with
        | Unsupported _ -> ()
        | x -> fail_expr "f" x);
    tc "VARIADIC" (fun () ->
        match e "f(VARIADIC ARRAY[1])" with
        | Func_call { variadic = true; _ } -> ()
        | x -> fail_expr "f" x);
    tc "WITHIN GROUP kept as agg_order" (fun () ->
        match e "percentile_cont(0.5) WITHIN GROUP (ORDER BY x)" with
        | Func_call
            {
              fname = { name = "percentile_cont"; _ };
              args = [ Const _ ];
              agg_order = [ _ ];
              _;
            } ->
            ()
        | x -> fail_expr "f" x);
    tc "SQL-syntax function EXTRACT" (fun () ->
        match e "EXTRACT(year FROM d)" with
        | Func_call
            {
              fname = { schema = Some "pg_catalog"; name = "extract" };
              args = [ _; _ ];
              _;
            } ->
            ()
        | x -> fail_expr "f" x);
    tc "dangerous function names preserved" (fun () ->
        match e "pg_sleep(10)" with
        | Func_call { fname = { schema = None; name = "pg_sleep" }; _ } -> ()
        | x -> fail_expr "f" x);
    tc "quoted function name keeps case" (fun () ->
        match e "\"MyFunc\"(1)" with
        | Func_call { fname = { name = "MyFunc"; _ }; _ } -> ()
        | x -> fail_expr "f" x);
    tc "function location" (fun () ->
        match e "lower(a)" with Func_call { loc = 7; _ } -> () | x -> fail_expr "f" x);
    tc "GROUPING() is Unsupported" (fun () ->
        match e "GROUPING(a)" with
        | Unsupported { node = "GroupingFunc"; _ } -> ()
        | x -> fail_expr "f" x);
    tc "XML expression is Unsupported" (fun () ->
        match e "xmlelement(name foo)" with
        | Unsupported { node = "XmlExpr"; _ } -> ()
        | x -> fail_expr "f" x);
    tc "JSON_OBJECT is Unsupported" (fun () ->
        match e "JSON_OBJECT('a': 1)" with Unsupported _ -> () | x -> fail_expr "f" x);
  ]

(* ------------------------------------------------------------------------ *)
(* Sublinks *)

let sublink_cases =
  [
    tc "EXISTS" (fun () ->
        match e "EXISTS (SELECT 1)" with
        | Sub_link { kind = Exists; testexpr = None; _ } -> ()
        | x -> fail_expr "s" x);
    tc "IN (subquery) is ANY with =" (fun () ->
        match e "a IN (SELECT b FROM u)" with
        | Sub_link
            {
              kind = Any;
              testexpr = Some (Column_ref _);
              oper = [ "=" ];
              subselect =
                {
                  body = Simple { from = [ Relation { rel = { name = "u"; _ }; _ } ]; _ };
                  _;
                };
              _;
            } ->
            ()
        | x -> fail_expr "s" x);
    tc "NOT IN (subquery)" (fun () ->
        match e "a NOT IN (SELECT b FROM u)" with
        | Bool_expr { op = Not; args = [ Sub_link { kind = Any; _ } ]; _ } -> ()
        | x -> fail_expr "s" x);
    tc "> ANY (subquery)" (fun () ->
        match e "a > ANY (SELECT 1)" with
        | Sub_link { kind = Any; oper = [ ">" ]; _ } -> ()
        | x -> fail_expr "s" x);
    tc "= SOME (subquery)" (fun () ->
        match e "a = SOME (SELECT 1)" with
        | Sub_link { kind = Any; oper = [ "=" ]; _ } -> ()
        | x -> fail_expr "s" x);
    tc "< ALL (subquery)" (fun () ->
        match e "a < ALL (SELECT 1)" with
        | Sub_link { kind = All; oper = [ "<" ]; _ } -> ()
        | x -> fail_expr "s" x);
    tc "ARRAY(subquery)" (fun () ->
        match e "ARRAY(SELECT 1)" with
        | Sub_link { kind = Array_sublink; _ } -> ()
        | x -> fail_expr "s" x);
    tc "row comparison with scalar subquery" (fun () ->
        (* the raw parser never emits ROWCOMPARE_SUBLINK; it is an A_Expr *)
        match e "(a, b) > (SELECT 1, 2)" with
        | A_expr { lexpr = Some (Row _); rexpr = Some (Sub_link { kind = Expr; _ }); _ }
          ->
            ()
        | x -> fail_expr "s" x);
    tc "sublink location" (fun () ->
        match e "EXISTS (SELECT 1)" with
        | Sub_link { loc = 7; _ } -> ()
        | x -> fail_expr "s" x);
    tc "unsupported inside a subquery bubbles to the sublink" (fun () ->
        match e "EXISTS (SELECT 1 FROM t GROUP BY DISTINCT a)" with
        | Unsupported { node = "SelectStmt.groupDistinct"; _ } -> ()
        | x -> fail_expr "s" x);
  ]

(* ------------------------------------------------------------------------ *)
(* FROM *)

let join_cases =
  let j sql kind natural () =
    match from1 sql with
    | Join { kind = k; natural = n; left = Relation _; right = Relation _; _ }
      when k = kind && n = natural ->
        ()
    | x -> fail_from sql x
  in
  [
    tc "INNER JOIN ON" (j "SELECT 1 FROM a JOIN b ON a.x = b.x" Inner false);
    tc "LEFT JOIN" (j "SELECT 1 FROM a LEFT JOIN b ON true" Left false);
    tc "LEFT OUTER JOIN" (j "SELECT 1 FROM a LEFT OUTER JOIN b ON true" Left false);
    tc "RIGHT JOIN" (j "SELECT 1 FROM a RIGHT JOIN b ON true" Right false);
    tc "FULL JOIN" (j "SELECT 1 FROM a FULL JOIN b ON true" Full false);
    tc "CROSS JOIN" (j "SELECT 1 FROM a CROSS JOIN b" Cross false);
    tc "NATURAL JOIN" (j "SELECT 1 FROM a NATURAL JOIN b" Inner true);
    tc "NATURAL LEFT JOIN" (j "SELECT 1 FROM a NATURAL LEFT JOIN b" Left true);
    tc "JOIN USING" (fun () ->
        match from1 "SELECT 1 FROM a JOIN b USING (x, y)" with
        | Join { kind = Inner; using = [ "x"; "y" ]; quals = None; _ } -> ()
        | x -> fail_from "using" x);
    tc "JOIN ON keeps quals" (fun () ->
        match from1 "SELECT 1 FROM a JOIN b ON a.x = b.x" with
        | Join { quals = Some (A_expr { name = [ "=" ]; _ }); _ } -> ()
        | x -> fail_from "quals" x);
    tc "JOIN ON true is Inner, not Cross" (fun () ->
        match from1 "SELECT 1 FROM a JOIN b ON true" with
        | Join { kind = Inner; quals = Some (Const { value = Bool true; _ }); _ } -> ()
        | x -> fail_from "on true" x);
    tc "joins nest left-deep" (fun () ->
        match from1 "SELECT 1 FROM a JOIN b ON true JOIN c ON true" with
        | Join
            {
              left = Join { left = Relation { rel = { name = "a"; _ }; _ }; _ };
              right = Relation { rel = { name = "c"; _ }; _ };
              _;
            } ->
            ()
        | x -> fail_from "nest" x);
    tc "parenthesized join with alias" (fun () ->
        match from1 "SELECT 1 FROM (a JOIN b ON true) AS j" with
        | Join { alias = Some { aliasname = "j"; _ }; _ } -> ()
        | x -> fail_from "alias" x);
    tc "JOIN USING AS alias is Unsupported_from" (fun () ->
        match from1 "SELECT 1 FROM a JOIN b USING (x) AS j" with
        | Unsupported_from _ -> ()
        | x -> fail_from "using alias" x);
    tc "join location is first relation" (fun () ->
        match from1 "SELECT 1 FROM a JOIN b ON true" with
        | Join { loc = 14; _ } -> ()
        | x -> fail_from "loc" x);
  ]

let from_cases =
  [
    tc "relation with alias and column aliases" (fun () ->
        match from1 "SELECT 1 FROM s.t AS a(x, y)" with
        | Relation
            {
              rel = { schema = Some "s"; name = "t" };
              alias = Some { aliasname = "a"; colnames = [ "x"; "y" ] };
              inh = true;
              loc = 14;
            } ->
            ()
        | x -> fail_from "rel" x);
    tc "ONLY t has inh=false" (fun () ->
        match from1 "SELECT 1 FROM ONLY t" with
        | Relation { inh = false; _ } -> ()
        | x -> fail_from "only" x);
    tc "t * has inh=true" (fun () ->
        match from1 "SELECT 1 FROM t *" with
        | Relation { inh = true; _ } -> ()
        | x -> fail_from "star" x);
    tc "catalog.schema.table is Unsupported_from" (fun () ->
        match from1 "SELECT 1 FROM db.s.t" with
        | Unsupported_from { loc = 14; _ } -> ()
        | x -> fail_from "3-part" x);
    tc "comma FROM list" (fun () ->
        match (simple "SELECT 1 FROM a, b, c").from with
        | [ Relation _; Relation _; Relation _ ] -> ()
        | _ -> Alcotest.fail "from list");
    tc "subquery in FROM" (fun () ->
        match from1 "SELECT * FROM (SELECT a FROM t) AS s" with
        | Subquery
            {
              lateral = false;
              alias = Some { aliasname = "s"; _ };
              query = { body = Simple _; _ };
              _;
            } ->
            ()
        | x -> fail_from "subq" x);
    tc "LATERAL subquery" (fun () ->
        match (simple "SELECT * FROM t, LATERAL (SELECT t.a) s").from with
        | [ Relation _; Subquery { lateral = true; _ } ] -> ()
        | _ -> Alcotest.fail "lateral");
    tc "function in FROM" (fun () ->
        match from1 "SELECT * FROM generate_series(1, 10) AS g(i)" with
        | Function
            {
              lateral = false;
              ordinality = false;
              calls =
                [
                  Func_call
                    { fname = { name = "generate_series"; _ }; args = [ _; _ ]; _ };
                ];
              alias = Some { aliasname = "g"; colnames = [ "i" ] };
              _;
            } ->
            ()
        | x -> fail_from "srf" x);
    tc "function WITH ORDINALITY" (fun () ->
        match from1 "SELECT * FROM unnest(ARRAY[1]) WITH ORDINALITY AS u(v, n)" with
        | Function { ordinality = true; alias = Some { colnames = [ "v"; "n" ]; _ }; _ }
          ->
            ()
        | x -> fail_from "ord" x);
    tc "LATERAL function" (fun () ->
        match (simple "SELECT * FROM t, LATERAL unnest(t.arr) u").from with
        | [ _; Function { lateral = true; _ } ] -> ()
        | _ -> Alcotest.fail "lateral fn");
    tc "ROWS FROM is Unsupported_from" (fun () ->
        match from1 "SELECT * FROM ROWS FROM (f(), g()) r" with
        | Unsupported_from { node = "RangeFunction (ROWS FROM)"; _ } -> ()
        | x -> fail_from "rowsfrom" x);
    tc "column definition list is Unsupported_from" (fun () ->
        match from1 "SELECT * FROM f() AS r(a int)" with
        | Unsupported_from _ -> ()
        | x -> fail_from "coldef" x);
    tc "TABLESAMPLE is Unsupported_from" (fun () ->
        match from1 "SELECT * FROM t TABLESAMPLE SYSTEM (10)" with
        | Unsupported_from { node = "RangeTableSample"; _ } -> ()
        | x -> fail_from "sample" x);
    tc "XMLTABLE is Unsupported_from" (fun () ->
        match from1 "SELECT * FROM XMLTABLE('/a' PASSING x COLUMNS b int)" with
        | Unsupported_from { node = "RangeTableFunc"; _ } -> ()
        | x -> fail_from "xml" x);
    tc "JSON_TABLE is Unsupported_from" (fun () ->
        match
          from1 "SELECT * FROM JSON_TABLE('{}', '$' COLUMNS (a int PATH '$.a')) jt"
        with
        | Unsupported_from _ -> ()
        | x -> fail_from "json" x);
    tc "unsupported subquery in FROM becomes Unsupported_from" (fun () ->
        match from1 "SELECT * FROM (SELECT a FROM t GROUP BY DISTINCT a) s" with
        | Unsupported_from { node = "SelectStmt.groupDistinct"; _ } -> ()
        | x -> fail_from "subq" x);
  ]

(* ------------------------------------------------------------------------ *)
(* SELECT clauses *)

let select_cases =
  [
    tc "targets with aliases" (fun () ->
        match (simple "SELECT a AS x, b y, c FROM t").targets with
        | [
         { alias = Some "x"; target_loc = 7; _ };
         { alias = Some "y"; _ };
         { alias = None; _ };
        ] ->
            ()
        | _ -> Alcotest.fail "aliases");
    tc "quoted alias keeps case" (fun () ->
        match (simple "SELECT a AS \"Total\"").targets with
        | [ { alias = Some "Total"; _ } ] -> ()
        | _ -> Alcotest.fail "alias");
    tc "no DISTINCT" (fun () ->
        Alcotest.(check bool) "none" true ((simple "SELECT a FROM t").distinct = None));
    tc "DISTINCT" (fun () ->
        match (simple "SELECT DISTINCT a FROM t").distinct with
        | Some [] -> ()
        | _ -> Alcotest.fail "distinct");
    tc "DISTINCT ON" (fun () ->
        match (simple "SELECT DISTINCT ON (a, b) a FROM t").distinct with
        | Some [ Column_ref _; Column_ref _ ] -> ()
        | _ -> Alcotest.fail "distinct on");
    tc "WHERE" (fun () ->
        match where "SELECT a FROM t WHERE tenant_id = $1" with
        | A_expr
            {
              lexpr = Some (Column_ref { fields = [ Name "tenant_id" ]; _ });
              rexpr = Some (Param { number = 1; _ });
              _;
            } ->
            ()
        | x -> fail_expr "where" x);
    tc "GROUP BY / HAVING" (fun () ->
        let s = simple "SELECT a, count(*) FROM t GROUP BY a, b HAVING count(*) > 1" in
        match (s.group_by, s.having) with
        | [ Column_ref _; Column_ref _ ], Some (A_expr _) -> ()
        | _ -> Alcotest.fail "group");
    tc "GROUPING SETS is Unsupported" (fun () ->
        match (simple "SELECT a FROM t GROUP BY GROUPING SETS ((a), (b))").group_by with
        | [ Unsupported { node = "GroupingSet"; _ } ] -> ()
        | _ -> Alcotest.fail "grouping sets");
    tc "ROLLUP is Unsupported" (fun () ->
        match (simple "SELECT a FROM t GROUP BY ROLLUP (a)").group_by with
        | [ Unsupported { node = "GroupingSet"; _ } ] -> ()
        | _ -> Alcotest.fail "rollup");
    tc "CUBE is Unsupported" (fun () ->
        match (simple "SELECT a FROM t GROUP BY a, CUBE (b)").group_by with
        | [ Column_ref _; Unsupported { node = "GroupingSet"; _ } ] -> ()
        | _ -> Alcotest.fail "cube");
    tc "GROUP BY () is Unsupported" (fun () ->
        match (simple "SELECT count(*) FROM t GROUP BY ()").group_by with
        | [ Unsupported _ ] -> ()
        | _ -> Alcotest.fail "empty");
    tc "GROUP BY DISTINCT makes the statement unsupported" (fun () ->
        match one "SELECT a FROM t GROUP BY DISTINCT a" with
        | Other { kind = "Unsupported:SelectStmt.groupDistinct"; _ } -> ()
        | x -> fail_stmt "gd" x);
    tc "WINDOW clause" (fun () ->
        match
          (simple "SELECT avg(x) OVER w FROM t WINDOW w AS (PARTITION BY z ORDER BY y)")
            .windows
        with
        | [ { win_name = Some "w"; partition_by = [ _ ]; win_order_by = [ _ ]; _ } ] -> ()
        | _ -> Alcotest.fail "window");
    tc "ORDER BY" (fun () ->
        match (sel "SELECT a FROM t ORDER BY a DESC NULLS LAST, 2").order_by with
        | [
         { sort_expr = Column_ref _; _ }; { sort_expr = Const { value = Int "2"; _ }; _ };
        ] ->
            ()
        | _ -> Alcotest.fail "order");
    tc "ORDER BY USING operator is Unsupported" (fun () ->
        match (sel "SELECT a FROM t ORDER BY a USING <").order_by with
        | [ { sort_expr = Unsupported _; _ } ] -> ()
        | _ -> Alcotest.fail "using");
    tc "LIMIT / OFFSET" (fun () ->
        let s = sel "SELECT a FROM t LIMIT 10 OFFSET 5" in
        match (s.limit_count, s.limit_all, s.limit_offset) with
        | Some (Const { value = Int "10"; _ }), false, Some (Const { value = Int "5"; _ })
          ->
            ()
        | _ -> Alcotest.fail "limit");
    tc "LIMIT ALL" (fun () ->
        let s = sel "SELECT a FROM t LIMIT ALL" in
        match (s.limit_count, s.limit_all) with
        | None, true -> ()
        | _ -> Alcotest.fail "limit all");
    tc "LIMIT NULL is treated like LIMIT ALL" (fun () ->
        let s = sel "SELECT a FROM t LIMIT NULL" in
        match (s.limit_count, s.limit_all) with
        | None, true -> ()
        | _ -> Alcotest.fail "limit null");
    tc "no LIMIT" (fun () ->
        let s = sel "SELECT a FROM t" in
        match (s.limit_count, s.limit_all, s.limit_offset) with
        | None, false, None -> ()
        | _ -> Alcotest.fail "no limit");
    tc "LIMIT $1" (fun () ->
        match (sel "SELECT a FROM t LIMIT $1").limit_count with
        | Some (Param { number = 1; _ }) -> ()
        | _ -> Alcotest.fail "limit param");
    tc "LIMIT expression" (fun () ->
        match (sel "SELECT a FROM t LIMIT 5 + 5").limit_count with
        | Some (A_expr _) -> ()
        | _ -> Alcotest.fail "limit expr");
    tc "FETCH FIRST n ROWS ONLY" (fun () ->
        match (sel "SELECT a FROM t FETCH FIRST 5 ROWS ONLY").limit_count with
        | Some (Const { value = Int "5"; _ }) -> ()
        | _ -> Alcotest.fail "fetch");
    tc "OFFSET n ROWS FETCH NEXT 1 ROW ONLY" (fun () ->
        let s = sel "SELECT a FROM t OFFSET 2 ROWS FETCH NEXT 1 ROW ONLY" in
        match (s.limit_count, s.limit_offset) with
        | Some (Const { value = Int "1"; _ }), Some (Const { value = Int "2"; _ }) -> ()
        | _ -> Alcotest.fail "fetch next");
    tc "FETCH FIRST WITH TIES is unsupported" (fun () ->
        match one "SELECT a FROM t ORDER BY a FETCH FIRST 5 ROWS WITH TIES" with
        | Other { kind = "Unsupported:SelectStmt.limitOption=LIMIT_OPTION_WITH_TIES"; _ }
          ->
            ()
        | x -> fail_stmt "ties" x);
    tc "FOR UPDATE" (fun () ->
        Alcotest.(check (list string))
          "locking" [ "FOR UPDATE" ] (sel "SELECT a FROM t FOR UPDATE").locking);
    tc "FOR SHARE / NO KEY UPDATE / KEY SHARE" (fun () ->
        Alcotest.(check (list string))
          "locking"
          [ "FOR SHARE"; "FOR NO KEY UPDATE"; "FOR KEY SHARE" ]
          (sel "SELECT a FROM t FOR SHARE FOR NO KEY UPDATE FOR KEY SHARE").locking);
    tc "FOR UPDATE OF t NOWAIT" (fun () ->
        Alcotest.(check (list string))
          "locking" [ "FOR UPDATE" ]
          (sel "SELECT a FROM t FOR UPDATE OF t NOWAIT").locking);
    tc "no locking" (fun () ->
        Alcotest.(check (list string)) "locking" [] (sel "SELECT 1").locking);
    tc "SELECT INTO" (fun () ->
        Alcotest.(check bool) "into" true (simple "SELECT a INTO newtab FROM t").into);
    tc "SELECT INTO TEMP" (fun () ->
        Alcotest.(check bool) "into" true (simple "SELECT a INTO TEMP newtab FROM t").into);
    tc "no INTO" (fun () ->
        Alcotest.(check bool) "into" false (simple "SELECT a FROM t").into);
    tc "SELECT without targets" (fun () ->
        match (simple "SELECT FROM t").targets with
        | [] -> ()
        | _ -> Alcotest.fail "empty targets");
    tc "TABLE t" (fun () ->
        match (simple "TABLE t").from with
        | [ Relation { rel = { name = "t"; _ }; _ } ] -> ()
        | _ -> Alcotest.fail "table");
    tc "statement location of first statement is 0" (fun () ->
        Alcotest.(check int) "loc" 0 (sel "SELECT 1").sel_loc);
  ]

(* ------------------------------------------------------------------------ *)
(* Set operations, VALUES, CTEs *)

let setop_cases =
  [
    tc "UNION" (fun () ->
        match (sel "SELECT 1 UNION SELECT 2").body with
        | Set_op
            {
              op = Union;
              all = false;
              larg = { body = Simple _; _ };
              rarg = { body = Simple _; _ };
            } ->
            ()
        | _ -> Alcotest.fail "union");
    tc "UNION ALL" (fun () ->
        match (sel "SELECT 1 UNION ALL SELECT 2").body with
        | Set_op { op = Union; all = true; _ } -> ()
        | _ -> Alcotest.fail "union all");
    tc "INTERSECT" (fun () ->
        match (sel "SELECT 1 INTERSECT SELECT 2").body with
        | Set_op { op = Intersect; _ } -> ()
        | _ -> Alcotest.fail "intersect");
    tc "EXCEPT ALL" (fun () ->
        match (sel "SELECT 1 EXCEPT ALL SELECT 2").body with
        | Set_op { op = Except; all = true; _ } -> ()
        | _ -> Alcotest.fail "except");
    tc "ORDER BY / LIMIT apply on top of the set operation" (fun () ->
        let s =
          sel
            "(SELECT a FROM t UNION SELECT a FROM u) INTERSECT ALL SELECT 3 ORDER BY 1 \
             LIMIT 5 OFFSET 2"
        in
        match s with
        | {
         body =
           Set_op
             {
               op = Intersect;
               all = true;
               larg =
                 { body = Set_op { op = Union; _ }; order_by = []; limit_count = None; _ };
               rarg = { body = Simple _; _ };
             };
         order_by = [ _ ];
         limit_count = Some (Const { value = Int "5"; _ });
         limit_offset = Some _;
         _;
        } ->
            ()
        | _ -> Alcotest.fail "setop limit");
    tc "parenthesized arm keeps its own LIMIT" (fun () ->
        match (sel "(SELECT a FROM t LIMIT 1) UNION SELECT a FROM u").body with
        | Set_op
            { larg = { limit_count = Some _; _ }; rarg = { limit_count = None; _ }; _ } ->
            ()
        | _ -> Alcotest.fail "arm limit");
    tc "VALUES" (fun () ->
        match (sel "VALUES (1, 'a'), (2, 'b')").body with
        | Values
            [
              [ Const { value = Int "1"; _ }; Const { value = String "a"; _ } ]; [ _; _ ];
            ] ->
            ()
        | _ -> Alcotest.fail "values");
    tc "VALUES with ORDER BY LIMIT" (fun () ->
        match sel "VALUES (2), (1) ORDER BY 1 LIMIT 1" with
        | { body = Values [ _; _ ]; order_by = [ _ ]; limit_count = Some _; _ } -> ()
        | _ -> Alcotest.fail "values limit");
    tc "VALUES in FROM" (fun () ->
        match from1 "SELECT * FROM (VALUES (1), (2)) AS v(x)" with
        | Subquery
            {
              query = { body = Values [ [ _ ]; [ _ ] ]; _ };
              alias = Some { colnames = [ "x" ]; _ };
              _;
            } ->
            ()
        | x -> fail_from "values from" x);
    tc "CTE" (fun () ->
        match (sel "WITH c AS (SELECT a FROM t) SELECT * FROM c").with_ with
        | Some
            {
              recursive = false;
              ctes =
                [
                  { cte_name = "c"; cte_colnames = []; cte_query = Select _; cte_loc = 5 };
                ];
              _;
            } ->
            ()
        | _ -> Alcotest.fail "cte");
    tc "CTE reference is a Relation" (fun () ->
        match from1 "WITH c AS (SELECT 1) SELECT * FROM c" with
        | Relation { rel = { schema = None; name = "c" }; _ } -> ()
        | x -> fail_from "cte ref" x);
    tc "multiple CTEs" (fun () ->
        match (sel "WITH a AS (SELECT 1), b AS (SELECT 2) SELECT * FROM a, b").with_ with
        | Some { ctes = [ { cte_name = "a"; _ }; { cte_name = "b"; _ } ]; _ } -> ()
        | _ -> Alcotest.fail "ctes");
    tc "WITH RECURSIVE with column list" (fun () ->
        match
          (sel
             "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < \
              10) SELECT * FROM r")
            .with_
        with
        | Some
            {
              recursive = true;
              ctes =
                [
                  {
                    cte_name = "r";
                    cte_colnames = [ "n" ];
                    cte_query = Select { body = Set_op { op = Union; all = true; _ }; _ };
                    _;
                  };
                ];
              _;
            } ->
            ()
        | _ -> Alcotest.fail "recursive");
    tc "MATERIALIZED / NOT MATERIALIZED accepted" (fun () ->
        match
          (sel
             "WITH a AS MATERIALIZED (SELECT 1), b AS NOT MATERIALIZED (SELECT 2) SELECT \
              1")
            .with_
        with
        | Some { ctes = [ { cte_query = Select _; _ }; { cte_query = Select _; _ } ]; _ }
          ->
            ()
        | _ -> Alcotest.fail "materialized");
    tc "data-modifying CTE: DELETE" (fun () ->
        match
          (sel "WITH d AS (DELETE FROM t WHERE x RETURNING *) SELECT * FROM d").with_
        with
        | Some
            {
              ctes =
                [
                  {
                    cte_query =
                      Delete { del_rel = { name = "t"; _ }; del_returning = [ _ ]; _ };
                    _;
                  };
                ];
              _;
            } ->
            ()
        | _ -> Alcotest.fail "dml cte");
    tc "data-modifying CTE: INSERT" (fun () ->
        match
          (sel "WITH i AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM i").with_
        with
        | Some { ctes = [ { cte_query = Insert _; _ } ]; _ } -> ()
        | _ -> Alcotest.fail "dml cte");
    tc "data-modifying CTE: UPDATE" (fun () ->
        match
          (sel "WITH u AS (UPDATE t SET a = 1 RETURNING *) SELECT * FROM u").with_
        with
        | Some { ctes = [ { cte_query = Update _; _ } ]; _ } -> ()
        | _ -> Alcotest.fail "dml cte");
    tc "CTE SEARCH clause makes the CTE query unsupported" (fun () ->
        match
          (sel
             "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SEARCH DEPTH \
              FIRST BY n SET ord SELECT * FROM r")
            .with_
        with
        | Some { ctes = [ { cte_query = Other { kind; _ }; _ } ]; _ }
          when String.length kind > 12 && String.sub kind 0 12 = "Unsupported:" ->
            ()
        | _ -> Alcotest.fail "search");
    tc "CTE CYCLE clause makes the CTE query unsupported" (fun () ->
        match
          (sel
             "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) CYCLE n SET \
              is_cycle USING path SELECT * FROM r")
            .with_
        with
        | Some { ctes = [ { cte_query = Other _; _ } ]; _ } -> ()
        | _ -> Alcotest.fail "cycle");
    tc "nested CTE inside subquery" (fun () ->
        match from1 "SELECT * FROM (WITH c AS (SELECT 1) SELECT * FROM c) s" with
        | Subquery { query = { with_ = Some { ctes = [ _ ]; _ }; _ }; _ } -> ()
        | x -> fail_from "nested cte" x);
  ]

(* ------------------------------------------------------------------------ *)
(* INSERT / UPDATE / DELETE *)

let dml_cases =
  [
    tc "INSERT VALUES" (fun () ->
        match one "INSERT INTO s.t (a, b) VALUES (1, 2)" with
        | Insert
            {
              ins_rel = { schema = Some "s"; name = "t" };
              ins_alias = None;
              ins_cols = [ "a"; "b" ];
              ins_source = Some { body = Values [ [ _; _ ] ]; _ };
              on_conflict = false;
              ins_returning = [];
              ins_with = None;
              ins_loc = 0;
            } ->
            ()
        | x -> fail_stmt "insert" x);
    tc "INSERT SELECT" (fun () ->
        match one "INSERT INTO t SELECT * FROM u" with
        | Insert
            {
              ins_cols = [];
              ins_source = Some { body = Simple { from = [ Relation _ ]; _ }; _ };
              _;
            } ->
            ()
        | x -> fail_stmt "insert select" x);
    tc "INSERT DEFAULT VALUES" (fun () ->
        match one "INSERT INTO t DEFAULT VALUES" with
        | Insert { ins_source = None; _ } -> ()
        | x -> fail_stmt "default values" x);
    tc "INSERT alias and RETURNING" (fun () ->
        match one "INSERT INTO t AS x (a) VALUES (1) RETURNING id, a AS b" with
        | Insert
            {
              ins_alias = Some { aliasname = "x"; _ };
              ins_returning = [ _; { alias = Some "b"; _ } ];
              _;
            } ->
            ()
        | x -> fail_stmt "returning" x);
    tc "INSERT ON CONFLICT DO NOTHING" (fun () ->
        match one "INSERT INTO t (a) VALUES (1) ON CONFLICT DO NOTHING" with
        | Insert { on_conflict = true; _ } -> ()
        | x -> fail_stmt "on conflict" x);
    tc "INSERT ON CONFLICT (col) DO NOTHING" (fun () ->
        match one "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO NOTHING" with
        | Insert { on_conflict = true; _ } -> ()
        | x -> fail_stmt "on conflict" x);
    tc "INSERT ON CONFLICT DO UPDATE is unsupported" (fun () ->
        match
          one "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = excluded.a"
        with
        | Other { kind = "Unsupported:OnConflictClause.targetList"; _ } -> ()
        | x -> fail_stmt "do update" x);
    tc "INSERT ON CONFLICT ON CONSTRAINT is unsupported" (fun () ->
        match
          one "INSERT INTO t (a) VALUES (1) ON CONFLICT ON CONSTRAINT c DO NOTHING"
        with
        | Other _ -> ()
        | x -> fail_stmt "on constraint" x);
    tc "INSERT DEFAULT in VALUES is Unsupported expr" (fun () ->
        match one "INSERT INTO t (a, b) VALUES (DEFAULT, 1)" with
        | Insert
            {
              ins_source =
                Some
                  {
                    body =
                      Values [ [ Unsupported { node = "SetToDefault"; _ }; Const _ ] ];
                    _;
                  };
              _;
            } ->
            ()
        | x -> fail_stmt "default" x);
    tc "INSERT OVERRIDING is unsupported" (fun () ->
        match one "INSERT INTO t OVERRIDING SYSTEM VALUE VALUES (1)" with
        | Other { kind = "Unsupported:InsertStmt.override=OVERRIDING_SYSTEM_VALUE"; _ } ->
            ()
        | x -> fail_stmt "overriding" x);
    tc "INSERT into column subfield is unsupported" (fun () ->
        match one "INSERT INTO t (a[1]) VALUES (1)" with
        | Other _ -> ()
        | x -> fail_stmt "subfield" x);
    tc "INSERT with WITH" (fun () ->
        match one "WITH s AS (SELECT 1) INSERT INTO t SELECT * FROM s" with
        | Insert { ins_with = Some { ctes = [ _ ]; _ }; _ } -> ()
        | x -> fail_stmt "with insert" x);
    tc "UPDATE" (fun () ->
        match one "UPDATE t SET a = 1, b = b + 1 WHERE id = $1 RETURNING *" with
        | Update
            {
              upd_rel = { name = "t"; _ };
              set = [ ("a", Const _); ("b", A_expr _) ];
              upd_where = Some _;
              upd_returning = [ _ ];
              upd_from = [];
              upd_alias = None;
              _;
            } ->
            ()
        | x -> fail_stmt "update" x);
    tc "UPDATE FROM with alias" (fun () ->
        match one "UPDATE ONLY t AS x SET a = u.a FROM u WHERE x.id = u.id" with
        | Update
            {
              upd_alias = Some { aliasname = "x"; _ };
              upd_from = [ Relation { rel = { name = "u"; _ }; _ } ];
              _;
            } ->
            ()
        | x -> fail_stmt "update from" x);
    tc "UPDATE multi-assign from row" (fun () ->
        match one "UPDATE t SET (a, b) = (1, 2)" with
        | Update
            {
              set =
                [
                  ("a", Const { value = Int "1"; _ }); ("b", Const { value = Int "2"; _ });
                ];
              _;
            } ->
            ()
        | x -> fail_stmt "multi" x);
    tc "UPDATE multi-assign from subquery is Unsupported" (fun () ->
        match one "UPDATE t SET (a, b) = (SELECT 1, 2)" with
        | Update { set = [ ("a", Unsupported _); ("b", Unsupported _) ]; _ } -> ()
        | x -> fail_stmt "multi sub" x);
    tc "UPDATE SET a[1] is Unsupported" (fun () ->
        match one "UPDATE t SET a[1] = 3" with
        | Update { set = [ ("a", Unsupported _) ]; _ } -> ()
        | x -> fail_stmt "subscript" x);
    tc "UPDATE SET DEFAULT is Unsupported" (fun () ->
        match one "UPDATE t SET a = DEFAULT" with
        | Update { set = [ ("a", Unsupported { node = "SetToDefault"; _ }) ]; _ } -> ()
        | x -> fail_stmt "default" x);
    tc "UPDATE WHERE CURRENT OF is Unsupported" (fun () ->
        match one "UPDATE t SET a = 1 WHERE CURRENT OF c" with
        | Update { upd_where = Some (Unsupported { node = "CurrentOfExpr"; _ }); _ } -> ()
        | x -> fail_stmt "current of" x);
    tc "DELETE" (fun () ->
        match one "DELETE FROM t WHERE a = 1" with
        | Delete
            {
              del_rel = { name = "t"; schema = None };
              using = [];
              del_where = Some _;
              del_returning = [];
              _;
            } ->
            ()
        | x -> fail_stmt "delete" x);
    tc "DELETE USING RETURNING" (fun () ->
        match one "DELETE FROM s.t AS x USING u WHERE x.a = u.a RETURNING x.*" with
        | Delete
            {
              del_rel = { schema = Some "s"; name = "t" };
              del_alias = Some { aliasname = "x"; _ };
              using = [ Relation _ ];
              del_returning =
                [ { expr = Column_ref { fields = [ Name "x"; Star ]; _ }; _ } ];
              _;
            } ->
            ()
        | x -> fail_stmt "delete using" x);
    tc "DELETE without WHERE" (fun () ->
        match one "DELETE FROM t" with
        | Delete { del_where = None; _ } -> ()
        | x -> fail_stmt "delete" x);
    tc "DELETE from 3-part name is unsupported" (fun () ->
        match one "DELETE FROM db.s.t" with Other _ -> () | x -> fail_stmt "3part" x);
    tc "MERGE is Other" (fun () ->
        match one "MERGE INTO t USING u ON t.id = u.id WHEN MATCHED THEN DELETE" with
        | Other { kind = "MergeStmt"; _ } -> ()
        | x -> fail_stmt "merge" x);
  ]

(* ------------------------------------------------------------------------ *)
(* EXPLAIN *)

let explain_cases =
  [
    tc "EXPLAIN" (fun () ->
        match one "EXPLAIN SELECT 1" with
        | Explain { analyze = false; options = []; stmt = Select _; loc = 0 } -> ()
        | x -> fail_stmt "explain" x);
    tc "EXPLAIN ANALYZE" (fun () ->
        match one "EXPLAIN ANALYZE SELECT 1" with
        | Explain { analyze = true; options = [ "analyze" ]; _ } -> ()
        | x -> fail_stmt "explain analyze" x);
    tc "EXPLAIN ANALYZE VERBOSE" (fun () ->
        match one "EXPLAIN ANALYZE VERBOSE SELECT 1" with
        | Explain { analyze = true; options = [ "analyze"; "verbose" ]; _ } -> ()
        | x -> fail_stmt "explain analyze verbose" x);
    tc "EXPLAIN (ANALYZE, BUFFERS)" (fun () ->
        match one "EXPLAIN (ANALYZE, BUFFERS) SELECT 1" with
        | Explain { analyze = true; options = [ "analyze"; "buffers" ]; _ } -> ()
        | x -> fail_stmt "explain options" x);
    tc "EXPLAIN (ANALYZE true)" (fun () ->
        match one "EXPLAIN (ANALYZE true) SELECT 1" with
        | Explain { analyze = true; _ } -> ()
        | x -> fail_stmt "analyze true" x);
    tc "EXPLAIN (ANALYZE on)" (fun () ->
        match one "EXPLAIN (ANALYZE on) SELECT 1" with
        | Explain { analyze = true; _ } -> ()
        | x -> fail_stmt "analyze on" x);
    tc "EXPLAIN (ANALYZE 1)" (fun () ->
        match one "EXPLAIN (ANALYZE 1) SELECT 1" with
        | Explain { analyze = true; _ } -> ()
        | x -> fail_stmt "analyze 1" x);
    tc "EXPLAIN (ANALYZE false)" (fun () ->
        match one "EXPLAIN (ANALYZE false, FORMAT json) SELECT 1" with
        | Explain { analyze = false; options = [ "analyze"; "format" ]; _ } -> ()
        | x -> fail_stmt "analyze false" x);
    tc "EXPLAIN (ANALYZE off)" (fun () ->
        match one "EXPLAIN (ANALYZE off) SELECT 1" with
        | Explain { analyze = false; _ } -> ()
        | x -> fail_stmt "analyze off" x);
    tc "EXPLAIN (ANALYZE 0)" (fun () ->
        match one "EXPLAIN (ANALYZE 0) SELECT 1" with
        | Explain { analyze = false; _ } -> ()
        | x -> fail_stmt "analyze 0" x);
    tc "EXPLAIN of DELETE" (fun () ->
        match one "EXPLAIN ANALYZE DELETE FROM t" with
        | Explain { analyze = true; stmt = Delete _; _ } -> ()
        | x -> fail_stmt "explain delete" x);
    tc "EXPLAIN of unsupported select" (fun () ->
        match one "EXPLAIN SELECT a FROM t GROUP BY DISTINCT a" with
        | Explain { stmt = Other _; _ } | Other _ -> ()
        | x -> fail_stmt "explain unsupported" x);
  ]

(* ------------------------------------------------------------------------ *)
(* Other statements *)

let other_cases =
  List.map
    (fun (sql, kind) ->
      tc ("Other " ^ kind) (fun () ->
          match one sql with
          | Other { kind = k; _ } when k = kind -> ()
          | x -> fail_stmt sql x))
    [
      ("CREATE TABLE x (a int)", "CreateStmt");
      ("DROP TABLE x", "DropStmt");
      ("ALTER TABLE x ADD COLUMN b int", "AlterTableStmt");
      ("TRUNCATE x", "TruncateStmt");
      ("DO $$ BEGIN END $$", "DoStmt");
      ("CALL p()", "CallStmt");
      ("COPY t TO STDOUT", "CopyStmt");
      ("SET search_path = evil", "VariableSetStmt");
      ("SHOW search_path", "VariableShowStmt");
      ("RESET ALL", "VariableSetStmt");
      ("LOCK TABLE t", "LockStmt");
      ("BEGIN", "TransactionStmt");
      ("COMMIT", "TransactionStmt");
      ("PREPARE p AS SELECT 1", "PrepareStmt");
      ("EXECUTE p", "ExecuteStmt");
      ("DEALLOCATE p", "DeallocateStmt");
      ("GRANT SELECT ON t TO u", "GrantStmt");
      ("CREATE FUNCTION f() RETURNS int AS 'select 1' LANGUAGE sql", "CreateFunctionStmt");
      ("VACUUM t", "VacuumStmt");
      ("LISTEN c", "ListenStmt");
      ("NOTIFY c", "NotifyStmt");
      ("CREATE VIEW v AS SELECT 1", "ViewStmt");
      ("CREATE TABLE x AS SELECT 1", "CreateTableAsStmt");
      ("DECLARE c CURSOR FOR SELECT 1", "DeclareCursorStmt");
      ("DISCARD ALL", "DiscardStmt");
    ]

(* ------------------------------------------------------------------------ *)
(* Multi-statement, empty, comments, locations *)

let multi_cases =
  [
    tc "two statements" (fun () ->
        match parse "SELECT 1; DROP TABLE x" with
        | [ Select { sel_loc = 0; _ }; Other { kind = "DropStmt"; loc = 9 } ] -> ()
        | l -> Alcotest.failf "got %s" (String.concat "; " (List.map Ast_debug.stmt l)));
    tc "three statements with locations" (fun () ->
        Alcotest.(check (list int))
          "locs" [ 0; 9; 19 ]
          (List.map stmt_loc (parse "SELECT 1; SELECT 2; SELECT 3")));
    tc "trailing semicolon" (fun () ->
        Alcotest.(check int) "n" 1 (List.length (parse "SELECT 1;")));
    tc "empty string" (fun () -> Alcotest.(check int) "n" 0 (List.length (parse "")));
    tc "whitespace only" (fun () ->
        Alcotest.(check int) "n" 0 (List.length (parse "  \n\t ")));
    tc "comment only" (fun () ->
        Alcotest.(check int) "n" 0 (List.length (parse "-- nothing\n/* here */")));
    tc "semicolons only" (fun () ->
        Alcotest.(check int) "n" 0 (List.length (parse ";;;")));
    tc "comments around statement" (fun () ->
        match parse "/* a */ SELECT 1 -- b\n" with
        | [ Select _ ] -> ()
        | _ -> Alcotest.fail "comments");
    tc "nested block comment" (fun () ->
        match parse "/* a /* nested */ still */ SELECT 1" with
        | [ Select _ ] -> ()
        | _ -> Alcotest.fail "nested comment");
    tc "semicolon in string is not a separator" (fun () ->
        match e "'a; DROP TABLE x'" with
        | Const { value = String "a; DROP TABLE x"; _ } -> ()
        | x -> fail_expr "str" x);
    tc "semicolon in dollar quote is not a separator" (fun () ->
        Alcotest.(check int) "n" 1 (List.length (parse "SELECT $q$; DROP TABLE x$q$")));
    tc "semicolon in comment is not a separator" (fun () ->
        Alcotest.(check int) "n" 1 (List.length (parse "SELECT 1 /* ; DROP TABLE x */")));
    tc "second statement expression locations are absolute" (fun () ->
        match parse "SELECT 1; SELECT abc" with
        | [
         _;
         Select
           {
             body = Simple { targets = [ { expr = Column_ref { loc = 17; _ }; _ } ]; _ };
             sel_loc = 9;
             _;
           };
        ] ->
            ()
        | _ -> Alcotest.fail "abs loc");
  ]

(* ------------------------------------------------------------------------ *)
(* Errors *)

let error_cases =
  [
    tc "syntax error is E_PARSE with location" (fun () ->
        let r = err "SELECT FROM WHERE" in
        code_is E_PARSE r;
        Alcotest.(check (option int)) "loc" (Some 12) r.loc);
    tc "error at end of input" (fun () ->
        let r = err "SELECT a FROM" in
        code_is E_PARSE r;
        Alcotest.(check (option int)) "loc" (Some 13) r.loc);
    tc "error message mentions token" (fun () ->
        let r = err "SELEKT 1" in
        code_is E_PARSE r;
        Alcotest.(check bool) "msg" true (String.length r.message > 0);
        Alcotest.(check (option int)) "loc" (Some 0) r.loc);
    tc "unterminated string" (fun () -> code_is E_PARSE (err "SELECT 'abc"));
    tc "unterminated quoted identifier" (fun () -> code_is E_PARSE (err "SELECT \"abc"));
    tc "unterminated comment" (fun () -> code_is E_PARSE (err "SELECT 1 /* x"));
    tc "unterminated dollar quote" (fun () -> code_is E_PARSE (err "SELECT $$abc"));
    tc "error in second statement" (fun () ->
        let r = err "SELECT 1; SELECT FROM WHERE" in
        code_is E_PARSE r;
        Alcotest.(check (option int)) "loc" (Some 22) r.loc);
    tc "NUL byte rejected" (fun () -> code_is E_PARSE (err "SELECT 1\000; DROP TABLE x"));
    tc "invalid U& escape" (fun () -> code_is E_PARSE (err "SELECT U&\"\\zzzz\""));
    tc "reason rule is parse" (fun () ->
        Alcotest.(check string) "rule" "parse" (err "SELECT (").rule);
  ]

(* ------------------------------------------------------------------------ *)
(* Limits and robustness *)

let rep n s = String.concat "" (List.init n (fun _ -> s))

let limit_cases =
  [
    tc "max_bytes enforced" (fun () ->
        let r = err ~limits:{ limits with max_bytes = 10 } "SELECT 12345" in
        code_is E_LIMIT r);
    tc "max_bytes boundary accepted" (fun () ->
        Alcotest.(check int)
          "n" 1
          (List.length (parse ~limits:{ limits with max_bytes = 8 } "SELECT 1")));
    tc "max_bytes checked before parsing (garbage)" (fun () ->
        code_is E_LIMIT (err ~limits:{ limits with max_bytes = 3 } "#### not sql"));
    tc "max_depth enforced" (fun () ->
        code_is E_LIMIT
          (err ~limits:{ limits with max_depth = 5 }
             ("SELECT " ^ rep 10 "(" ^ "1" ^ rep 10 "+1)")));
    tc "max_depth default allows ordinary queries" (fun () ->
        ignore
          (one
             "SELECT a, b FROM t JOIN u ON t.id = u.id WHERE a IN (SELECT x FROM v WHERE \
              y = (SELECT max(z) FROM w WHERE w.k = v.k)) ORDER BY a LIMIT 10"));
    tc "max_nodes enforced" (fun () ->
        code_is E_LIMIT
          (err
             ~limits:{ limits with max_nodes = 50 }
             ("SELECT a FROM t WHERE a IN ("
             ^ String.concat "," (List.init 100 string_of_int)
             ^ ")")));
    tc "max_nodes allows large IN list under default" (fun () ->
        match
          where
            ("SELECT a FROM t WHERE a IN ("
            ^ String.concat "," (List.init 1000 string_of_int)
            ^ ")")
        with
        | A_expr { kind = In; rexpr = Some (Row { args; _ }); _ } ->
            Alcotest.(check int) "items" 1000 (List.length args)
        | x -> fail_expr "in" x);
    tc "10k nested parentheses never crash" (fun () ->
        let sql = "SELECT " ^ rep 10_000 "(" ^ "1" ^ rep 10_000 ")" in
        match P.parse ~limits:big sql with
        | Ok _ -> ()
        | Error r -> (
            match r.code with E_LIMIT | E_PARSE -> () | _ -> Alcotest.fail "code"));
    tc "100k nested parentheses rejected with E_LIMIT" (fun () ->
        code_is E_LIMIT
          (err ~limits:big ("SELECT " ^ rep 100_000 "(" ^ "1" ^ rep 100_000 ")")));
    tc "deep nesting under default limits is E_LIMIT" (fun () ->
        code_is E_LIMIT (err ("SELECT " ^ rep 1000 "(" ^ "1" ^ rep 1000 "+1)")));
    tc "100k-deep operator chain in a domain does not crash" (fun () ->
        let sql = "SELECT 1" ^ rep 100_000 "+1" in
        let d = Domain.spawn (fun () -> P.parse ~limits:big sql) in
        match Domain.join d with
        | Ok [ Select { body = Simple { targets = [ { expr = A_expr _; _ } ]; _ }; _ } ]
          ->
            ()
        | Ok _ -> Alcotest.fail "shape"
        | Error r -> Alcotest.failf "error %s" r.message);
    tc "100k-deep chain under default limits is E_LIMIT in a domain" (fun () ->
        let sql = "SELECT 1" ^ rep 100_000 "+1" in
        let d =
          Domain.spawn (fun () ->
              P.parse ~limits:{ limits with max_bytes = 10_000_000 } sql)
        in
        match Domain.join d with
        | Error r -> code_is E_LIMIT r
        | Ok _ -> Alcotest.fail "expected E_LIMIT");
    tc "20k UNION chain in a domain" (fun () ->
        let sql = "SELECT 1" ^ rep 20_000 " UNION ALL SELECT 1" in
        let d = Domain.spawn (fun () -> P.parse ~limits:big sql) in
        match Domain.join d with
        | Ok [ Select { body = Set_op _; _ } ] -> ()
        | _ -> Alcotest.fail "union chain");
    tc "50k JOIN chain in a domain" (fun () ->
        let sql = "SELECT 1 FROM a" ^ rep 50_000 " JOIN a ON true" in
        let d = Domain.spawn (fun () -> P.parse ~limits:big sql) in
        match Domain.join d with
        | Ok [ Select { body = Simple { from = [ Join _ ]; _ }; _ } ] -> ()
        | _ -> Alcotest.fail "join chain");
    tc "deep CASE nesting fails cleanly" (fun () ->
        let sql = "SELECT " ^ rep 5000 "CASE WHEN true THEN " ^ "1" ^ rep 5000 " END" in
        match P.parse ~limits:big sql with
        | Ok _ -> ()
        | Error r -> (
            match r.code with E_PARSE | E_LIMIT -> () | _ -> Alcotest.fail "code"));
    tc "parallel parsing from 4 domains" (fun () ->
        let work i () =
          List.init 200 (fun j ->
              match
                P.parse ~limits (Printf.sprintf "SELECT a%d FROM t WHERE x = %d" i j)
              with
              | Ok
                  [
                    Select
                      {
                        body =
                          Simple
                            {
                              targets =
                                [ { expr = Column_ref { fields = [ Name n ]; _ }; _ } ];
                              _;
                            };
                        _;
                      };
                  ] ->
                  n = Printf.sprintf "a%d" i
              | _ -> false)
          |> List.for_all Fun.id
        in
        let ds = List.init 4 (fun i -> Domain.spawn (work i)) in
        Alcotest.(check bool) "all ok" true (List.for_all Domain.join ds));
    tc "random byte strings never raise" (fun () ->
        let st = Random.State.make [| 42 |] in
        for _ = 1 to 3000 do
          let n = Random.State.int st 64 in
          let s = String.init n (fun _ -> Char.chr (Random.State.int st 256)) in
          match P.parse ~limits s with Ok _ | Error _ -> ()
        done);
    tc "random SQL-ish token soup never raises" (fun () ->
        let toks =
          [|
            "SELECT";
            "FROM";
            "WHERE";
            "(";
            ")";
            ",";
            "a";
            "t";
            "1";
            "'x'";
            "=";
            "AND";
            "OR";
            "JOIN";
            "ON";
            "UNION";
            "WITH";
            "AS";
            "IN";
            "::";
            "int";
            "*";
            ".";
            ";";
            "LIMIT";
            "ALL";
            "$1";
            "CASE";
            "WHEN";
            "THEN";
            "END";
            "NOT";
            "NULL";
            "IS";
            "[";
            "]";
            "ARRAY";
            "OVER";
            "GROUP";
            "BY";
            "ORDER";
            "VALUES";
            "INSERT";
            "INTO";
            "UPDATE";
            "SET";
            "DELETE";
            "RETURNING";
            "EXPLAIN";
            "LATERAL";
            "EXISTS";
            "DISTINCT";
            "\"";
            "$$";
            "--";
            "/*";
          |]
        in
        let st = Random.State.make [| 7 |] in
        for _ = 1 to 3000 do
          let n = Random.State.int st 30 in
          let s =
            String.concat " "
              (List.init n (fun _ -> toks.(Random.State.int st (Array.length toks))))
          in
          match P.parse ~limits s with Ok _ | Error _ -> ()
        done);
    tc "random mutations of valid queries never raise" (fun () ->
        let base =
          "WITH c AS (SELECT a, count(*) FROM t WHERE b IN (1,2) GROUP BY a) SELECT * \
           FROM c JOIN u USING (a) WHERE x::int > ANY(ARRAY[1]) ORDER BY 1 LIMIT 10"
        in
        let st = Random.State.make [| 99 |] in
        for _ = 1 to 3000 do
          let b = Bytes.of_string base in
          for _ = 1 to 1 + Random.State.int st 4 do
            Bytes.set b
              (Random.State.int st (Bytes.length b))
              (Char.chr (32 + Random.State.int st 95))
          done;
          match P.parse ~limits (Bytes.to_string b) with Ok _ | Error _ -> ()
        done);
  ]

(* ------------------------------------------------------------------------ *)
(* Fingerprint and version *)

let misc_cases =
  [
    tc "postgres_version is 17.x" (fun () ->
        Alcotest.(check bool)
          "17" true
          (String.length P.postgres_version >= 2
          && String.sub P.postgres_version 0 3 = "17."));
    tc "fingerprint equal modulo literals" (fun () ->
        match
          ( P.fingerprint "SELECT a FROM t WHERE b = 1",
            P.fingerprint "SELECT a FROM t WHERE b = 2" )
        with
        | Some x, Some y -> Alcotest.(check string) "fp" x y
        | _ -> Alcotest.fail "no fingerprint");
    tc "fingerprint differs for different queries" (fun () ->
        match (P.fingerprint "SELECT a FROM t", P.fingerprint "SELECT b FROM t") with
        | Some x, Some y -> Alcotest.(check bool) "differ" true (x <> y)
        | _ -> Alcotest.fail "no fingerprint");
    tc "fingerprint of invalid SQL is None" (fun () ->
        Alcotest.(check (option string)) "none" None (P.fingerprint "SELECT FROM WHERE"));
    tc "fingerprint never raises on garbage" (fun () ->
        ignore (P.fingerprint "\000\255(((("));
  ]

(* ------------------------------------------------------------------------ *)
(* Adversarial shapes from the threat model *)

let attack_cases =
  [
    tc "statement smuggling yields two statements" (fun () ->
        Alcotest.(check int)
          "n" 2
          (List.length (parse "SELECT * FROM t WHERE a = 1; DELETE FROM t")));
    tc "OR 1=1 kept as Bool_expr" (fun () ->
        match where "SELECT * FROM t WHERE tenant_id = 'a' OR 1 = 1" with
        | Bool_expr { op = Or; args = [ A_expr _; A_expr _ ]; _ } -> ()
        | x -> fail_expr "or" x);
    tc "set_config call visible" (fun () ->
        match e "set_config('search_path', 'evil', false)" with
        | Func_call
            {
              fname = { name = "set_config"; _ };
              args = [ _; _; Const { value = Bool false; _ } ];
              _;
            } ->
            ()
        | x -> fail_expr "set_config" x);
    tc "pg_catalog relation visible" (fun () ->
        match from1 "SELECT * FROM pg_catalog.pg_shadow" with
        | Relation { rel = { schema = Some "pg_catalog"; name = "pg_shadow" }; _ } -> ()
        | x -> fail_from "catalog" x);
    tc "information_schema relation visible" (fun () ->
        match from1 "SELECT * FROM information_schema.tables" with
        | Relation { rel = { schema = Some "information_schema"; name = "tables" }; _ } ->
            ()
        | x -> fail_from "info" x);
    tc "regclass cast inside WHERE visible" (fun () ->
        match where "SELECT 1 WHERE 'secret'::regclass IS NOT NULL" with
        | Null_test
            { arg = Type_cast { type_name = { type_names = [ "regclass" ]; _ }; _ }; _ }
          ->
            ()
        | x -> fail_expr "regclass" x);
    tc "dblink in FROM visible" (fun () ->
        match from1 "SELECT * FROM dblink('host=x', 'select 1') AS r(a int)" with
        | Unsupported_from _ -> ()
        | x -> fail_from "dblink" x);
    tc "UNION branch without filter is visible" (fun () ->
        match (sel "SELECT a FROM t WHERE tenant_id = 1 UNION SELECT a FROM t").body with
        | Set_op
            {
              larg = { body = Simple { where = Some _; _ }; _ };
              rarg = { body = Simple { where = None; _ }; _ };
              _;
            } ->
            ()
        | _ -> Alcotest.fail "union branch");
    tc "nextval in subquery visible" (fun () ->
        match e "(SELECT nextval('s'))" with
        | Sub_link
            {
              subselect =
                {
                  body =
                    Simple
                      {
                        targets =
                          [
                            { expr = Func_call { fname = { name = "nextval"; _ }; _ }; _ };
                          ];
                        _;
                      };
                  _;
                };
              _;
            } ->
            ()
        | x -> fail_expr "nextval" x);
    tc "quoted keyword identifier" (fun () ->
        match e "\"select\"" with
        | Column_ref { fields = [ Name "select" ]; _ } -> ()
        | x -> fail_expr "kw" x);
  ]

let () =
  Alcotest.run "pg_parse"
    [
      ("constants", const_cases);
      ("columns", column_cases);
      ("a_expr", aexpr_cases);
      ("expressions", expr_cases);
      ("sql_value", sqlvalue_cases);
      ("casts", cast_cases);
      ("functions", func_cases);
      ("sublinks", sublink_cases);
      ("joins", join_cases);
      ("from", from_cases);
      ("select", select_cases);
      ("setops_values_ctes", setop_cases);
      ("dml", dml_cases);
      ("explain", explain_cases);
      ("other", other_cases);
      ("multi", multi_cases);
      ("errors", error_cases);
      ("limits", limit_cases);
      ("misc", misc_cases);
      ("attacks", attack_cases);
    ]
