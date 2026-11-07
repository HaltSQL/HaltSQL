(* Hand-built AST tests: independent of the parser, and covering AST shapes
   the parser rarely or never produces (fail-closed handling). *)

open Haltsql_core
open Ast
open Helpers
open Reason

let t ?(policy = default_policy) ?(ctx = ctx) ?binds ?kind name stmt expect =
  Alcotest.test_case name `Quick (fun () ->
      let a = A.analyze policy ctx stmt in
      check_analysis ?binds ~expect a;
      match kind with
      | Some k ->
          if a.statement_kind <> Some k then Alcotest.fail "unexpected statement_kind"
      | None -> ())

let s x = Select x
let from_orders_where w = sel ~from:[ rel "orders" ] ~where:w [ tgt (c "id") ]
let b1 = [ (1, Context.One "acme") ]

let p_all =
  policy ~statements:[ Policy.Select; Policy.Insert; Policy.Update; Policy.Delete ] ()

let ins ?(cols = [ "tenant_id"; "status" ]) ?(on_conflict = false) rows =
  Insert
    {
      ins_with = None;
      ins_rel = { schema = None; name = "orders" };
      ins_alias = None;
      ins_cols = cols;
      ins_source =
        Some
          {
            with_ = None;
            body = Values rows;
            order_by = [];
            limit_count = None;
            limit_all = false;
            limit_offset = None;
            locking = [];
            sel_loc = -1;
          };
      on_conflict;
      ins_returning = [];
      ins_loc = -1;
    }

let unsup n = Unsupported { node = n; loc = 3 }

let cases =
  [
    t "simple tenant proof"
      (s (from_orders_where (eq (c "tenant_id") (param 1))))
      [] ~binds:b1 ~kind:Policy.Select;
    t "missing proof"
      (s (sel ~from:[ rel "orders" ] [ tgt (c "id") ]))
      [ E_TENANT_MISSING ];
    t "or breaks proof"
      (s (from_orders_where (or_ [ eq (c "tenant_id") (param 1); eq (int 1) (int 1) ])))
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "not breaks proof"
      (s (from_orders_where (not_ (eq (c "tenant_id") (param 1)))))
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "nested and"
      (s
         (from_orders_where
            (and_ [ and_ [ eq (c "status") (str "x"); eq (c "tenant_id") (param 1) ] ])))
      [] ~binds:b1;
    t "unsupported expression node" (s (sel [ tgt (unsup "XmlExpr") ])) [ E_UNSUPPORTED ];
    t "unsupported in where of tenant query"
      (s
         (from_orders_where
            (and_ [ eq (c "tenant_id") (param 1); unsup "JsonIsPredicate" ])))
      [ E_UNSUPPORTED ] ~binds:b1;
    t "other sublink"
      (s
         (sel
            [
              tgt
                (Sub_link
                   {
                     kind = Other_sublink "ROWCOMPARE";
                     testexpr = None;
                     oper = [];
                     subselect = sel [ tgt (int 1) ];
                     loc = -1;
                   });
            ]))
      [ E_UNSUPPORTED ];
    t "unsupported from"
      (s
         (sel
            ~from:[ Unsupported_from { node = "RangeTableFunc"; loc = -1 } ]
            [ tgt (int 1) ]))
      [ E_UNSUPPORTED ];
    t "other statement" (Other { kind = "CreateStmt"; loc = 0 }) [ E_STATEMENT_KIND ];
    t "other unsupported marker"
      (Other { kind = "Unsupported:MergeStmt"; loc = 0 })
      [ E_UNSUPPORTED ];
    t "unsupported marker in cte"
      (s
         (sel
            ~with_:
              (with_
                 [
                   cte "x" (Other { kind = "Unsupported:ON CONFLICT DO UPDATE"; loc = 0 });
                 ])
            [ tgt (int 1) ]))
      [ E_UNSUPPORTED ];
    t "explain inside cte"
      (s
         (sel
            ~with_:
              (with_
                 [
                   cte "x"
                     (Explain
                        {
                          analyze = false;
                          options = [];
                          stmt = Select (sel [ tgt (int 1) ]);
                          loc = 0;
                        });
                 ])
            [ tgt (int 1) ]))
      [ E_UNSUPPORTED ];
    t "explain analyze"
      ~policy:(policy ~allow_explain:true ())
      (Explain
         {
           analyze = true;
           options = [ "analyze" ];
           stmt = Select (sel [ tgt (int 1) ]);
           loc = 0;
         })
      [ E_STATEMENT_KIND ];
    t "explain plain"
      ~policy:(policy ~allow_explain:true ())
      (Explain
         {
           analyze = false;
           options = [ "verbose" ];
           stmt = Select (sel [ tgt (int 1) ]);
           loc = 0;
         })
      [] ~kind:Policy.Select;
    t "sql value svfop current_date"
      (s (sel [ tgt (Sql_value { op = "SVFOP_CURRENT_DATE"; loc = -1 }) ]))
      [];
    t "sql value svfop current_timestamp_n"
      (s (sel [ tgt (Sql_value { op = "SVFOP_CURRENT_TIMESTAMP_N"; loc = -1 }) ]))
      [];
    t "sql value svfop current_user"
      (s (sel [ tgt (Sql_value { op = "SVFOP_CURRENT_USER"; loc = -1 }) ]))
      [ E_FUNCTION_DENIED ];
    t "sql value lowercase session_user"
      (s (sel [ tgt (Sql_value { op = "session_user"; loc = -1 }) ]))
      [ E_FUNCTION_DENIED ];
    t "star in the middle of a column ref"
      (s
         (sel
            ~from:[ rel "currencies" ]
            [ tgt (Column_ref { fields = [ Star; Name "code" ]; loc = -1 }) ]))
      [ E_COLUMN_UNRESOLVED ];
    t "four-part column ref"
      (s
         (sel
            ~from:[ rel "currencies" ]
            [ tgt (col [ "db"; "app"; "currencies"; "code" ]) ]))
      [ E_COLUMN_UNRESOLVED ];
    t "empty column ref"
      (s (sel ~from:[ rel "currencies" ] [ tgt (Column_ref { fields = []; loc = -1 }) ]))
      [ E_COLUMN_UNRESOLVED ];
    t "aliased join"
      (s
         (sel
            ~from:
              [
                Join
                  {
                    kind = Inner;
                    natural = false;
                    left = rel "currencies" ~as_:"a";
                    right = rel "currencies" ~as_:"b";
                    quals = Some (Const { value = Bool true; loc = -1 });
                    using = [];
                    alias = alias "j";
                    loc = -1;
                  };
              ]
            [ tgt (c2 "a" "code") ]))
      [ E_UNSUPPORTED ];
    t "operator with non-pg_catalog schema"
      (s
         (sel
            [
              tgt
                (A_expr
                   {
                     kind = Op;
                     name = [ "evil"; "=" ];
                     lexpr = Some (int 1);
                     rexpr = Some (int 1);
                     loc = -1;
                   });
            ]))
      [ E_OPERATOR_DENIED ];
    t "empty operator name"
      (s
         (sel
            [
              tgt
                (A_expr
                   {
                     kind = Op;
                     name = [];
                     lexpr = Some (int 1);
                     rexpr = Some (int 1);
                     loc = -1;
                   });
            ]))
      [ E_OPERATOR_DENIED ];
    t "qualified tenant equals is not = when schema evil"
      (s
         (from_orders_where
            (A_expr
               {
                 kind = Op;
                 name = [ "evil"; "=" ];
                 lexpr = Some (c "tenant_id");
                 rexpr = Some (param 1);
                 loc = -1;
               })))
      [ E_OPERATOR_DENIED; E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "denied cast with array bounds"
      (s
         (sel
            [
              tgt
                (Type_cast
                   {
                     arg = str "x";
                     type_name =
                       {
                         type_names = [ "pg_catalog"; "regclass" ];
                         array_bounds = 1;
                         type_loc = -1;
                       };
                     loc = -1;
                   });
            ]))
      [ E_CAST_DENIED ];
    t "limit as typecast int" ~policy:(policy ~require_limit:10 ())
      (s
         {
           (sel ~from:[ rel "currencies" ] [ tgt (c "code") ]) with
           limit_count = Some (cast (int 5) [ "pg_catalog"; "int8" ]);
         })
      [];
    t "limit as float const (big int)" ~policy:(policy ~require_limit:10 ())
      (s
         {
           (sel ~from:[ rel "currencies" ] [ tgt (c "code") ]) with
           limit_count = Some (Const { value = Float "12345678901234"; loc = -1 });
         })
      [ E_LIMIT_TOO_HIGH ];
    t "limit_all flag" ~policy:(policy ~require_limit:10 ())
      (s { (sel ~from:[ rel "currencies" ] [ tgt (c "code") ]) with limit_all = true })
      [ E_LIMIT_REQUIRED ];
    t "union with limit on top record" ~policy:(policy ~require_limit:10 ())
      (s
         (union ~limit:5
            (sel ~from:[ rel "currencies" ] [ tgt (c "code") ])
            (sel ~from:[ rel "currencies" ] [ tgt (c "code") ])))
      [];
    t "into flag in subquery"
      (s (sel ~from:[ subq ~as_:"x" (sel ~into:true [ tgt (int 1) ]) ] [ tgt (int 1) ]))
      [ E_SELECT_INTO ];
    t "locking in union branch"
      (s
         (union
            (sel ~locking:[ "FOR KEY SHARE" ]
               ~from:[ rel "currencies" ]
               [ tgt (c "code") ])
            (sel [ tgt (int 1) ])))
      [ E_LOCKING_CLAUSE ];
    t "cte shadow"
      (s
         (sel
            ~with_:(with_ [ cte "orders" (Select (sel [ tgt ~alias:"id" (int 1) ])) ])
            ~from:[ rel "orders" ]
            [ tgt (c "id") ]))
      [];
    t "qualified bypasses cte"
      (s
         (sel
            ~with_:(with_ [ cte "orders" (Select (sel [ tgt ~alias:"id" (int 1) ])) ])
            ~from:[ rel ~schema:"app" "orders" ]
            [ tgt (c "id") ]))
      [ E_TENANT_MISSING ];
    t "exists unfiltered (ast)"
      (s
         (from_orders_where
            (and_
               [
                 eq (c "tenant_id") (param 1);
                 exists (sel ~from:[ rel "items" ~as_:"i" ] [ tgt (int 1) ]);
               ])))
      [ E_TENANT_MISSING ] ~binds:b1;
    t "scalar subquery filtered (ast)"
      (s
         (from_orders_where
            (and_
               [
                 eq (c "tenant_id") (param 1);
                 eq (c "status")
                   (scalar
                      (sel
                         ~from:[ rel "items" ~as_:"i" ]
                         ~where:(eq (c2 "i" "tenant_id") (param 1))
                         [ tgt (c2 "i" "x") ]));
               ])))
      [] ~binds:b1;
    t "left join nullable side (ast)"
      (s
         (sel
            ~from:
              [
                join ~kind:Left
                  ~quals:(eq (c2 "i" "tenant_id") (param 1))
                  (rel "orders" ~as_:"o") (rel "items" ~as_:"i");
              ]
            ~where:(eq (c2 "o" "tenant_id") (param 1))
            [ tgt (c2 "o" "id") ]))
      [] ~binds:b1;
    t "left join preserved side (ast)"
      (s
         (sel
            ~from:
              [
                join ~kind:Left
                  ~quals:
                    (and_
                       [
                         eq (c2 "i" "tenant_id") (param 1);
                         eq (c2 "o" "tenant_id") (param 1);
                       ])
                  (rel "orders" ~as_:"o") (rel "items" ~as_:"i");
              ]
            [ tgt (c2 "o" "id") ]))
      [ E_TENANT_MISSING ];
    t "full join (ast)"
      (s
         (sel
            ~from:
              [
                join ~kind:Full
                  ~quals:
                    (and_
                       [
                         eq (c2 "i" "tenant_id") (param 1);
                         eq (c2 "o" "tenant_id") (param 1);
                       ])
                  (rel "orders" ~as_:"o") (rel "items" ~as_:"i");
              ]
            [ tgt (c2 "o" "id") ]))
      [ E_TENANT_MISSING; E_PARAM_UNBOUND ];
    t "lateral subquery unfiltered (ast)"
      (s
         (sel
            ~from:
              [
                rel "orders" ~as_:"o";
                subq ~lateral:true ~as_:"x"
                  (sel
                     ~from:[ rel "items" ~as_:"i" ]
                     ~where:(eq (c2 "i" "order_id") (c2 "o" "id"))
                     [ tgt (c2 "i" "qty") ]);
              ]
            ~where:(eq (c2 "o" "tenant_id") (param 1))
            [ tgt (c2 "x" "qty") ]))
      [ E_TENANT_MISSING ] ~binds:b1;
    t "non-lateral subquery cannot see sibling"
      (s
         (sel
            ~from:
              [ rel "currencies" ~as_:"c"; subq ~as_:"x" (sel [ tgt (c2 "c" "code") ]) ]
            [ tgt (int 1) ]))
      [ E_COLUMN_UNRESOLVED ];
    t "recursive cte self reference (ast)"
      (s
         (sel
            ~with_:
              (with_ ~recursive:true
                 [
                   cte ~cols:[ "n" ] "r"
                     (Select
                        (union ~all:true
                           (sel [ tgt (int 1) ])
                           (sel
                              ~from:[ rel "r" ]
                              ~where:(aop "<" (c "n") (int 5))
                              [ tgt (aop "+" (c "n") (int 1)) ])));
                 ])
            ~from:[ rel "r" ]
            [ tgt (c "n") ]))
      [ E_UNSUPPORTED ];
    t "whole-row of denied-column table"
      (s
         (sel
            ~from:[ rel "customers" ~as_:"c" ]
            ~where:(eq (c2 "c" "tenant_id") (param 1))
            [ tgt (c "c") ]))
      [ E_COLUMN_DENIED ];
    t "whole-row via indirection"
      (s
         (sel
            ~from:[ rel "customers" ~as_:"c" ]
            ~where:(eq (c2 "c" "tenant_id") (param 1))
            [
              tgt
                (Indirection
                   { arg = c "c"; subscripts = []; fields = [ Name "email" ]; loc = -1 });
            ]))
      [ E_COLUMN_DENIED ];
    t "literal mode int normalization"
      ~policy:(policy ~mode:Policy.Literal ())
      ~ctx:ctx_int
      (s
         (from_orders_where
            (eq (c "tenant_id") (Const { value = Int "+0042"; loc = -1 }))))
      [];
    t "literal mode in row list"
      ~policy:(policy ~mode:Policy.Literal ())
      ~ctx:ctx_many
      (s
         (from_orders_where
            (A_expr
               {
                 kind = In;
                 name = [ "=" ];
                 lexpr = Some (c "tenant_id");
                 rexpr = Some (Row { args = [ str "acme"; str "acme-eu" ]; loc = -1 });
                 loc = -1;
               })))
      [];
    t "not in list does not prove"
      ~policy:(policy ~mode:Policy.Literal ())
      (s
         (from_orders_where
            (A_expr
               {
                 kind = In;
                 name = [ "<>" ];
                 lexpr = Some (c "tenant_id");
                 rexpr = Some (Row { args = [ str "evil" ]; loc = -1 });
                 loc = -1;
               })))
      [ E_TENANT_MISSING ];
    t "param conflict across keys"
      (s
         (sel
            ~from:[ rel "memberships" ]
            ~where:(and_ [ eq (c "org_id") (param 1); eq (c "user_id") (param 1) ])
            [ tgt (c "id") ]))
      [ E_TENANT_MISMATCH ];
    t "insert ok (ast)" ~policy:p_all
      (ins [ [ param 1; str "new" ] ])
      [] ~binds:b1 ~kind:Policy.Insert;
    t "insert default in non-tenant column" ~policy:p_all
      (ins [ [ param 1; unsup "SetToDefault" ] ])
      [] ~binds:b1;
    t "insert default in tenant column" ~policy:p_all
      (ins [ [ unsup "SetToDefault"; str "x" ] ])
      [ E_TENANT_WRITE ];
    t "insert other unsupported cell" ~policy:p_all
      (ins [ [ param 1; unsup "XmlExpr" ] ])
      [ E_UNSUPPORTED ] ~binds:b1;
    t "insert on conflict (ast)" ~policy:p_all
      (ins ~on_conflict:true [ [ param 1; str "x" ] ])
      [ E_UNSUPPORTED ] ~binds:b1;
    t "insert empty column list" ~policy:p_all
      (ins ~cols:[] [ [ param 1 ] ])
      [ E_WRITE_DENIED; E_TENANT_WRITE; E_PARAM_UNBOUND ];
    t "data-modifying cte (ast)"
      (s
         (sel
            ~with_:(with_ [ cte "d" (ins [ [ param 1; str "x" ] ]) ])
            ~from:[ rel "d" ]
            [ tgt (int 1) ]))
      [ E_DATA_MODIFYING_CTE ];
    t "statement kinds empty" ~policy:(policy ~statements:[] ())
      (s (sel [ tgt (int 1) ]))
      [ E_STATEMENT_KIND ];
    t "reasons carry locations"
      (s (sel [ tgt (fn "pg_sleep" [ int 1 ]) ]))
      [ E_FUNCTION_DENIED ];
  ]

let robustness =
  [
    Alcotest.test_case "deeply nested expression does not raise" `Quick (fun () ->
        let rec deep n = if n = 0 then c "code" else aop "+" (deep (n - 1)) (int 1) in
        let a =
          A.analyze default_policy ctx
            (s (sel ~from:[ rel "currencies" ] [ tgt (deep 2000) ]))
        in
        check_analysis ~expect:[] a);
    Alcotest.test_case "reason locations are passed through" `Quick (fun () ->
        let a =
          A.analyze default_policy ctx
            (s
               (sel
                  [
                    tgt
                      (Func_call
                         {
                           fname = { schema = None; name = "pg_sleep" };
                           args = [];
                           agg_star = false;
                           agg_distinct = false;
                           agg_filter = None;
                           agg_order = [];
                           over = None;
                           variadic = false;
                           loc = 17;
                         });
                  ]))
        in
        match a.reasons with
        | [ r ] -> Alcotest.(check (option int)) "loc" (Some 17) r.loc
        | _ -> Alcotest.fail "expected one reason");
    Alcotest.test_case "rule ids are stable" `Quick (fun () ->
        let a =
          A.analyze default_policy ctx (s (sel ~from:[ rel "orders" ] [ tgt (c "id") ]))
        in
        Alcotest.(check (list string))
          "rules" [ "tenancy.predicate" ]
          (List.map (fun (r : Reason.t) -> r.rule) a.reasons));
    Alcotest.test_case "tenant-missing hint names alias and placeholder" `Quick (fun () ->
        let a =
          A.analyze default_policy ctx
            (s (sel ~from:[ rel "orders" ~as_:"o" ] [ tgt (c2 "o" "id") ]))
        in
        match a.reasons with
        | [ { hint = Some h; _ } ] ->
            let contains sub =
              let n = String.length h and m = String.length sub in
              let rec go i = i + m <= n && (String.sub h i m = sub || go (i + 1)) in
              go 0
            in
            if not (contains "o.tenant_id = $1" && contains "app.orders") then
              Alcotest.failf "hint: %s" h
        | _ -> Alcotest.fail "expected one reason with hint");
  ]

let suites = [ ("ast.rules", cases); ("ast.robustness", robustness) ]
