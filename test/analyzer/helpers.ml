(* Test helpers: policy builders, an AST DSL and assertion helpers. *)

open Haltsql_core
module A = Haltsql_analyzer.Analyzer

(* ---------------------------------------------------------------- policy *)

let table ?(schema = "app") ?(columns = Policy.All) ?(tenant = [])
    ?(writes = Policy.no_writes) name : Policy.table =
  { schema; name; columns; tenant_columns = tenant; writes }

let only l = Policy.Only l
let t_tenant = [ ("tenant_id", "tenant") ]

let default_functions =
  [
    "count";
    "sum";
    "avg";
    "min";
    "max";
    "coalesce";
    "lower";
    "upper";
    "now";
    "date_trunc";
    "generate_series";
    "unnest";
    "json_build_object";
    "length";
    "abs";
    "round";
    "btrim";
    "extract";
    "date_part";
    "array_agg";
    "row_number";
    "rank";
    "lag";
    "jsonb_array_elements";
  ]

let default_operators =
  [
    "=";
    "<>";
    "!=";
    "<";
    ">";
    "<=";
    ">=";
    "+";
    "-";
    "*";
    "/";
    "%";
    "||";
    "~~";
    "~~*";
    "!~~";
    "!~~*";
  ]

let default_deny_casts =
  [ "regclass"; "regproc"; "regprocedure"; "regtype"; "regnamespace"; "regrole"; "oid" ]

let orders =
  table "orders"
    ~columns:
      (only [ "id"; "tenant_id"; "status"; "total_cents"; "created_at"; "customer_id" ])
    ~tenant:t_tenant
    ~writes:
      {
        Policy.insert = true;
        update = Some (only [ "status"; "total_cents"; "tenant_id" ]);
        delete = true;
      }

let customers =
  table "customers"
    ~columns:(only [ "id"; "tenant_id"; "name"; "created_at" ])
    ~tenant:t_tenant

let currencies = table "currencies"

(* tenant-scoped, all columns readable, no catalog entry *)
let items =
  table "items" ~tenant:t_tenant
    ~writes:{ Policy.insert = true; update = Some Policy.All; delete = false }

(* composite tenancy *)
let memberships =
  table "memberships"
    ~columns:(only [ "id"; "org_id"; "user_id"; "role" ])
    ~tenant:[ ("org_id", "org"); ("user_id", "user") ]

(* tenant-scoped Only table without catalog *)
let notes = table "notes" ~columns:(only [ "id"; "tenant_id"; "body" ]) ~tenant:t_tenant

(* global table with restricted columns, no catalog *)
let products = table "products" ~columns:(only [ "id"; "name"; "price" ])

(* explicitly allowed system relation *)
let pg_settings_tbl =
  table ~schema:"pg_catalog" "pg_settings" ~columns:(only [ "name"; "setting" ])

let catalog : Catalog.t =
  let mk name cols =
    {
      Catalog.schema = "app";
      name;
      columns = List.map (fun c -> { Catalog.col_name = c; col_type = Some "text" }) cols;
    }
  in
  {
    Catalog.tables =
      [
        mk "orders"
          [ "id"; "tenant_id"; "status"; "total_cents"; "created_at"; "customer_id" ];
        mk "customers" [ "id"; "tenant_id"; "name"; "email"; "ssn"; "created_at" ];
        mk "currencies" [ "code"; "name"; "rate" ];
        mk "memberships" [ "id"; "org_id"; "user_id"; "role" ];
      ];
  }

let policy ?(statements = [ Policy.Select ]) ?require_limit ?(mode = Policy.Bound)
    ?(keys = [ ("tenant", "tenant_id"); ("org", "org_id"); ("user", "user_id") ])
    ?(functions = default_functions) ?(operators = default_operators)
    ?(deny_casts = default_deny_casts) ?(allow_explain = false) ?(catalog = catalog)
    ?(max_joins = 8) ?(search_path = [ "app" ])
    ?(tables =
      [
        orders;
        customers;
        currencies;
        items;
        memberships;
        notes;
        products;
        pg_settings_tbl;
      ]) () : Policy.t =
  {
    api_version = "haltsql.dev/v1";
    name = "test";
    owner = None;
    description = None;
    dialect = "postgres";
    search_path;
    limits = { Policy.default_limits with max_joins };
    statements;
    require_limit;
    tenancy = { mode; keys };
    tables;
    functions;
    operators;
    deny_casts;
    allow_explain;
    mode = Policy.Enforce;
    catalog;
    version = "sha256:test";
  }

let default_policy = policy ()

let ctx =
  Context.make
    [
      ("tenant_id", Context.One "acme");
      ("org_id", Context.One "o1");
      ("user_id", Context.One "u1");
    ]

let ctx_many =
  Context.make
    [
      ("tenant_id", Context.Many [ "acme"; "acme-eu" ]);
      ("org_id", Context.One "o1");
      ("user_id", Context.One "u1");
    ]

let ctx_int =
  Context.make
    [
      ("tenant_id", Context.One "42");
      ("org_id", Context.One "7");
      ("user_id", Context.One "9");
    ]

(* ---------------------------------------------------------------- AST DSL *)

open Ast

let field s = if String.equal s "*" then Star else Name s
let col fs = Column_ref { fields = List.map field fs; loc = -1 }
let c s = col [ s ]
let c2 t s = col [ t; s ]
let star = col [ "*" ]
let int n = Const { value = Int (string_of_int n); loc = -1 }
let str s = Const { value = String s; loc = -1 }
let param n = Param { number = n; loc = -1 }

let aop ?(kind = Op) o l r =
  A_expr { kind; name = [ o ]; lexpr = Some l; rexpr = Some r; loc = -1 }

let eq l r = aop "=" l r
let and_ args = Bool_expr { op = And; args; loc = -1 }
let or_ args = Bool_expr { op = Or; args; loc = -1 }
let not_ a = Bool_expr { op = Not; args = [ a ]; loc = -1 }

let fn ?schema ?(agg_star = false) ?over name args =
  Func_call
    {
      fname = { schema; name };
      args;
      agg_star;
      agg_distinct = false;
      agg_filter = None;
      agg_order = [];
      over;
      variadic = false;
      loc = -1;
    }

let cast e ty =
  Type_cast
    {
      arg = e;
      type_name = { type_names = ty; array_bounds = 0; type_loc = -1 };
      loc = -1;
    }

let tgt ?alias e = { expr = e; alias; target_loc = -1 }
let alias ?(cols = []) a = Some { aliasname = a; colnames = cols }

let rel ?schema ?as_ ?(cols = []) name =
  Relation
    {
      rel = { schema; name };
      alias = (match as_ with Some a -> alias ~cols a | None -> None);
      inh = true;
      loc = -1;
    }

let join ?(kind = Inner) ?quals ?(using = []) l r =
  Join
    { kind; natural = false; left = l; right = r; quals; using; alias = None; loc = -1 }

let subq ?(lateral = false) ?as_ q =
  Subquery
    {
      lateral;
      query = q;
      alias = (match as_ with Some a -> alias a | None -> None);
      loc = -1;
    }

let sel ?with_ ?where ?(from = []) ?limit ?(group_by = []) ?having ?(order_by = [])
    ?(locking = []) ?(into = false) ?distinct targets : select =
  {
    with_;
    body = Simple { distinct; targets; into; from; where; group_by; having; windows = [] };
    order_by = List.map (fun e -> { sort_expr = e; sort_loc = -1 }) order_by;
    limit_count = Option.map int limit;
    limit_all = false;
    limit_offset = None;
    locking;
    sel_loc = -1;
  }

let union ?(all = false) ?limit l r : select =
  {
    with_ = None;
    body = Set_op { op = Union; all; larg = l; rarg = r };
    order_by = [];
    limit_count = Option.map int limit;
    limit_all = false;
    limit_offset = None;
    locking = [];
    sel_loc = -1;
  }

let with_ ?(recursive = false) ctes = { recursive; ctes; with_loc = -1 }

let cte ?(cols = []) name q =
  { cte_name = name; cte_colnames = cols; cte_query = q; cte_loc = -1 }

let exists q =
  Sub_link { kind = Exists; testexpr = None; oper = []; subselect = q; loc = -1 }

let scalar q =
  Sub_link { kind = Expr; testexpr = None; oper = []; subselect = q; loc = -1 }

(* ---------------------------------------------------------------- checks *)

let codes (a : A.analysis) =
  List.sort_uniq compare
    (List.map (fun (r : Reason.t) -> Reason.code_to_string r.code) a.reasons)

let show_reasons (a : A.analysis) =
  String.concat "\n"
    (List.map
       (fun (r : Reason.t) ->
         Printf.sprintf "  %s [%s] %s%s"
           (Reason.code_to_string r.code)
           r.rule r.message
           (match r.hint with Some h -> " -- hint: " ^ h | None -> ""))
       a.reasons)

let value_str = function
  | Context.One s -> s
  | Context.Many l -> "[" ^ String.concat "," l ^ "]"

let binds_str l =
  String.concat "; " (List.map (fun (n, v) -> Printf.sprintf "$%d=%s" n (value_str v)) l)

let check_analysis ?binds ?tables ?columns ~expect (a : A.analysis) =
  let expect = List.sort_uniq compare (List.map Reason.code_to_string expect) in
  let got = codes a in
  if got <> expect then
    Alcotest.failf "expected codes [%s] got [%s]\n%s" (String.concat ", " expect)
      (String.concat ", " got) (show_reasons a);
  List.iter
    (fun (r : Reason.t) ->
      if String.equal r.rule "" then Alcotest.fail "reason without rule id";
      if r.hint = None then Alcotest.failf "reason without hint: %s" r.message)
    a.reasons;
  (match binds with
  | Some b ->
      if a.bind_params <> b then
        Alcotest.failf "expected binds [%s] got [%s]" (binds_str b)
          (binds_str a.bind_params)
  | None -> ());
  (match tables with
  | Some t ->
      if a.tables <> t then
        Alcotest.failf "expected tables [%s] got [%s]" (String.concat "," t)
          (String.concat "," a.tables)
  | None -> ());
  match columns with
  | Some cs ->
      if a.columns <> cs then
        Alcotest.failf "expected columns [%s] got [%s]" (String.concat "," cs)
          (String.concat "," a.columns)
  | None -> ()
