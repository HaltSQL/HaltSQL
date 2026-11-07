(* Policy-driven property tests (PLAN.md §8.3) over the saas fixture policy.

   (a) SAFE generator: random queries over the saas schema with a correct
       tenant predicate on every tenant-table occurrence, allowed columns and
       functions, and a constant LIMIT. They must be allowed with
       bind_params = [(1, ctx.tenant_id)].
   (b) Evasion transforms applied to safe queries. Meaning-preserving
       transforms (CTE / derived-table wrapping, case, quoting, U&"" escapes,
       comments, whitespace, schema qualification, redundant parentheses,
       filtered UNION branches, trailing semicolon) must keep "allowed";
       isolation-breaking transforms must deny with the expected code.
   (c) Determinism: verifying twice gives identical verdict JSON (except
       elapsed_us), and the YAML policy and its JSON twin give identical
       verdicts (including policy_version).
   (d) Totality: random byte strings and SQL token soup never raise, and any
       denial carries only codes from Reason.all_codes (and never E_INTERNAL).

   Environment:
   - HALTSQL_QCHECK_SEED   RNG seed (default 20261107); always printed
   - HALTSQL_QCHECK_COUNT  iterations per property (default 300) *)

open Haltsql

let seed =
  match Option.bind (Sys.getenv_opt "HALTSQL_QCHECK_SEED") int_of_string_opt with
  | Some s -> s
  | None -> 20261107

let count =
  match Option.bind (Sys.getenv_opt "HALTSQL_QCHECK_COUNT") int_of_string_opt with
  | Some n when n > 0 -> n
  | _ -> 300

let fixtures =
  match Sys.getenv_opt "HALTSQL_FIXTURES" with Some d -> d | None -> "../fixtures"

let load_policy file =
  match Policy_load.of_file (Filename.concat fixtures file) with
  | Ok p -> p
  | Error es ->
      failwith
        (Printf.sprintf "cannot load %s:\n%s" file
           (String.concat "\n" (List.map Load_error.to_string es)))

let policy = lazy (load_policy "policies/saas.yaml")
let policy_json = lazy (load_policy "policies/saas.json")
let tenant = "acme"
let ctx = Context.make [ ("tenant_id", Context.One tenant) ]
let verify sql = Haltsql.verify (Lazy.force policy) ctx sql

let codes (v : Verdict.t) =
  List.map (fun (r : Reason.t) -> r.code) (v.reasons @ v.shadow_reasons)

let codes_str v = String.concat "," (List.map Reason.code_to_string (codes v))

let verdict_json (v : Verdict.t) =
  Yojson.Safe.to_string (Verdict.to_json { v with elapsed_us = 0 })

(* ------------------------------------------------------------------ *)
(* Schema (allowed columns only; tenant column handled separately)     *)

let tables =
  [
    ( "orders",
      [
        "id";
        "customer_id";
        "status";
        "total_cents";
        "currency";
        "created_at";
        "updated_at";
      ] );
    ( "order_items",
      [
        "id"; "order_id"; "product_sku"; "quantity"; "unit_price_cents"; "discount_cents";
      ] );
    ("customers", [ "id"; "name"; "country"; "plan"; "created_at" ]);
    ( "invoices",
      [
        "id";
        "customer_id";
        "order_id";
        "amount_cents";
        "status";
        "issued_at";
        "due_at";
        "paid_at";
      ] );
    ( "payments",
      [ "id"; "invoice_id"; "amount_cents"; "method"; "card_last4"; "created_at" ] );
    ("users", [ "id"; "display_name"; "role"; "created_at"; "last_login_at" ]);
    ("audit_events", [ "id"; "actor_id"; "action"; "target"; "created_at" ]);
  ]

let numeric =
  [
    ("orders", "total_cents");
    ("order_items", "quantity");
    ("invoices", "amount_cents");
    ("payments", "amount_cents");
  ]

type rel = { tbl : string; alias : string }

type item =
  | Col of int * string  (** rel index, column *)
  | Count_star
  | Agg of string * int * string  (** fn, rel index, column *)

type q = {
  rels : rel list;  (** first is FROM, the rest are INNER JOINed *)
  proj : item list;
  group : bool;  (** GROUP BY the plain columns *)
  filters : (int * string * string) list;  (** rel index, column, rhs (e.g. "> 5") *)
  order : bool;
  limit : int;
}

(* Rendering style: meaning-preserving surface variations. *)
type style = {
  upper_kw : bool;
  ident : [ `Plain | `Upper | `Quoted | `Uescape ];
  schema : bool;
  comments : bool;
  parens : bool;
  newlines : bool;
  semicolon : bool;
}

let plain_style =
  {
    upper_kw = true;
    ident = `Plain;
    schema = false;
    comments = false;
    parens = false;
    newlines = false;
    semicolon = false;
  }

let uescape s =
  let b = Buffer.create (String.length s * 5) in
  Buffer.add_string b "U&\"";
  String.iter (fun c -> Buffer.add_string b (Printf.sprintf "\\%04X" (Char.code c))) s;
  Buffer.add_char b '"';
  Buffer.contents b

let id st s =
  match st.ident with
  | `Plain -> s
  | `Upper -> String.uppercase_ascii s
  | `Quoted -> "\"" ^ s ^ "\""
  | `Uescape -> uescape s

let kw st k = if st.upper_kw then String.uppercase_ascii k else String.lowercase_ascii k
let sp st = if st.newlines then "\n  " else " "
let cm st = if st.comments then " /* hs */ " else " "
let tenant_col = "tenant_id"

let rel_ref st (r : rel) =
  (if st.schema then id st "app" ^ "." else "") ^ id st r.tbl ^ " " ^ id st r.alias

let colref st (q : q) i c = id st (List.nth q.rels i).alias ^ "." ^ id st c

let default_pred st q i =
  let p = Printf.sprintf "%s = $1" (colref st q i tenant_col) in
  if st.parens then "(" ^ p ^ ")" else p

type knobs = {
  pred : int -> string option;  (** tenant predicate for relation i (None = omit) *)
  aliased : bool;  (** give projections output aliases c0, c1, ... *)
  extra_proj : string list;  (** appended to the select list *)
  extra_from : string;  (** appended after the joins *)
  extra_where : string list;
  with_limit : bool;
  from_override : string option;  (** replaces "<rel0> JOIN ..." entirely *)
}

let knobs st q =
  {
    pred = (fun i -> Some (default_pred st q i));
    aliased = false;
    extra_proj = [];
    extra_from = "";
    extra_where = [];
    with_limit = true;
    from_override = None;
  }

let render_item st q = function
  | Col (i, c) -> colref st q i c
  | Count_star -> kw st "count" ^ "(*)"
  | Agg (f, i, c) -> kw st f ^ "(" ^ colref st q i c ^ ")"

let render ?(st = plain_style) ?k (q : q) =
  let k = match k with Some k -> k | None -> knobs st q in
  let k_ = kw st in
  let proj =
    List.mapi
      (fun n it ->
        let e = render_item st q it in
        if k.aliased then
          Printf.sprintf "%s %s %s" e (k_ "AS") (id st (Printf.sprintf "c%d" n))
        else e)
      q.proj
    @ k.extra_proj
  in
  let from =
    match k.from_override with
    | Some f -> f
    | None ->
        let rel0 = rel_ref st (List.hd q.rels) in
        let joins =
          List.mapi
            (fun j r ->
              let i = j + 1 in
              let cond =
                Printf.sprintf "%s = %s" (colref st q i "id") (colref st q 0 "id")
              in
              let on =
                match k.pred i with
                | Some p -> p ^ " " ^ k_ "AND" ^ " " ^ cond
                | None -> cond
              in
              Printf.sprintf "%s%s %s %s %s" (sp st) (k_ "JOIN") (rel_ref st r) (k_ "ON")
                on)
            (List.tl q.rels)
        in
        rel0 ^ String.concat "" joins
  in
  let where =
    (match k.pred 0 with Some p -> [ p ] | None -> [])
    @ List.map (fun (i, c, rhs) -> Printf.sprintf "%s %s" (colref st q i c) rhs) q.filters
    @ k.extra_where
  in
  let group_cols =
    List.filter_map (function Col (i, c) -> Some (colref st q i c) | _ -> None) q.proj
  in
  String.concat ""
    [
      k_ "SELECT";
      cm st;
      String.concat ", " proj;
      sp st;
      k_ "FROM";
      " ";
      from;
      k.extra_from;
      (if where = [] then ""
       else sp st ^ k_ "WHERE" ^ " " ^ String.concat (" " ^ k_ "AND" ^ cm st) where);
      (if q.group && group_cols <> [] then
         sp st ^ k_ "GROUP BY" ^ " " ^ String.concat ", " group_cols
       else "");
      (if q.order then sp st ^ k_ "ORDER BY" ^ " 1" else "");
      (if k.with_limit then Printf.sprintf "%s%s %d" (sp st) (k_ "LIMIT") q.limit else "");
      (if st.semicolon then ";" else "");
    ]

(* ------------------------------------------------------------------ *)
(* Generators                                                          *)

let gen_q : q QCheck.Gen.t =
  let open QCheck.Gen in
  let* nrels = oneof_weighted [ (5, return 1); (3, return 2); (1, return 3) ] in
  let* tbls = list_size (return nrels) (oneof_list (List.map fst tables)) in
  let rels = List.mapi (fun i t -> { tbl = t; alias = Printf.sprintf "a%d" i }) tbls in
  let cols_of i = List.assoc (List.nth tbls i) tables in
  let gen_col =
    let* i = int_bound (nrels - 1) in
    let* c = oneof_list (cols_of i) in
    return (i, c)
  in
  let* agg = bool in
  let* plain = list_size (int_range 1 3) gen_col in
  let plain = List.sort_uniq compare plain in
  let* aggs =
    if not agg then return []
    else
      let nums =
        List.concat
          (List.mapi
             (fun i t ->
               match List.assoc_opt t numeric with Some c -> [ (i, c) ] | None -> [])
             tbls)
      in
      let* extra =
        if nums = [] then return []
        else
          let* f = oneof_list [ "sum"; "avg"; "max"; "min" ] in
          let* i, c = oneof_list nums in
          return [ Agg (f, i, c) ]
      in
      return (Count_star :: extra)
  in
  let* nfilters = int_bound 2 in
  let* filters =
    list_size (return nfilters)
      (let* i = int_bound (nrels - 1) in
       let* c = oneof_list (cols_of i) in
       let* rhs = oneof_list [ "IS NOT NULL"; "IS NULL" ] in
       return (i, c, rhs))
  in
  let* order = bool in
  let* limit = int_range 1 1000 in
  return
    {
      rels;
      proj = List.map (fun (i, c) -> Col (i, c)) plain @ aggs;
      group = agg;
      filters;
      order;
      limit;
    }

let gen_style : style QCheck.Gen.t =
  let open QCheck.Gen in
  let* upper_kw = bool in
  let* ident =
    oneof_weighted
      [
        (4, return `Plain); (2, return `Upper); (2, return `Quoted); (1, return `Uescape);
      ]
  in
  let* schema = bool in
  let* comments = bool in
  let* parens = bool in
  let* newlines = bool in
  let* semicolon = bool in
  return { upper_kw; ident; schema; comments; parens; newlines; semicolon }

(* ------------------------------------------------------------------ *)
(* Transforms                                                          *)

type expectation = Allowed | Denied of Reason.code | Denied_any of Reason.code list
type transform = { tname : string; apply : style -> q -> string; expect : expectation }

let inner_aliased st q k = render ~st ~k:{ k with aliased = true; with_limit = false } q

let outer_cols st q =
  String.concat ", " (List.mapi (fun n _ -> "s." ^ id st (Printf.sprintf "c%d" n)) q.proj)

let preserving : transform list =
  [
    { tname = "identity"; expect = Allowed; apply = (fun st q -> render ~st q) };
    {
      tname = "wrap in CTE";
      expect = Allowed;
      apply =
        (fun st q ->
          let inner = inner_aliased { st with semicolon = false } q (knobs st q) in
          Printf.sprintf "WITH s AS (%s) SELECT %s FROM s LIMIT %d" inner
            (outer_cols st q) q.limit);
    };
    {
      tname = "wrap in derived table";
      expect = Allowed;
      apply =
        (fun st q ->
          let inner = inner_aliased { st with semicolon = false } q (knobs st q) in
          Printf.sprintf "SELECT %s FROM (%s) s LIMIT %d" (outer_cols st q) inner q.limit);
    };
    {
      tname = "filtered UNION ALL branch";
      expect = Allowed;
      apply =
        (fun st q ->
          let st' = { st with semicolon = false } in
          let b = inner_aliased st' q (knobs st' q) in
          Printf.sprintf "(%s) UNION ALL (%s) LIMIT %d" b b q.limit);
    };
    {
      tname = "filtered LEFT JOIN on nullable side";
      expect = Allowed;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:
              {
                k with
                extra_from =
                  " LEFT JOIN customers lx ON lx.tenant_id = $1 AND lx.id = a0.id";
              }
            q);
    };
    {
      tname = "redundant duplicate tenant conjunct";
      expect = Allowed;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with extra_where = [ default_pred st q 0 ] } q);
    };
  ]

let customers_join = " JOIN customers wc ON wc.tenant_id = $1 AND wc.id = a0.id"

let breaking : transform list =
  [
    {
      tname = "drop tenant predicate of FROM relation";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with pred = (fun i -> if i = 0 then None else k.pred i) } q);
    };
    {
      tname = "drop tenant predicate of every relation";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with pred = (fun _ -> None) } q);
    };
    {
      tname = "OR true";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:
              {
                k with
                pred =
                  (fun i ->
                    if i = 0 then Some ("(" ^ default_pred st q 0 ^ " OR 1 = 1)")
                    else k.pred i);
              }
            q);
    };
    {
      tname = "OR other condition";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:
              {
                k with
                pred =
                  (fun i ->
                    if i = 0 then
                      Some
                        ("(" ^ default_pred st q 0 ^ " OR " ^ colref st q 0 "id" ^ " > 0)")
                    else k.pred i);
              }
            q);
    };
    {
      tname = "NOT of negated predicate";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:
              {
                k with
                pred =
                  (fun i ->
                    if i = 0 then
                      Some (Printf.sprintf "NOT (%s <> $1)" (colref st q 0 tenant_col))
                    else k.pred i);
              }
            q);
    };
    {
      tname = "cast on column side";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:
              {
                k with
                pred =
                  (fun i ->
                    if i = 0 then
                      Some (Printf.sprintf "%s::text = $1" (colref st q 0 tenant_col))
                    else k.pred i);
              }
            q);
    };
    {
      tname = "predicate hidden in correlated EXISTS";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:
              {
                k with
                pred =
                  (fun i ->
                    if i = 0 then
                      Some
                        (Printf.sprintf "EXISTS (SELECT 1 WHERE %s = $1)"
                           (colref st q 0 tenant_col))
                    else k.pred i);
              }
            q);
    };
    {
      tname = "move filter to outer query";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let st' = { st with semicolon = false } in
          let k = knobs st' q in
          let inner =
            render ~st:st'
              ~k:
                {
                  k with
                  aliased = true;
                  with_limit = false;
                  pred = (fun i -> if i = 0 then None else k.pred i);
                  extra_proj = [ colref st' q 0 tenant_col ^ " AS tq" ];
                }
              {
                q with
                group = false;
                proj = List.filter (function Col _ -> true | _ -> false) q.proj @ [];
              }
          in
          let nproj =
            List.length (List.filter (function Col _ -> true | _ -> false) q.proj)
          in
          let cols =
            String.concat ", " (List.init nproj (fun n -> Printf.sprintf "s.c%d" n))
          in
          Printf.sprintf "SELECT %s FROM (%s) s WHERE s.tq = $1 LIMIT %d" cols inner
            q.limit);
    };
    {
      tname = "unfiltered UNION ALL branch";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let st' = { st with semicolon = false } in
          let k = knobs st' q in
          Printf.sprintf "(%s) UNION ALL (%s) LIMIT %d" (inner_aliased st' q k)
            (inner_aliased st' q { k with pred = (fun _ -> None) })
            q.limit);
    };
    {
      tname = "unfiltered EXCEPT branch";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let st' = { st with semicolon = false } in
          let k = knobs st' q in
          Printf.sprintf "(%s) EXCEPT (%s) LIMIT %d"
            (inner_aliased st' q { k with pred = (fun _ -> None) })
            (inner_aliased st' q k) q.limit);
    };
    {
      tname = "unfiltered LEFT JOIN on nullable side";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:{ k with extra_from = " LEFT JOIN customers lx ON lx.id = a0.id" }
            q);
    };
    {
      tname = "unfiltered tenant table on preserved side of LEFT JOIN";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          let r0 = List.hd q.rels in
          let from =
            Printf.sprintf "customers px LEFT JOIN %s ON %s AND %s = px.id"
              (rel_ref st r0) (default_pred st q 0) (colref st q 0 "id")
          in
          (* keep the remaining INNER JOINs: render them after the LEFT JOIN *)
          let joins =
            List.mapi
              (fun j r ->
                Printf.sprintf " JOIN %s ON %s AND %s = %s" (rel_ref st r)
                  (default_pred st q (j + 1))
                  (colref st q (j + 1) "id")
                  (colref st q 0 "id"))
              (List.tl q.rels)
          in
          render ~st
            ~k:
              {
                k with
                pred = (fun i -> if i = 0 then None else k.pred i);
                from_override = Some (from ^ String.concat "" joins);
              }
            q);
    };
    {
      tname = "unfiltered CROSS JOIN of tenant table";
      expect = Denied E_TENANT_MISSING;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with extra_from = " CROSS JOIN invoices cx" } q);
    };
    {
      tname = "tenant literal for another tenant";
      expect = Denied E_TENANT_MISMATCH;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:
              {
                k with
                pred =
                  (fun i ->
                    if i = 0 then Some (colref st q 0 tenant_col ^ " = 'globex'")
                    else k.pred i);
              }
            q);
    };
    {
      tname = "add denied column";
      expect = Denied E_COLUMN_DENIED;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:{ k with extra_from = customers_join; extra_proj = [ "wc.email" ] }
            q);
    };
    {
      tname = "denied column only in WHERE";
      expect = Denied E_COLUMN_DENIED;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:
              { k with extra_from = customers_join; extra_where = [ "wc.ssn LIKE '9%'" ] }
            q);
    };
    {
      tname = "whole-row reference to customers";
      expect = Denied_any [ E_COLUMN_DENIED; E_COLUMN_UNRESOLVED ];
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with extra_from = customers_join; extra_proj = [ "wc" ] } q);
    };
    {
      tname = "add denied function (pg_sleep)";
      expect = Denied E_FUNCTION_DENIED;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with extra_where = [ "pg_sleep(1) IS NOT NULL" ] } q);
    };
    {
      tname = "add denied function (set_config)";
      expect = Denied E_FUNCTION_DENIED;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st
            ~k:{ k with extra_proj = [ "set_config('app.tenant_id', 'globex', false)" ] }
            q);
    };
    {
      tname = "regclass cast";
      expect = Denied E_CAST_DENIED;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with extra_proj = [ "'app.api_keys'::regclass" ] } q);
    };
    {
      tname = "system catalog join";
      expect = Denied E_TABLE_DENIED;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with extra_from = " CROSS JOIN pg_catalog.pg_class pc" } q);
    };
    {
      tname = "EXPLAIN ANALYZE wrapper";
      expect = Denied E_STATEMENT_KIND;
      apply =
        (fun st q -> "EXPLAIN ANALYZE " ^ render ~st:{ st with semicolon = false } q);
    };
    {
      tname = "data-modifying CTE prefix";
      expect = Denied E_DATA_MODIFYING_CTE;
      apply =
        (fun st q ->
          "WITH d AS (DELETE FROM orders WHERE tenant_id = $1 RETURNING id) "
          ^ render ~st q);
    };
    {
      tname = "smuggled second statement";
      expect = Denied E_MULTI_STATEMENT;
      apply =
        (fun st q ->
          render ~st:{ st with semicolon = false } q ^ "; DROP TABLE app.orders");
    };
    {
      tname = "FOR UPDATE";
      expect = Denied E_LOCKING_CLAUSE;
      apply =
        (fun st q ->
          (* locking is not allowed with aggregates; drop them to keep it one violation *)
          let q =
            {
              q with
              group = false;
              order = false;
              proj = List.filter (function Col _ -> true | _ -> false) q.proj;
            }
          in
          render ~st:{ st with semicolon = false } q ^ " FOR UPDATE");
    };
    {
      tname = "LIMIT too high";
      expect = Denied E_LIMIT_TOO_HIGH;
      apply = (fun st q -> render ~st { q with limit = 1001 + q.limit });
    };
    {
      tname = "no LIMIT";
      expect = Denied E_LIMIT_REQUIRED;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with with_limit = false } q);
    };
    {
      tname = "unbound extra parameter";
      expect = Denied E_PARAM_UNBOUND;
      apply =
        (fun st q ->
          let k = knobs st q in
          render ~st ~k:{ k with extra_where = [ colref st q 0 "id" ^ " = $2" ] } q);
    };
  ]

let print_case (st, q) =
  Printf.sprintf
    "style={kw=%b ident=%s schema=%b comments=%b parens=%b nl=%b semi=%b}\nSQL: %s"
    st.upper_kw
    (match st.ident with
    | `Plain -> "plain"
    | `Upper -> "upper"
    | `Quoted -> "quoted"
    | `Uescape -> "uescape")
    st.schema st.comments st.parens st.newlines st.semicolon (render ~st q)

let arb_case = QCheck.make ~print:print_case QCheck.Gen.(pair gen_style gen_q)
let expect_bind = [ (1, Context.One tenant) ]

let check_transform (t : transform) =
  QCheck.Test.make ~count ~name:("transform: " ^ t.tname) arb_case (fun (st, q) ->
      let sql = t.apply st q in
      let v = verify sql in
      match t.expect with
      | Allowed ->
          if not v.allowed then
            QCheck.Test.fail_reportf "expected allow, got deny [%s]\nSQL: %s\n%s"
              (codes_str v) sql (verdict_json v)
          else if v.bind_params <> expect_bind then
            QCheck.Test.fail_reportf "allowed but bind_params differ\nSQL: %s\n%s" sql
              (verdict_json v)
          else true
      | Denied code ->
          if v.allowed then
            QCheck.Test.fail_reportf "ESCAPE: expected deny %s, got allow\nSQL: %s"
              (Reason.code_to_string code) sql
          else if not (List.mem code (codes v)) then
            QCheck.Test.fail_reportf "denied but missing %s (got [%s])\nSQL: %s"
              (Reason.code_to_string code) (codes_str v) sql
          else if v.bind_params <> [] then
            QCheck.Test.fail_reportf "denied verdict carries bind_params\nSQL: %s" sql
          else true
      | Denied_any cs ->
          if v.allowed then
            QCheck.Test.fail_reportf "ESCAPE: expected deny, got allow\nSQL: %s" sql
          else if not (List.exists (fun c -> List.mem c (codes v)) cs) then
            QCheck.Test.fail_reportf "denied but with none of [%s] (got [%s])\nSQL: %s"
              (String.concat "," (List.map Reason.code_to_string cs))
              (codes_str v) sql
          else true)

(* Composition: two independent breaking transforms can't cancel out; and a
   breaking transform stays breaking after the CTE/derived-table wrapper. *)
let check_wrapped_breaking =
  let gen =
    QCheck.Gen.(
      let* st = gen_style in
      let* q = gen_q in
      let* which = oneof_list [ "drop"; "or"; "cast"; "notexists" ] in
      let* wrap = oneof_list [ `Cte; `Derived; `Lateral ] in
      return (st, q, which, wrap))
  in
  let print (st, q, which, _) = print_case (st, q) ^ "\nbreak=" ^ which in
  QCheck.Test.make ~count
    ~name:"transform: breaking predicate inside CTE/derived/LATERAL wrapper"
    (QCheck.make ~print gen) (fun (st, q, which, wrap) ->
      let st = { st with semicolon = false } in
      let k = knobs st q in
      let p0 =
        match which with
        | "drop" -> None
        | "or" -> Some ("(" ^ default_pred st q 0 ^ " OR TRUE)")
        | "cast" -> Some (colref st q 0 tenant_col ^ "::text = $1")
        | _ ->
            Some
              (Printf.sprintf "NOT (%s IS DISTINCT FROM $1)" (colref st q 0 tenant_col))
      in
      let inner =
        inner_aliased st q { k with pred = (fun i -> if i = 0 then p0 else k.pred i) }
      in
      let sql =
        match wrap with
        | `Cte ->
            Printf.sprintf "WITH s AS (%s) SELECT %s FROM s LIMIT %d" inner
              (outer_cols st q) q.limit
        | `Derived ->
            Printf.sprintf "SELECT %s FROM (%s) s LIMIT %d" (outer_cols st q) inner
              q.limit
        | `Lateral ->
            Printf.sprintf
              "SELECT %s FROM currencies cur CROSS JOIN LATERAL (%s) s LIMIT %d"
              (outer_cols st q) inner q.limit
      in
      let v = verify sql in
      if v.allowed then
        QCheck.Test.fail_reportf "ESCAPE: wrapped breaking transform allowed\nSQL: %s" sql
      else if not (List.mem Reason.E_TENANT_MISSING (codes v)) then
        QCheck.Test.fail_reportf "denied without E_TENANT_MISSING [%s]\nSQL: %s"
          (codes_str v) sql
      else true)

(* ------------------------------------------------------------------ *)
(* (c) determinism                                                     *)

let gen_any_sql =
  QCheck.Gen.(
    let* st = gen_style in
    let* q = gen_q in
    let* t = oneof_list (preserving @ breaking) in
    return (t.apply st q))

let check_determinism =
  QCheck.Test.make ~count ~name:"determinism: verify twice gives identical verdict JSON"
    (QCheck.make ~print:Fun.id gen_any_sql) (fun sql ->
      let a = verdict_json (verify sql) and b = verdict_json (verify sql) in
      if a <> b then QCheck.Test.fail_reportf "verdicts differ\n%s\n%s" a b else true)

let check_yaml_json_twin =
  QCheck.Test.make ~count
    ~name:"determinism: YAML policy and JSON twin give identical verdicts"
    (QCheck.make ~print:Fun.id gen_any_sql) (fun sql ->
      let a = verdict_json (Haltsql.verify (Lazy.force policy) ctx sql)
      and b = verdict_json (Haltsql.verify (Lazy.force policy_json) ctx sql) in
      if a <> b then QCheck.Test.fail_reportf "YAML vs JSON verdicts differ\n%s\n%s" a b
      else true)

(* ------------------------------------------------------------------ *)
(* (d) totality                                                        *)

let tokens =
  [|
    "SELECT";
    "FROM";
    "WHERE";
    "AND";
    "OR";
    "NOT";
    "JOIN";
    "LEFT";
    "ON";
    "UNION";
    "ALL";
    "WITH";
    "AS";
    "LIMIT";
    "OFFSET";
    "GROUP";
    "BY";
    "ORDER";
    "HAVING";
    "EXISTS";
    "IN";
    "LATERAL";
    "(";
    ")";
    ",";
    ";";
    "*";
    "=";
    "<>";
    "||";
    "::";
    "$1";
    "$2";
    "$0";
    "$99999999999";
    "1";
    "0";
    "-1";
    "1e309";
    "'x'";
    "'acme'";
    "E'\\x00'";
    "$$";
    "$tag$";
    "--";
    "/*";
    "*/";
    "\"";
    "U&\"\\0061\"";
    "orders";
    "customers";
    "o";
    "c";
    "tenant_id";
    "email";
    "id";
    "app";
    "pg_catalog";
    "pg_sleep";
    "count";
    "regclass";
    "DELETE";
    "INSERT";
    "UPDATE";
    "DROP";
    "TABLE";
    "EXPLAIN";
    "ANALYZE";
    "FOR";
    "INTO";
    "CASE";
    "WHEN";
    "THEN";
    "END";
    "NULL";
    "ARRAY";
    "[";
    "]";
    ".";
    "ROW";
    "VALUES";
    "DO";
    "COPY";
    "SET";
    "\\";
    "\n";
    "\x00";
    "\xff";
  |]

let gen_soup =
  QCheck.Gen.(
    let* n = int_range 0 40 in
    let* toks = list_size (return n) (oneof_array tokens) in
    let* sep = oneof_list [ " "; ""; "\n" ] in
    return (String.concat sep toks))

let gen_bytes = QCheck.Gen.(string_size ~gen:char (int_range 0 300))
let all_codes = Reason.all_codes

let totality name gen =
  QCheck.Test.make ~count:(count * 2) ~name (QCheck.make ~print:String.escaped gen)
    (fun sql ->
      match verify sql with
      | exception e -> QCheck.Test.fail_reportf "verify raised %s" (Printexc.to_string e)
      | v ->
          let cs = codes v in
          if v.allowed && v.reasons <> [] then
            QCheck.Test.fail_reportf "allowed with reasons"
          else if (not v.allowed) && cs = [] then
            QCheck.Test.fail_reportf "denied without a reason"
          else if not (List.for_all (fun c -> List.mem c all_codes) cs) then
            QCheck.Test.fail_reportf "unknown reason code"
          else if List.mem Reason.E_INTERNAL cs then
            QCheck.Test.fail_reportf "E_INTERNAL (analyzer bug): %s" (codes_str v)
          else true)

let () =
  Printf.printf
    "haltsql property tests: seed=%d count=%d (set HALTSQL_QCHECK_SEED / \
     HALTSQL_QCHECK_COUNT)\n\
     %!"
    seed count;
  let rand () = Random.State.make [| seed |] in
  let to_alc t = QCheck_alcotest.to_alcotest ~rand:(rand ()) t in
  Alcotest.run "haltsql-property"
    [
      ( "safe-generator",
        [
          to_alc
            (QCheck.Test.make ~count
               ~name:"generated safe queries are allowed with bind [$1=acme]" arb_case
               (fun (st, q) ->
                 let sql = render ~st q in
                 let v = verify sql in
                 if not v.allowed then
                   QCheck.Test.fail_reportf "safe query denied [%s]\nSQL: %s\n%s"
                     (codes_str v) sql (verdict_json v)
                 else if v.bind_params <> expect_bind then
                   QCheck.Test.fail_reportf "bind_params differ\nSQL: %s\n%s" sql
                     (verdict_json v)
                 else true));
        ] );
      ("meaning-preserving", List.map (fun t -> to_alc (check_transform t)) preserving);
      ( "isolation-breaking",
        List.map (fun t -> to_alc (check_transform t)) breaking
        @ [ to_alc check_wrapped_breaking ] );
      ("determinism", [ to_alc check_determinism; to_alc check_yaml_json_twin ]);
      ( "totality",
        [
          to_alc (totality "random bytes never raise; denials use known codes" gen_bytes);
          to_alc
            (totality "SQL token soup never raises; denials use known codes" gen_soup);
        ] );
    ]
