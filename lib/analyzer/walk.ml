(** The statement walker: builds scopes level by level, resolves every relation and column
    reference, applies the per-node rules and invokes the tenancy prover for each SELECT /
    DML level.

    Every [match] over an AST type lists its constructors explicitly (no wildcard arms),
    so adding a constructor to {!Haltsql_core.Ast} breaks the build here instead of being
    silently accepted. *)

open Haltsql_core

type cte_binding = { cname : string; ccols : Scope.knowledge }

type cx = {
  scope : Scope.t;  (** visible FROM levels, innermost first *)
  ctes : cte_binding list;  (** visible CTE names, innermost first *)
}

let empty_cx = { scope = Scope.empty; ctes = [] }
let sprintf = Printf.sprintf

(* ------------------------------------------------------------------------ *)
(* Generic reasons                                                          *)

let unsupported (env : Env.t) ~loc what =
  Env.emit env ~loc ~rule:"syntax.unsupported" Reason.E_UNSUPPORTED
    (sprintf "%s is not supported by HaltSQL's analyzer and is denied" what)
    ~hint:"Rewrite the query using plain SELECT / JOIN / WHERE constructs."

let unresolved (env : Env.t) ~loc msg =
  Env.emit env ~loc ~rule:"columns.resolve" Reason.E_COLUMN_UNRESOLVED msg
    ~hint:
      "Qualify every column with its table alias (e.g. o.status) and reference only \
       columns that exist; HaltSQL denies references it cannot resolve unambiguously."

(* ------------------------------------------------------------------------ *)
(* Relation resolution (rule D)                                              *)

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.equal (String.sub s 0 (String.length prefix)) prefix

(** Postgres searches pg_catalog first unless it is placed explicitly in the search path.
*)
let effective_search_path (p : Policy.t) =
  if List.mem "pg_catalog" p.search_path then p.search_path
  else "pg_catalog" :: p.search_path

(** Does a trusted (typed, i.e. snapshot-originated; see [catalog_columns]) catalog entry
    exist for schema [s]? Entries the loader derived from the policy prove nothing about
    what else exists in the schema. *)
let catalog_has_schema (p : Policy.t) s =
  List.exists
    (fun (t : Catalog.table) ->
      String.equal t.schema s
      && List.exists (fun (c : Catalog.column) -> Option.is_some c.col_type) t.columns)
    p.catalog.tables

(** Resolve a relation name against the policy (CTEs are handled by the caller).
    Unqualified names walk the effective search path:
    - [pg_catalog]: a policy table [pg_catalog.x] wins; otherwise a name starting with
      ["pg_"] is a system relation and is denied;
    - a schema with a matching policy table wins, but only if every earlier schema in the
      path is known (via the catalog snapshot) NOT to contain a relation of that name —
      otherwise Postgres might resolve the name to an unlisted relation in the earlier
      schema, so we deny and ask for a schema-qualified name. *)
let resolve_table (p : Policy.t) (q : Ast.qname) : (Policy.table, string * string) result
    =
  match q.schema with
  | Some s -> (
      match Policy.find_table p ~schema:s ~name:q.name with
      | Some tb -> Ok tb
      | None ->
          Error
            ( sprintf "relation %s.%s is not in the policy's table allowlist" s q.name,
              "Use only the tables listed in the policy." ))
  | None ->
      let rec go earlier = function
        | [] ->
            Error
              ( sprintf
                  "relation %s does not resolve to a policy table through search_path \
                   [%s]"
                  q.name
                  (String.concat ", " p.search_path),
                "Use only the tables listed in the policy." )
        | "pg_catalog" :: rest -> (
            match Policy.find_table p ~schema:"pg_catalog" ~name:q.name with
            | Some tb -> Ok tb
            | None ->
                if starts_with ~prefix:"pg_" q.name then
                  Error
                    ( sprintf "relation %s resolves to the system catalog (pg_catalog.%s)"
                        q.name q.name,
                      "System catalogs are not accessible; use only the tables listed in \
                       the policy." )
                else go earlier rest)
        | s :: rest -> (
            match Policy.find_table p ~schema:s ~name:q.name with
            | Some tb ->
                let shadow_free s' =
                  catalog_has_schema p s'
                  && Option.is_none (Catalog.find p.catalog ~schema:s' ~name:q.name)
                in
                if List.for_all shadow_free earlier then Ok tb
                else
                  Error
                    ( sprintf
                        "relation %s matches %s.%s, but an earlier search_path schema \
                         might contain a relation with the same name"
                        q.name s q.name,
                      sprintf "Schema-qualify the table: %s.%s." s q.name )
            | None ->
                go (if String.equal s "pg_catalog" then earlier else s :: earlier) rest)
      in
      go [] (effective_search_path p)

(** Full column list of a policy table from the catalog snapshot, if it is trustworthy.
    SECURITY: when a policy has no [catalog:] snapshot the loader DERIVES catalog entries
    from the policy's own [Only] column lists, which says nothing about the real table (it
    may have more, denied, columns). Trusting such an entry would let [SELECT *] on an
    [Only] table pass. Derived entries never carry column types, while
    [haltsql schema pull] snapshots always do, so an entry is trusted only if at least one
    column has a type. (An untyped hand-written snapshot is therefore ignored: fail
    closed.) *)
let catalog_columns (p : Policy.t) (tb : Policy.table) =
  match Catalog.find p.catalog ~schema:tb.schema ~name:tb.name with
  | Some ct -> (
      let typed =
        List.exists (fun (c : Catalog.column) -> Option.is_some c.col_type) ct.columns
      in
      if not typed then None
      else match Catalog.column_names ct with [] -> None | l -> Some l)
  | None -> None

(** Column knowledge of a base occurrence. Tables with an [Only] list are always
    [At_least] (even with a catalog) so that a stale catalog can never make us attribute a
    read of a denied column to another item. *)
let base_knowledge (p : Policy.t) (tb : Policy.table) catalog : Scope.knowledge =
  let tenant = List.map fst tb.tenant_columns in
  match (tb.columns, catalog) with
  | Policy.All, Some l -> Scope.Exact l
  | Policy.All, None -> Scope.At_least tenant
  | Policy.Only only, Some l ->
      Scope.At_least (Util.sort_uniq_strings (l @ only @ tenant))
  | Policy.Only only, None ->
      ignore p;
      Scope.At_least (Util.sort_uniq_strings (only @ tenant))

let base_item (env : Env.t) (tb : Policy.table) ~(alias : Ast.alias option) ~loc :
    Scope.item =
  let catalog = catalog_columns env.policy tb in
  Env.add_table env (Policy.table_qualified_name tb);
  {
    Scope.id = Env.fresh_id env;
    name = Some (match alias with Some a -> a.aliasname | None -> tb.name);
    schema = (match alias with Some _ -> None | None -> Some tb.schema);
    cols = base_knowledge env.policy tb catalog;
    source = Scope.Base { table = tb; catalog };
    loc;
  }

let derived_item (env : Env.t) ~descr ~name ~cols ~loc : Scope.item =
  {
    Scope.id = Env.fresh_id env;
    name;
    schema = None;
    cols;
    source = Scope.Derived descr;
    loc;
  }

let denied_item (env : Env.t) ~name ~schema ~loc : Scope.item =
  {
    Scope.id = Env.fresh_id env;
    name;
    schema;
    cols = Scope.At_least [];
    source = Scope.Denied;
    loc;
  }

(* ------------------------------------------------------------------------ *)
(* Column reads (rule E)                                                     *)

let readable_list = function
  | Policy.All -> "all"
  | Policy.Only [] -> "(none)"
  | Policy.Only l -> String.concat ", " l

let read_col (env : Env.t) ~loc (r : Scope.col_ref) =
  match r.item.source with
  | Scope.Derived _ | Scope.Denied -> ()
  | Scope.Base { table = tb; _ } -> (
      let tname = Policy.table_qualified_name tb in
      Env.add_column env (tname ^ "." ^ r.col);
      match tb.columns with
      | Policy.All -> ()
      | Policy.Only l ->
          if not (List.mem r.col l) then
            Env.emit env ~loc ~rule:"columns.denied" Reason.E_COLUMN_DENIED
              (sprintf "column %s of %s is not readable under this policy" r.col tname)
              ~hint:
                (sprintf "Remove %s from the query; readable columns of %s are: %s." r.col
                   tname (readable_list tb.columns)))

(** [*], [t.*] and whole-row references [t] read every column of the item. *)
let read_whole (env : Env.t) ~loc (it : Scope.item) =
  match it.source with
  | Scope.Derived _ | Scope.Denied -> ()
  | Scope.Base { table = tb; catalog } -> (
      let tname = Policy.table_qualified_name tb in
      let add_all cols = List.iter (fun c -> Env.add_column env (tname ^ "." ^ c)) cols in
      let denied () =
        Env.emit env ~loc ~rule:"columns.star" Reason.E_COLUMN_DENIED
          (sprintf
             "* or a whole-row reference to %s would read columns that are not readable \
              (or not known to the catalog)"
             tname)
          ~hint:
            (sprintf
               "List the allowed columns explicitly instead of * / whole-row references: \
                %s."
               (readable_list tb.columns))
      in
      match (tb.columns, catalog) with
      | Policy.All, Some cols -> add_all cols
      | Policy.All, None -> Env.add_column env (tname ^ ".*")
      | Policy.Only l, Some cols ->
          if List.for_all (fun c -> List.mem c l) cols then add_all cols else denied ()
      | Policy.Only _, None -> denied ())

let item_star_knowledge (it : Scope.item) : Scope.knowledge =
  match it.source with
  | Scope.Base { catalog = Some l; _ } -> Scope.Exact l
  | Scope.Base { catalog = None; _ } -> Scope.At_least (Scope.knowledge_names it.cols)
  | Scope.Derived _ | Scope.Denied -> it.cols

let one_named env ~loc ~what its k =
  match its with
  | [ it ] -> k it
  | [] -> unresolved env ~loc (sprintf "%s does not name any FROM item in scope" what)
  | _ :: _ :: _ ->
      unresolved env ~loc
        (sprintf "%s is ambiguous: several FROM items have that name" what)

let qualified_col env ~loc ~what its c =
  one_named env ~loc ~what its (fun it ->
      match Scope.presence it c with
      | Scope.Yes | Scope.Maybe -> read_col env ~loc { Scope.item = it; col = c }
      | Scope.No ->
          unresolved env ~loc
            (sprintf
               "%s has no column %s (attribute-notation function calls are not allowed)"
               (Scope.item_display it) c))

let single_name (env : Env.t) scope ~loc c =
  let r = Scope.resolve_unqualified scope c in
  let w = Scope.find_named scope c in
  match (r, w) with
  | Scope.U_col cr, _ -> read_col env ~loc cr
  | Scope.U_merged crs, _ -> List.iter (read_col env ~loc) crs
  | Scope.U_none, [ it ] -> read_whole env ~loc it
  | Scope.U_none, [] ->
      unresolved env ~loc (sprintf "column %s does not exist in any visible FROM item" c)
  | Scope.U_none, _ :: _ :: _ ->
      unresolved env ~loc (sprintf "%s is ambiguous: several FROM items have that name" c)
  | (Scope.U_maybe _ | Scope.U_ambiguous _), [ it ] ->
      (* Postgres prefers a column over a whole-row reference. If every item
         that might own a column [c] is harmless, either reading is safe and
         we check the (stricter) whole-row reading; otherwise deny. *)
      let candidates =
        match r with
        | Scope.U_maybe cr -> [ cr.item ]
        | Scope.U_ambiguous its -> its
        | Scope.U_col _ | Scope.U_merged _ | Scope.U_none -> []
      in
      if
        List.for_all (fun (x : Scope.item) -> x.id = it.id || Scope.harmless x) candidates
      then read_whole env ~loc it
      else
        unresolved env ~loc
          (sprintf "%s could be a column or a whole-row reference to %s" c
             (Scope.item_display it))
  | Scope.U_maybe cr, [] -> read_col env ~loc cr
  | Scope.U_ambiguous its, [] ->
      unresolved env ~loc
        (sprintf "column %s is ambiguous (could belong to %s)" c
           (String.concat ", " (List.map Scope.item_display its)))
  | (Scope.U_maybe _ | Scope.U_ambiguous _), _ :: _ :: _ ->
      unresolved env ~loc (sprintf "%s is ambiguous" c)

let resolve_column (env : Env.t) (scope : Scope.t) (fields : Ast.field list) ~loc =
  match Scope.classify_fields fields with
  | None -> unresolved env ~loc "malformed column reference ('*' must be last)"
  | Some ([], true) -> List.iter (read_whole env ~loc) (Scope.innermost_items scope)
  | Some ([], false) -> unresolved env ~loc "empty column reference"
  | Some ([ c ], false) -> single_name env scope ~loc c
  | Some ([ t ], true) ->
      one_named env ~loc ~what:t (Scope.find_named scope t) (read_whole env ~loc)
  | Some ([ t; c ], false) -> qualified_col env ~loc ~what:t (Scope.find_named scope t) c
  | Some ([ s; t ], true) ->
      one_named env ~loc
        ~what:(s ^ "." ^ t)
        (Scope.find_schema_named scope s t)
        (read_whole env ~loc)
  | Some ([ s; t; c ], false) ->
      qualified_col env ~loc ~what:(s ^ "." ^ t) (Scope.find_schema_named scope s t) c
  | Some (_ :: _ :: _ :: _, true) | Some (_ :: _ :: _ :: _ :: _, false) ->
      unresolved env ~loc
        (sprintf
           "column reference %s has too many qualifiers (cross-database references are \
            not allowed)"
           (String.concat "."
              (List.map (function Ast.Name n -> n | Ast.Star -> "*") fields)))

(* ------------------------------------------------------------------------ *)
(* Expressions                                                               *)

let bare_name (e : Ast.expr) =
  match e with
  | Ast.Column_ref { fields = [ Ast.Name x ]; _ } -> Some x
  | Ast.Column_ref _ | Ast.Const _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _
  | Ast.Func_call _ | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _
  | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _
  | Ast.Indirection _ | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ ->
      None

type fres = {
  items : Scope.item list;
  quals : (int * Ast.expr) list;  (** item id -> join qual that is a tenancy location *)
  merged : (string * Scope.col_ref list) list;
}

let no_fres = { items = []; quals = []; merged = [] }

let rec walk_expr (env : Env.t) (cx : cx) (e : Ast.expr) : unit =
  let w = walk_expr env cx in
  match e with
  | Ast.Column_ref { fields; loc } -> resolve_column env cx.scope fields ~loc
  | Ast.Const _ -> ()
  | Ast.Param { number; loc } -> Env.add_param env number loc
  | Ast.A_expr { kind = Ast.Similar; name; lexpr; rexpr; loc } ->
      (* The grammar rewrites [x SIMILAR TO p] into
         [x ~ pg_catalog.similar_to_escape(p)]; that implicit call is part of
         the built-in syntax, so only its arguments are analyzed. *)
      Rules.check_aexpr env Ast.Similar name loc;
      Option.iter w lexpr;
      Option.iter
        (fun (r : Ast.expr) ->
          match r with
          | Ast.Func_call
              {
                fname = { schema = Some "pg_catalog" | None; name = "similar_to_escape" };
                args;
                _;
              } ->
              List.iter w args
          | Ast.Func_call _ | Ast.Column_ref _ | Ast.Const _ | Ast.Param _ | Ast.A_expr _
          | Ast.Bool_expr _ | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _
          | Ast.Null_test _ | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _
          | Ast.Row _ | Ast.Array _ | Ast.Indirection _ | Ast.Collate _ | Ast.Sql_value _
          | Ast.Unsupported _ ->
              w r)
        rexpr
  | Ast.A_expr { kind; name; lexpr; rexpr; loc } ->
      Rules.check_aexpr env kind name loc;
      Option.iter w lexpr;
      Option.iter w rexpr
  | Ast.Bool_expr { args; _ } -> List.iter w args
  | Ast.Func_call { fname; args; agg_filter; agg_order; over; loc; _ } ->
      Rules.check_function env fname loc;
      List.iter w args;
      Option.iter w agg_filter;
      List.iter (fun (sb : Ast.sort_by) -> w sb.sort_expr) agg_order;
      Option.iter (walk_window env cx) over
  | Ast.Type_cast { arg; type_name; loc } ->
      Rules.check_cast env type_name loc;
      w arg
  | Ast.Sub_link { kind; testexpr; oper; subselect; loc } ->
      (match kind with
      | Ast.Other_sublink n -> unsupported env ~loc (sprintf "sublink %s" n)
      | Ast.Any | Ast.All -> (
          match oper with [] -> () | _ :: _ -> Rules.check_operator_name env oper loc)
      | Ast.Exists | Ast.Expr | Ast.Array_sublink -> ());
      Option.iter w testexpr;
      ignore (walk_select env cx ~outermost:false subselect)
  | Ast.Case { arg; whens; default; _ } ->
      Option.iter w arg;
      List.iter
        (fun (c, r) ->
          w c;
          w r)
        whens;
      Option.iter w default
  | Ast.Null_test { arg; _ } | Ast.Boolean_test { arg; _ } | Ast.Collate { arg; _ } ->
      w arg
  | Ast.Coalesce { args; _ } | Ast.Min_max { args; _ } | Ast.Row { args; _ } ->
      List.iter w args
  | Ast.Array { elements; _ } -> List.iter w elements
  | Ast.Indirection { arg; subscripts; _ } ->
      w arg;
      List.iter w subscripts
  | Ast.Sql_value { op; loc } -> Rules.check_sql_value env op loc
  | Ast.Unsupported { node; loc } ->
      unsupported env ~loc (sprintf "expression node %s" node)

and walk_window env cx (wd : Ast.window_def) =
  List.iter (walk_expr env cx) wd.partition_by;
  List.iter (fun (sb : Ast.sort_by) -> walk_expr env cx sb.sort_expr) wd.win_order_by

(* ------------------------------------------------------------------------ *)
(* FROM items                                                                *)

and walk_from (env : Env.t) (cx : cx) ~(siblings : Scope.item list) (fi : Ast.from_item) :
    fres =
  match fi with
  | Ast.Relation { rel; alias; inh = _; loc } -> (
      let cte =
        match rel.schema with
        | None -> List.find_opt (fun b -> String.equal b.cname rel.name) cx.ctes
        | Some _ -> None
      in
      let colnames = match alias with Some a -> a.colnames | None -> [] in
      let alias_name = Option.map (fun (a : Ast.alias) -> a.aliasname) alias in
      match cte with
      | Some b ->
          let it =
            derived_item env ~descr:("CTE " ^ b.cname)
              ~name:(Some (Option.value alias_name ~default:b.cname))
              ~cols:(Scope.rename colnames b.ccols)
              ~loc
          in
          { no_fres with items = [ it ] }
      | None -> (
          match resolve_table env.policy rel with
          | Ok tb ->
              (match colnames with
              | [] -> ()
              | _ :: _ ->
                  unsupported env ~loc
                    (sprintf "a column alias list on base table %s (positional renaming)"
                       (Policy.table_qualified_name tb)));
              { no_fres with items = [ base_item env tb ~alias ~loc ] }
          | Error (msg, hint) ->
              Env.emit env ~loc ~rule:"tables.allowlist" Reason.E_TABLE_DENIED msg ~hint;
              let it =
                denied_item env
                  ~name:(Some (Option.value alias_name ~default:rel.name))
                  ~schema:(match alias with Some _ -> None | None -> rel.schema)
                  ~loc
              in
              { no_fres with items = [ it ] }))
  | Ast.Subquery { lateral; query; alias; loc } ->
      let scope = if lateral then Scope.push siblings cx.scope else cx.scope in
      let k = walk_select env { cx with scope } ~outermost:false query in
      let colnames = match alias with Some a -> a.colnames | None -> [] in
      let it =
        derived_item env ~descr:"subquery"
          ~name:(Option.map (fun (a : Ast.alias) -> a.aliasname) alias)
          ~cols:(Scope.rename colnames k) ~loc
      in
      { no_fres with items = [ it ] }
  | Ast.Function { lateral = _; calls; ordinality; alias; loc } ->
      (* Functions in FROM are implicitly LATERAL in Postgres. *)
      let fcx = { cx with scope = Scope.push siblings cx.scope } in
      List.iter (walk_expr env fcx) calls;
      let fnames =
        List.filter_map
          (fun (c : Ast.expr) ->
            match c with
            | Ast.Func_call { fname; _ } -> Some fname.name
            | Ast.Column_ref _ | Ast.Const _ | Ast.Param _ | Ast.A_expr _
            | Ast.Bool_expr _ | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _
            | Ast.Null_test _ | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _
            | Ast.Row _ | Ast.Array _ | Ast.Indirection _ | Ast.Collate _
            | Ast.Sql_value _ | Ast.Unsupported _ ->
                None)
          calls
      in
      let alias_name = Option.map (fun (a : Ast.alias) -> a.aliasname) alias in
      let colnames = match alias with Some a -> a.colnames | None -> [] in
      let names =
        colnames @ Util.opt_list alias_name @ fnames
        @ if ordinality then [ "ordinality" ] else []
      in
      let name =
        match alias_name with Some a -> Some a | None -> Util.last (List.rev fnames)
      in
      let it =
        derived_item env ~descr:"function" ~name ~cols:(Scope.At_least names) ~loc
      in
      { no_fres with items = [ it ] }
  | Ast.Join { kind; natural; left; right; quals; using; alias; loc } ->
      if natural then
        unsupported env ~loc "NATURAL JOIN (its column set depends on the schema; use ON)";
      (match alias with
      | None -> ()
      | Some a -> unsupported env ~loc (sprintf "an alias on a JOIN (%s)" a.aliasname));
      Env.add_joins env 1;
      let l = walk_from env cx ~siblings left in
      let r = walk_from env cx ~siblings:(siblings @ l.items) right in
      let all = l.items @ r.items in
      let using_merged =
        List.map
          (fun u ->
            let side (f : fres) =
              match
                Scope.resolve_unqualified
                  [ { Scope.items = f.items; merged = f.merged } ]
                  u
              with
              | Scope.U_col cr | Scope.U_maybe cr -> [ cr ]
              | Scope.U_merged crs -> crs
              | Scope.U_ambiguous _ | Scope.U_none ->
                  unresolved env ~loc
                    (sprintf "USING column %s cannot be resolved on both sides" u);
                  []
            in
            let refs = side l @ side r in
            List.iter (read_col env ~loc) refs;
            (u, refs))
          using
      in
      let merged = using_merged @ l.merged @ r.merged in
      let jscope = Scope.push ~merged (siblings @ all) cx.scope in
      Option.iter (walk_expr env { cx with scope = jscope }) quals;
      let attach its q = List.map (fun (it : Scope.item) -> (it.id, q)) its in
      let own =
        match quals with
        | None -> []
        | Some q -> (
            match kind with
            | Ast.Inner | Ast.Cross -> attach all q
            | Ast.Left -> attach r.items q
            | Ast.Right -> attach l.items q
            | Ast.Full -> [])
      in
      { items = all; quals = l.quals @ r.quals @ own; merged }
  | Ast.Unsupported_from { node; loc } ->
      unsupported env ~loc (sprintf "FROM item %s" node);
      (* A nameless placeholder absorbs unqualified column references so the
         single E_UNSUPPORTED is not buried under resolution errors. *)
      { no_fres with items = [ denied_item env ~name:None ~schema:None ~loc ] }

and walk_from_list env cx (fis : Ast.from_item list) : fres =
  let fr =
    List.fold_left
      (fun acc fi ->
        let r = walk_from env cx ~siblings:acc.items fi in
        {
          items = acc.items @ r.items;
          quals = acc.quals @ r.quals;
          merged = acc.merged @ r.merged;
        })
      no_fres fis
  in
  fr

(* ------------------------------------------------------------------------ *)
(* SELECT                                                                    *)

and walk_select (env : Env.t) (cx : cx) ~outermost (s : Ast.select) : Scope.knowledge =
  let cx = walk_with env cx s.with_ in
  (match s.locking with
  | [] -> ()
  | l :: _ ->
      Env.emit env ~loc:s.sel_loc ~rule:"select.locking" Reason.E_LOCKING_CLAUSE
        (sprintf "locking clause %s is not allowed" l)
        ~hint:"Remove FOR UPDATE / FOR SHARE; the query must be read-only.");
  if outermost then Rules.check_limit env s;
  Option.iter (walk_expr env cx) s.limit_count;
  Option.iter (walk_expr env cx) s.limit_offset;
  match s.body with
  | Ast.Simple ss -> walk_simple env cx ss ~order_by:s.order_by
  | Ast.Values rows ->
      List.iter (List.iter (walk_expr env cx)) rows;
      let k =
        match rows with
        | r :: _ -> Scope.Exact (List.mapi (fun i _ -> sprintf "column%d" (i + 1)) r)
        | [] -> Scope.Exact []
      in
      walk_output_order env cx k s.order_by;
      k
  | Ast.Set_op { larg; rarg; _ } ->
      let k = walk_select env cx ~outermost:false larg in
      ignore (walk_select env cx ~outermost:false rarg);
      walk_output_order env cx k s.order_by;
      k

(** ORDER BY of a set operation / VALUES: only output columns are visible. *)
and walk_output_order env cx k order_by =
  let it = derived_item env ~descr:"result" ~name:None ~cols:k ~loc:(-1) in
  let ocx = { cx with scope = Scope.push [ it ] cx.scope } in
  List.iter (fun (sb : Ast.sort_by) -> walk_expr env ocx sb.sort_expr) order_by

and walk_simple env cx (ss : Ast.simple_select) ~order_by : Scope.knowledge =
  if ss.into then
    Env.emit env ~rule:"select.into" Reason.E_SELECT_INTO
      "SELECT ... INTO creates a table"
      ~hint:"Remove the INTO clause; the query must be read-only.";
  let fr = walk_from_list env cx ss.from in
  Env.add_joins env (max 0 (List.length ss.from - 1));
  let scope = Scope.push ~merged:fr.merged fr.items cx.scope in
  let lcx = { cx with scope } in
  let w = walk_expr env lcx in
  Option.iter w ss.where;
  List.iter (fun (t : Ast.target) -> w t.expr) ss.targets;
  let out_names =
    List.filter_map
      (fun t -> if Ast_util.is_star_target t then None else Some (Ast_util.target_name t))
      ss.targets
  in
  (* ORDER BY / DISTINCT ON: a bare name that matches an output column refers
     to that output column (Postgres resolves output names first). *)
  let order_expr e =
    match bare_name e with Some x when List.mem x out_names -> () | Some _ | None -> w e
  in
  (* GROUP BY: input columns first; a bare output name is used only when no
     input column definitely has that name. *)
  let group_expr e =
    match bare_name e with
    | Some x when List.mem x out_names -> (
        match Scope.resolve_unqualified scope x with
        | Scope.U_col _ | Scope.U_merged _ -> w e
        | Scope.U_maybe _ | Scope.U_ambiguous _ | Scope.U_none -> ())
    | Some _ | None -> w e
  in
  List.iter group_expr ss.group_by;
  Option.iter w ss.having;
  List.iter (walk_window env lcx) ss.windows;
  (match ss.distinct with None -> () | Some es -> List.iter order_expr es);
  List.iter (fun (sb : Ast.sort_by) -> order_expr sb.sort_expr) order_by;
  Tenancy.check_level env scope ~items:fr.items ~where:ss.where ~quals:fr.quals;
  targets_knowledge scope ss.targets

and targets_knowledge scope (targets : Ast.target list) : Scope.knowledge =
  Scope.concat_knowledge
    (List.map
       (fun (t : Ast.target) ->
         let star_of its = Scope.concat_knowledge (List.map item_star_knowledge its) in
         match t.expr with
         | Ast.Column_ref { fields; _ } when Ast_util.is_star_target t -> (
             match Scope.classify_fields fields with
             | Some ([], true) -> star_of (Scope.innermost_items scope)
             | Some ([ n ], true) -> star_of (Scope.find_named scope n)
             | Some ([ s; n ], true) -> star_of (Scope.find_schema_named scope s n)
             | Some (_, _) | None -> Scope.At_least [])
         | Ast.Column_ref _ | Ast.Const _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _
         | Ast.Func_call _ | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _
         | Ast.Null_test _ | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _
         | Ast.Row _ | Ast.Array _ | Ast.Indirection _ | Ast.Collate _ | Ast.Sql_value _
         | Ast.Unsupported _ ->
             Scope.Exact [ Ast_util.target_name t ])
       targets)

(* ------------------------------------------------------------------------ *)
(* WITH (rules D, L)                                                         *)

and walk_with env cx (w : Ast.with_clause option) : cx =
  match w with
  | None -> cx
  | Some { recursive; ctes; with_loc } ->
      if recursive then begin
        (* A recursive CTE can generate unbounded rows, and an outer LIMIT does
           not bound work done by aggregates, ORDER BY or DISTINCT over it, so
           it is a denial-of-service vector. Deny it (the body is still
           analyzed so every other violation is reported too). *)
        Env.emit env ~loc:with_loc ~rule:"syntax.recursive_cte" Reason.E_UNSUPPORTED
          "WITH RECURSIVE is denied: recursion cannot be bounded by LIMIT"
          ~hint:"Rewrite the query without WITH RECURSIVE (use joins over a fixed depth).";
        (* Every CTE of a WITH RECURSIVE list is visible to all of them
           (including itself); pre-bind with syntactic column names. *)
        let pre =
          List.map
            (fun (c : Ast.cte) ->
              let k =
                match c.cte_query with
                | Ast.Select s -> Ast_util.syntactic_columns s
                | Ast.Insert _ | Ast.Update _ | Ast.Delete _ | Ast.Explain _ | Ast.Other _
                  ->
                    Scope.At_least []
              in
              { cname = c.cte_name; ccols = Scope.rename c.cte_colnames k })
            ctes
        in
        let rcx = { cx with ctes = List.rev pre @ cx.ctes } in
        let bound =
          List.map
            (fun (c : Ast.cte) -> { cname = c.cte_name; ccols = walk_cte env rcx c })
            ctes
        in
        { cx with ctes = List.rev bound @ cx.ctes }
      end
      else
        List.fold_left
          (fun cx (c : Ast.cte) ->
            let k = walk_cte env cx c in
            { cx with ctes = { cname = c.cte_name; ccols = k } :: cx.ctes })
          cx ctes

and walk_cte env cx (c : Ast.cte) : Scope.knowledge =
  let k =
    match c.cte_query with
    | Ast.Select s -> walk_select env cx ~outermost:false s
    | (Ast.Insert _ | Ast.Update _ | Ast.Delete _) as st -> (
        match Ast_util.stmt_kind_of st with
        | Some k when Rules.kind_allowed env k -> walk_dml env cx st
        | Some k ->
            Env.emit env ~loc:c.cte_loc ~rule:"statement.data_modifying_cte"
              Reason.E_DATA_MODIFYING_CTE
              (sprintf
                 "CTE %s contains a data-modifying %s statement, which this policy does \
                  not allow"
                 c.cte_name
                 (String.uppercase_ascii (Policy.stmt_kind_to_string k)))
              ~hint:
                "Remove the INSERT/UPDATE/DELETE from the WITH clause; the query must be \
                 read-only.";
            Scope.At_least []
        | None -> Scope.At_least [])
    | Ast.Other { kind; loc } when Util.is_unsupported_kind kind ->
        unsupported env ~loc
          (sprintf "%s (inside CTE %s)" (Util.unsupported_what kind) c.cte_name);
        Scope.At_least []
    | Ast.Explain { loc; _ } | Ast.Other { loc; _ } ->
        unsupported env ~loc (sprintf "statement inside CTE %s" c.cte_name);
        Scope.At_least []
  in
  Scope.rename c.cte_colnames k

(* ------------------------------------------------------------------------ *)
(* DML (rule M)                                                              *)

and walk_dml env cx (st : Ast.stmt) : Scope.knowledge =
  match st with
  | Ast.Insert i -> walk_insert env cx i
  | Ast.Update u -> walk_update env cx u
  | Ast.Delete d -> walk_delete env cx d
  | Ast.Select s -> walk_select env cx ~outermost:false s
  | Ast.Explain { loc; _ } | Ast.Other { loc; _ } ->
      unsupported env ~loc "nested statement";
      Scope.At_least []

(** Resolve a DML target (never a CTE) and check the write permission. *)
and dml_target env (rel : Ast.qname) (alias : Ast.alias option) ~loc ~verb
    ~(allowed : Policy.writes -> bool) : Scope.item * Policy.table option =
  match resolve_table env.Env.policy rel with
  | Ok tb ->
      if not (allowed tb.writes) then
        Env.emit env ~loc ~rule:"writes.table" Reason.E_WRITE_DENIED
          (sprintf "%s on %s is not allowed by this policy" verb
             (Policy.table_qualified_name tb))
          ~hint:
            (sprintf "Do not %s %s." (String.lowercase_ascii verb)
               (Policy.table_qualified_name tb));
      ( base_item env tb
          ~alias:(Option.map (fun (a : Ast.alias) -> { a with colnames = [] }) alias)
          ~loc,
        Some tb )
  | Error (msg, hint) ->
      Env.emit env ~loc ~rule:"tables.allowlist" Reason.E_TABLE_DENIED msg ~hint;
      ( denied_item env
          ~name:(Some (match alias with Some a -> a.aliasname | None -> rel.name))
          ~schema:(match alias with Some _ -> None | None -> rel.schema)
          ~loc,
        None )

and walk_returning env cx scope (targets : Ast.target list) : Scope.knowledge =
  let rcx = { cx with scope } in
  List.iter (fun (t : Ast.target) -> walk_expr env rcx t.expr) targets;
  targets_knowledge scope targets

and walk_insert env cx (i : Ast.insert) : Scope.knowledge =
  let cx = walk_with env cx i.ins_with in
  if i.on_conflict then unsupported env ~loc:i.ins_loc "INSERT ... ON CONFLICT";
  let target, tbo =
    dml_target env i.ins_rel i.ins_alias ~loc:i.ins_loc ~verb:"INSERT" ~allowed:(fun w ->
        w.insert)
  in
  let tenant_cols = match tbo with Some tb -> tb.tenant_columns | None -> [] in
  (match i.ins_source with
  | None -> (
      match (tbo, tenant_cols) with
      | Some tb, _ :: _ ->
          Env.emit env ~loc:i.ins_loc ~rule:"tenancy.write" Reason.E_TENANT_WRITE
            (sprintf
               "INSERT ... DEFAULT VALUES into tenant-scoped %s cannot set the tenant \
                column"
               (Policy.table_qualified_name tb))
            ~hint:"Use INSERT ... (cols) VALUES (...) including the tenant column."
      | Some _, [] | None, _ -> ())
  | Some sel -> (
      (match i.ins_cols with
      | [] ->
          Env.emit env ~loc:i.ins_loc ~rule:"writes.columns" Reason.E_WRITE_DENIED
            "INSERT must name its target columns explicitly"
            ~hint:"Write INSERT INTO t (col1, col2, ...) VALUES (...)."
      | _ :: _ -> ());
      (* Inserted columns must be columns the policy exposes: a policy that
         hides users.password_hash must not let the model write it either. *)
      (match tbo with
      | Some ({ columns = Policy.Only allowed; _ } as tb) ->
          List.iter
            (fun col ->
              if not (List.mem col allowed) then
                Env.emit env ~loc:i.ins_loc ~rule:"writes.columns" Reason.E_WRITE_DENIED
                  (sprintf
                     "column %s of %s is not writable (not in the policy's column list)"
                     col
                     (Policy.table_qualified_name tb))
                  ~hint:(sprintf "Remove %s from the INSERT column list." col))
            i.ins_cols
      | Some { columns = Policy.All; _ } | None -> ());
      let scx = walk_with env cx sel.with_ in
      Option.iter (walk_expr env scx) sel.limit_count;
      Option.iter (walk_expr env scx) sel.limit_offset;
      List.iter (fun (sb : Ast.sort_by) -> walk_expr env scx sb.sort_expr) sel.order_by;
      match sel.body with
      | Ast.Values rows -> (
          (* A bare DEFAULT in a VALUES cell is the column default: allowed
             (a tenant column with DEFAULT fails the tenant-write check below). *)
          let cell (e : Ast.expr) =
            match e with
            | Ast.Unsupported { node = "SetToDefault"; _ } -> ()
            | Ast.Unsupported _ | Ast.Column_ref _ | Ast.Const _ | Ast.Param _
            | Ast.A_expr _ | Ast.Bool_expr _ | Ast.Func_call _ | Ast.Type_cast _
            | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _ | Ast.Boolean_test _
            | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _ | Ast.Indirection _
            | Ast.Collate _ | Ast.Sql_value _ ->
                walk_expr env scx e
          in
          List.iter (List.iter cell) rows;
          match tbo with
          | None -> ()
          | Some tb ->
              List.iter
                (fun (col, key) ->
                  match Util.index_of col i.ins_cols with
                  | None ->
                      Env.emit env ~loc:i.ins_loc ~rule:"tenancy.write"
                        Reason.E_TENANT_WRITE
                        (sprintf "INSERT into %s must set tenant column %s"
                           (Policy.table_qualified_name tb)
                           col)
                        ~hint:
                          (sprintf
                             "Add %s to the column list and the tenant value to every \
                              row."
                             col)
                  | Some idx ->
                      List.iter
                        (fun row ->
                          let e = List.nth_opt row idx in
                          let loc =
                            match e with
                            | Some e -> Ast_util.expr_loc e
                            | None -> i.ins_loc
                          in
                          Tenancy.check_insert_value env ~tb ~col ~key ~loc e)
                        rows)
                tb.tenant_columns)
      | Ast.Simple _ | Ast.Set_op _ ->
          unsupported env ~loc:sel.sel_loc
            "INSERT ... SELECT (only INSERT ... VALUES is analyzed)"));
  walk_returning env cx (Scope.push [ target ] cx.scope) i.ins_returning

and walk_update env cx (u : Ast.update) : Scope.knowledge =
  let cx = walk_with env cx u.upd_with in
  let target, tbo =
    dml_target env u.upd_rel u.upd_alias ~loc:u.upd_loc ~verb:"UPDATE" ~allowed:(fun w ->
        Option.is_some w.update)
  in
  (match tbo with
  | None -> ()
  | Some tb ->
      List.iter
        (fun (c, _) ->
          (match tb.writes.update with
          | None | Some Policy.All -> ()
          | Some (Policy.Only l) ->
              if not (List.mem c l) then
                Env.emit env ~loc:u.upd_loc ~rule:"writes.columns" Reason.E_WRITE_DENIED
                  (sprintf "column %s of %s may not be updated" c
                     (Policy.table_qualified_name tb))
                  ~hint:
                    (sprintf "Only these columns may be updated: %s."
                       (String.concat ", " l)));
          if List.mem_assoc c tb.tenant_columns then
            Env.emit env ~loc:u.upd_loc ~rule:"tenancy.write" Reason.E_TENANT_WRITE
              (sprintf "UPDATE may not assign tenant column %s of %s" c
                 (Policy.table_qualified_name tb))
              ~hint:"Do not SET the tenant column; rows cannot be moved between tenants.")
        u.set);
  let fr = walk_from_list env cx u.upd_from in
  Env.add_joins env (List.length u.upd_from);
  let items = target :: fr.items in
  let scope = Scope.push ~merged:fr.merged items cx.scope in
  let lcx = { cx with scope } in
  List.iter (fun (_, e) -> walk_expr env lcx e) u.set;
  Option.iter (walk_expr env lcx) u.upd_where;
  Tenancy.check_level env scope ~items ~where:u.upd_where ~quals:fr.quals;
  walk_returning env cx scope u.upd_returning

and walk_delete env cx (d : Ast.delete) : Scope.knowledge =
  let cx = walk_with env cx d.del_with in
  let target, _ =
    dml_target env d.del_rel d.del_alias ~loc:d.del_loc ~verb:"DELETE" ~allowed:(fun w ->
        w.delete)
  in
  let fr = walk_from_list env cx d.using in
  Env.add_joins env (List.length d.using);
  let items = target :: fr.items in
  let scope = Scope.push ~merged:fr.merged items cx.scope in
  let lcx = { cx with scope } in
  Option.iter (walk_expr env lcx) d.del_where;
  Tenancy.check_level env scope ~items ~where:d.del_where ~quals:fr.quals;
  walk_returning env cx scope d.del_returning
