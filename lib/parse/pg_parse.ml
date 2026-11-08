(* PostgreSQL parsing via libpg_query (Postgres 17 grammar), converted into
   Haltsql_core.Ast.

   Fail-closed design
   ------------------
   Every libpg_query node is converted by a function that first checks the
   node's keys against the exact set of keys we understand. Any unknown key,
   unknown enum value, unknown node type, or malformed shape raises [Unsup]
   internally. [Unsup] is caught at the nearest enclosing position that has an
   "unsupported" slot in the AST:

   - inside an expression          -> [Ast.Unsupported {node; loc}]
   - inside a FROM item            -> [Ast.Unsupported_from {node; loc}]
   - anywhere else in a statement  -> [Ast.Other {kind = "Unsupported:<what>"}]

   so nothing that could carry semantics is ever silently dropped.

   JSON conventions of libpg_query 17 (pg_query_parse):
   - nodes are {"NodeName": {fields}}; NULL list members are {};
   - zero ints, false bools and NULL pointers are omitted, so an absent
     "location" on a node that has a location field means byte 0;
   - "specific" sub-structures (SelectStmt.larg/rarg, withClause, intoClause,
     over, alias, typeName, relation, onConflictClause, infer) are written
     unwrapped, i.e. just {fields};
   - A_Const: {"ival":{"ival":n}} (ival 0 is {"ival":{}}), {"fval":{"fval":s}},
     {"sval":{"sval":s}}, {"boolval":{"boolval":true}} (false is {}),
     {"bsval":{"bsval":"b101"}}, {"isnull":true}; plus "location". *)

open Haltsql_core
module Raw = Haltsql_pgquery.Pgquery_raw

exception Unsup of string * int
(** [Unsup (what, loc)]: construct not mapped precisely. *)

type fields = (string * Yojson.Safe.t) list

let unsup ?(loc = -1) what = raise (Unsup (what, loc))

(* ------------------------------------------------------------------------ *)
(* Generic JSON helpers                                                      *)

let check_keys (node : string) (f : fields) (allowed : string list) (loc : int) =
  List.iter (fun (k, _) -> if not (List.mem k allowed) then unsup ~loc (node ^ "." ^ k)) f

let get (f : fields) k = List.assoc_opt k f

let int_field (f : fields) k =
  match get f k with
  | None -> None
  | Some (`Int i) -> Some i
  | Some (`Intlit _) -> unsup ("int overflow in " ^ k)
  | Some _ -> unsup ("malformed int " ^ k)

(** Location of a node that has a "location" field: absent means 0. *)
let loc_of (f : fields) = Option.value (int_field f "location") ~default:0

let bool_field (f : fields) k =
  match get f k with
  | None -> false
  | Some (`Bool b) -> b
  | Some _ -> unsup ("malformed bool " ^ k)

let string_field (f : fields) k =
  match get f k with
  | None -> None
  | Some (`String s) -> Some s
  | Some _ -> unsup ("malformed string " ^ k)

let list_field (f : fields) k =
  match get f k with
  | None -> []
  | Some (`List l) -> l
  | Some _ -> unsup ("malformed list " ^ k)

(** Unwrapped sub-structure, e.g. "withClause": {fields}. *)
let obj_field (f : fields) k : fields option =
  match get f k with
  | None -> None
  | Some (`Assoc o) -> Some o
  | Some _ -> unsup ("malformed object " ^ k)

(** A wrapped node {"Name": {fields}}. *)
let as_node (j : Yojson.Safe.t) : string * fields =
  match j with
  | `Assoc [ (name, `Assoc f) ] -> (name, f)
  | `Assoc [] -> unsup "NULL node"
  | _ -> unsup "malformed node"

let is_null_node = function `Assoc [] | `Null -> true | _ -> false

(** {"String": {"sval": s}} -> s *)
let string_node j =
  match as_node j with
  | "String", f ->
      check_keys "String" f [ "sval" ] (-1);
      Option.value (string_field f "sval") ~default:""
  | n, _ -> unsup ("expected String, got " ^ n)

let strings l = List.map string_node l

(* ------------------------------------------------------------------------ *)
(* Enumerations                                                              *)

let aexpr_kind loc = function
  | "AEXPR_OP" -> Ast.Op
  | "AEXPR_OP_ANY" -> Op_any
  | "AEXPR_OP_ALL" -> Op_all
  | "AEXPR_DISTINCT" -> Distinct
  | "AEXPR_NOT_DISTINCT" -> Not_distinct
  | "AEXPR_NULLIF" -> Nullif
  | "AEXPR_IN" -> In
  | "AEXPR_LIKE" -> Like
  | "AEXPR_ILIKE" -> Ilike
  | "AEXPR_SIMILAR" -> Similar
  | "AEXPR_BETWEEN" -> Between
  | "AEXPR_NOT_BETWEEN" -> Not_between
  | "AEXPR_BETWEEN_SYM" -> Between_sym
  | "AEXPR_NOT_BETWEEN_SYM" -> Not_between_sym
  | k -> unsup ~loc ("A_Expr." ^ k)

let sublink_kind = function
  | "EXISTS_SUBLINK" -> Ast.Exists
  | "ANY_SUBLINK" -> Any
  | "ALL_SUBLINK" -> All
  | "EXPR_SUBLINK" -> Expr
  | "ARRAY_SUBLINK" -> Array_sublink
  | k -> Other_sublink k

let sql_value_op loc = function
  | "SVFOP_CURRENT_DATE" -> "CURRENT_DATE"
  | "SVFOP_CURRENT_TIME" | "SVFOP_CURRENT_TIME_N" -> "CURRENT_TIME"
  | "SVFOP_CURRENT_TIMESTAMP" | "SVFOP_CURRENT_TIMESTAMP_N" -> "CURRENT_TIMESTAMP"
  | "SVFOP_LOCALTIME" | "SVFOP_LOCALTIME_N" -> "LOCALTIME"
  | "SVFOP_LOCALTIMESTAMP" | "SVFOP_LOCALTIMESTAMP_N" -> "LOCALTIMESTAMP"
  | "SVFOP_CURRENT_ROLE" -> "CURRENT_ROLE"
  | "SVFOP_CURRENT_USER" -> "CURRENT_USER"
  | "SVFOP_USER" -> "USER"
  | "SVFOP_SESSION_USER" -> "SESSION_USER"
  | "SVFOP_CURRENT_CATALOG" -> "CURRENT_CATALOG"
  | "SVFOP_CURRENT_SCHEMA" -> "CURRENT_SCHEMA"
  | k -> unsup ~loc ("SQLValueFunction." ^ k)

let locking_strength = function
  | "LCS_FORUPDATE" -> "FOR UPDATE"
  | "LCS_FORNOKEYUPDATE" -> "FOR NO KEY UPDATE"
  | "LCS_FORSHARE" -> "FOR SHARE"
  | "LCS_FORKEYSHARE" -> "FOR KEY SHARE"
  | k -> unsup ("LockingClause." ^ k)

(* ------------------------------------------------------------------------ *)
(* Names                                                                     *)

let qname_of_list loc (names : string list) : Ast.qname =
  match names with
  | [ name ] -> { schema = None; name }
  | [ schema; name ] -> { schema = Some schema; name }
  | _ -> unsup ~loc "qualified name with more than 2 parts"

let alias_of (f : fields) : Ast.alias =
  check_keys "Alias" f [ "aliasname"; "colnames" ] (-1);
  {
    aliasname = Option.value (string_field f "aliasname") ~default:"";
    colnames = strings (list_field f "colnames");
  }

let alias_field f = Option.map alias_of (obj_field f "alias")

(** RangeVar used as a target / base relation. Returns (qname, alias, inh, loc). *)
let range_var (f : fields) =
  let loc = loc_of f in
  check_keys "RangeVar" f
    [
      "catalogname"; "schemaname"; "relname"; "inh"; "relpersistence"; "alias"; "location";
    ]
    loc;
  if Option.is_some (get f "catalogname") then
    unsup ~loc "RangeVar (catalog-qualified name)";
  (match string_field f "relpersistence" with
  | None | Some "p" -> ()
  | Some p -> unsup ~loc ("RangeVar.relpersistence=" ^ p));
  let name =
    match string_field f "relname" with
    | Some n -> n
    | None -> unsup ~loc "RangeVar without relname"
  in
  let rel : Ast.qname = { schema = string_field f "schemaname"; name } in
  (rel, alias_field f, bool_field f "inh", loc)

(* ------------------------------------------------------------------------ *)
(* Constants                                                                 *)

let a_const (f : fields) : Ast.const =
  let loc = loc_of f in
  check_keys "A_Const" f
    [ "ival"; "fval"; "sval"; "boolval"; "bsval"; "isnull"; "location" ]
    loc;
  (* [present_inner k]: the {k: {k: ...}} wrapper of a key known to be present
     (selected by the match on [present] below), checked to hold only [k]. *)
  let present_inner k =
    match get f k with
    | Some (`Assoc o) ->
        check_keys ("A_Const." ^ k) o [ k ] loc;
        o
    | Some _ -> unsup ~loc ("malformed A_Const." ^ k)
    | None -> unsup ~loc ("A_Const without " ^ k)
  in
  let present = List.filter (fun (k, _) -> k <> "location") f |> List.map fst in
  match present with
  | [ "isnull" ] ->
      if bool_field f "isnull" then Null else unsup ~loc "A_Const.isnull=false"
  | [ "ival" ] -> (
      let o = present_inner "ival" in
      match get o "ival" with
      | None -> Int "0"
      | Some (`Int i) -> Int (string_of_int i)
      | Some (`Intlit s) -> Int s
      | Some _ -> unsup ~loc "malformed A_Const.ival")
  | [ "fval" ] -> (
      let o = present_inner "fval" in
      match string_field o "fval" with
      | Some s -> Float s
      | None -> unsup ~loc "A_Const.fval without value")
  | [ "sval" ] ->
      let o = present_inner "sval" in
      String (Option.value (string_field o "sval") ~default:"")
  | [ "boolval" ] ->
      let o = present_inner "boolval" in
      Bool (bool_field o "boolval")
  | [ "bsval" ] -> (
      let o = present_inner "bsval" in
      match string_field o "bsval" with
      | Some s -> Bit_string s
      | None -> unsup ~loc "A_Const.bsval without value")
  | _ -> unsup ~loc "malformed A_Const"

(** Constant-only expression used where the AST has no slot (window frame offsets, type
    modifiers): A_Const, possibly under TypeCasts. *)
let rec is_simple_const j =
  match j with
  | `Assoc [ ("A_Const", `Assoc _) ] -> true
  | `Assoc [ ("TypeCast", `Assoc f) ] -> (
      match get f "arg" with Some a -> is_simple_const a | None -> false)
  | _ -> false

(* ------------------------------------------------------------------------ *)
(* Expressions, selects, FROM items                                          *)

let type_name (f : fields) : Ast.type_name =
  let loc = loc_of f in
  check_keys "TypeName" f [ "names"; "typmods"; "typemod"; "arrayBounds"; "location" ] loc;
  List.iter
    (fun m -> if not (is_simple_const m) then unsup ~loc "TypeName.typmods")
    (list_field f "typmods");
  let names = strings (list_field f "names") in
  if names = [] then unsup ~loc "TypeName without names";
  {
    type_names = names;
    array_bounds = List.length (list_field f "arrayBounds");
    type_loc = loc;
  }

let rec expr (j : Yojson.Safe.t) : Ast.expr =
  match j with
  | `Assoc [ (name, `Assoc f) ] -> (
      let loc =
        match int_field f "location" with
        | Some l -> l
        | None -> -1
        | exception Unsup _ -> -1
      in
      try expr_node name f
      with Unsup (what, l) ->
        Unsupported { node = what; loc = (if l >= 0 then l else max loc (-1)) })
  | _ -> Unsupported { node = "malformed expression"; loc = -1 }

and expr_opt f k = Option.map expr (get f k)
and exprs l = List.map expr l

and expr_node (name : string) (f : fields) : Ast.expr =
  let loc = loc_of f in
  let keys ks = check_keys name f ks loc in
  match name with
  | "ColumnRef" ->
      keys [ "fields"; "location" ];
      let field j =
        match as_node j with
        | "String", _ -> Ast.Name (string_node j)
        | "A_Star", sf ->
            check_keys "A_Star" sf [] loc;
            Star
        | n, _ -> unsup ~loc ("ColumnRef field " ^ n)
      in
      let fields = List.map field (list_field f "fields") in
      if fields = [] then unsup ~loc "ColumnRef without fields";
      Column_ref { fields; loc }
  | "A_Const" -> Const { value = a_const f; loc }
  | "ParamRef" ->
      keys [ "number"; "location" ];
      Param { number = Option.value (int_field f "number") ~default:0; loc }
  | "A_Expr" ->
      keys [ "kind"; "name"; "lexpr"; "rexpr"; "location" ];
      let kind =
        match string_field f "kind" with
        | Some k -> aexpr_kind loc k
        | None -> unsup ~loc "A_Expr without kind"
      in
      let side k =
        match get f k with
        | None -> None
        | Some (`Assoc [ ("List", `Assoc lf) ]) ->
            (* IN (list) and BETWEEN bounds: represented as a Row. *)
            check_keys "List" lf [ "items" ] loc;
            Some (Ast.Row { args = exprs (list_field lf "items"); loc })
        | Some e -> Some (expr e)
      in
      A_expr
        {
          kind;
          name = strings (list_field f "name");
          lexpr = side "lexpr";
          rexpr = side "rexpr";
          loc;
        }
  | "BoolExpr" ->
      keys [ "boolop"; "args"; "location" ];
      let op =
        match string_field f "boolop" with
        | Some "AND_EXPR" -> Ast.And
        | Some "OR_EXPR" -> Or
        | Some "NOT_EXPR" -> Not
        | _ -> unsup ~loc "BoolExpr.boolop"
      in
      Bool_expr { op; args = exprs (list_field f "args"); loc }
  | "FuncCall" ->
      keys
        [
          "funcname";
          "args";
          "agg_order";
          "agg_filter";
          "over";
          "agg_within_group";
          "agg_star";
          "agg_distinct";
          "func_variadic";
          "funcformat";
          "location";
        ];
      (match string_field f "funcformat" with
      | None | Some ("COERCE_EXPLICIT_CALL" | "COERCE_SQL_SYNTAX") -> ()
      | Some ff -> unsup ~loc ("FuncCall.funcformat=" ^ ff));
      let fname = qname_of_list loc (strings (list_field f "funcname")) in
      Func_call
        {
          fname;
          args = exprs (list_field f "args");
          agg_star = bool_field f "agg_star";
          agg_distinct = bool_field f "agg_distinct";
          agg_filter = expr_opt f "agg_filter";
          (* WITHIN GROUP (ORDER BY ...) is kept as agg_order: every
             expression stays visible; ordered-set aggregates are identified
             by function name. *)
          agg_order = List.map sort_by (list_field f "agg_order");
          over = Option.map window_def (obj_field f "over");
          variadic = bool_field f "func_variadic";
          loc;
        }
  | "TypeCast" ->
      keys [ "arg"; "typeName"; "location" ];
      let arg =
        match get f "arg" with Some a -> expr a | None -> unsup ~loc "TypeCast.arg"
      in
      let tn =
        match obj_field f "typeName" with
        | Some t -> type_name t
        | None -> unsup ~loc "TypeCast.typeName"
      in
      Type_cast { arg; type_name = tn; loc }
  | "SubLink" ->
      keys [ "subLinkType"; "testexpr"; "operName"; "subselect"; "location" ];
      let kind =
        match string_field f "subLinkType" with
        | Some k -> sublink_kind k
        | None -> unsup ~loc "SubLink.subLinkType"
      in
      let oper = strings (list_field f "operName") in
      (* x IN (subquery) is ANY_SUBLINK without operName, i.e. = ANY. *)
      let oper = if kind = Any && oper = [] then [ "=" ] else oper in
      let subselect =
        match get f "subselect" with
        | Some j -> (
            match as_node j with
            | "SelectStmt", sf -> select ~loc sf
            | n, _ -> unsup ~loc ("SubLink.subselect " ^ n))
        | None -> unsup ~loc "SubLink without subselect"
      in
      Sub_link { kind; testexpr = expr_opt f "testexpr"; oper; subselect; loc }
  | "CaseExpr" ->
      keys [ "arg"; "args"; "defresult"; "location" ];
      let when_ j =
        match as_node j with
        | "CaseWhen", wf ->
            let wloc = loc_of wf in
            check_keys "CaseWhen" wf [ "expr"; "result"; "location" ] wloc;
            let req k =
              match get wf k with
              | Some e -> expr e
              | None -> unsup ~loc:wloc ("CaseWhen." ^ k ^ " missing")
            in
            (req "expr", req "result")
        | n, _ -> unsup ~loc ("CaseExpr arm " ^ n)
      in
      Case
        {
          arg = expr_opt f "arg";
          whens = List.map when_ (list_field f "args");
          default = expr_opt f "defresult";
          loc;
        }
  | "NullTest" ->
      keys [ "arg"; "nulltesttype"; "location" ];
      let is_null =
        match string_field f "nulltesttype" with
        | Some "IS_NULL" -> true
        | Some "IS_NOT_NULL" -> false
        | _ -> unsup ~loc "NullTest.nulltesttype"
      in
      let arg =
        match get f "arg" with Some a -> expr a | None -> unsup ~loc "NullTest.arg"
      in
      Null_test { arg; is_null; loc }
  | "BooleanTest" ->
      keys [ "arg"; "booltesttype"; "location" ];
      let test =
        match string_field f "booltesttype" with
        | Some
            (( "IS_TRUE" | "IS_NOT_TRUE" | "IS_FALSE" | "IS_NOT_FALSE" | "IS_UNKNOWN"
             | "IS_NOT_UNKNOWN" ) as t) ->
            t
        | _ -> unsup ~loc "BooleanTest.booltesttype"
      in
      let arg =
        match get f "arg" with Some a -> expr a | None -> unsup ~loc "BooleanTest.arg"
      in
      Boolean_test { arg; test; loc }
  | "CoalesceExpr" ->
      keys [ "args"; "location" ];
      Coalesce { args = exprs (list_field f "args"); loc }
  | "MinMaxExpr" ->
      keys [ "op"; "args"; "location" ];
      let greatest =
        match string_field f "op" with
        | Some "IS_GREATEST" -> true
        | Some "IS_LEAST" -> false
        | _ -> unsup ~loc "MinMaxExpr.op"
      in
      Min_max { greatest; args = exprs (list_field f "args"); loc }
  | "RowExpr" ->
      keys [ "args"; "row_format"; "location" ];
      (match string_field f "row_format" with
      | None | Some ("COERCE_EXPLICIT_CALL" | "COERCE_IMPLICIT_CAST") -> ()
      | Some rf -> unsup ~loc ("RowExpr.row_format=" ^ rf));
      Row { args = exprs (list_field f "args"); loc }
  | "A_ArrayExpr" ->
      keys [ "elements"; "location" ];
      Array { elements = exprs (list_field f "elements"); loc }
  | "A_Indirection" ->
      keys [ "arg"; "indirection" ];
      let loc = -1 in
      let arg =
        match get f "arg" with Some a -> expr a | None -> unsup "A_Indirection.arg"
      in
      let items = list_field f "indirection" in
      let subscripts, fields =
        List.fold_left
          (fun (subs, flds) j ->
            match as_node j with
            | "String", _ -> (subs, Ast.Name (string_node j) :: flds)
            | "A_Star", sf ->
                check_keys "A_Star" sf [] loc;
                (subs, Ast.Star :: flds)
            | "A_Indices", xf ->
                check_keys "A_Indices" xf [ "is_slice"; "lidx"; "uidx" ] loc;
                if bool_field xf "is_slice" || Option.is_some (get xf "lidx") then
                  unsup "A_Indices (array slice)";
                if flds <> [] then unsup "A_Indirection (subscript after field selection)";
                let u =
                  match get xf "uidx" with
                  | Some u -> expr u
                  | None -> unsup "A_Indices without index"
                in
                (u :: subs, flds)
            | n, _ -> unsup ("A_Indirection item " ^ n))
          ([], []) items
      in
      if items = [] then unsup "A_Indirection without indirection";
      Indirection { arg; subscripts = List.rev subscripts; fields = List.rev fields; loc }
  | "CollateClause" ->
      keys [ "arg"; "collname"; "location" ];
      let arg =
        match get f "arg" with Some a -> expr a | None -> unsup ~loc "CollateClause.arg"
      in
      Collate { arg; collation = strings (list_field f "collname"); loc }
  | "SQLValueFunction" ->
      keys [ "op"; "typmod"; "location" ];
      let op =
        match string_field f "op" with
        | Some o -> sql_value_op loc o
        | None -> unsup ~loc "SQLValueFunction.op"
      in
      Sql_value { op; loc }
  | other ->
      (* GroupingFunc, SetToDefault, XmlExpr, Json*, MultiAssignRef outside
         UPDATE, ... *)
      unsup ~loc other

and sort_by (j : Yojson.Safe.t) : Ast.sort_by =
  match as_node j with
  | "SortBy", f ->
      let loc = loc_of f in
      let sort_loc = loc in
      let bad what = Ast.Unsupported { node = what; loc } in
      let known =
        List.for_all
          (fun (k, _) -> List.mem k [ "node"; "sortby_dir"; "sortby_nulls"; "location" ])
          f
      in
      if not known then
        let k =
          List.find
            (fun (k, _) ->
              not (List.mem k [ "node"; "sortby_dir"; "sortby_nulls"; "location" ]))
            f
          |> fst
        in
        { sort_expr = bad ("SortBy." ^ k); sort_loc }
      else
        let dir_ok =
          match string_field f "sortby_dir" with
          | None | Some ("SORTBY_DEFAULT" | "SORTBY_ASC" | "SORTBY_DESC") -> true
          | Some _ -> false
        in
        let nulls_ok =
          match string_field f "sortby_nulls" with
          | None
          | Some ("SORTBY_NULLS_DEFAULT" | "SORTBY_NULLS_FIRST" | "SORTBY_NULLS_LAST") ->
              true
          | Some _ -> false
        in
        if not dir_ok then { sort_expr = bad "SortBy (USING operator)"; sort_loc }
        else if not nulls_ok then { sort_expr = bad "SortBy.sortby_nulls"; sort_loc }
        else
          let sort_expr =
            match get f "node" with
            | Some e -> expr e
            | None -> bad "SortBy without expression"
          in
          { sort_expr; sort_loc }
  | n, _ -> { sort_expr = Unsupported { node = n; loc = -1 }; sort_loc = -1 }

and window_def (f : fields) : Ast.window_def =
  let loc = loc_of f in
  check_keys "WindowDef" f
    [
      "name";
      "refname";
      "partitionClause";
      "orderClause";
      "frameOptions";
      "startOffset";
      "endOffset";
      "location";
    ]
    loc;
  if Option.is_some (get f "refname") then
    unsup ~loc "WindowDef (window referencing another window)";
  (* Frame clauses carry no table or column access; their offsets are only
     accepted when they are plain constants (otherwise they could hide a
     subquery we would not see). *)
  List.iter
    (fun k ->
      match get f k with
      | Some o when not (is_simple_const o) ->
          unsup ~loc ("WindowDef." ^ k ^ " (non-constant frame offset)")
      | _ -> ())
    [ "startOffset"; "endOffset" ];
  {
    win_name = string_field f "name";
    partition_by = exprs (list_field f "partitionClause");
    win_order_by = List.map sort_by (list_field f "orderClause");
    win_loc = loc;
  }

and target (j : Yojson.Safe.t) : Ast.target =
  match as_node j with
  | "ResTarget", f ->
      let loc = loc_of f in
      let expr_ =
        try
          check_keys "ResTarget" f [ "name"; "val"; "location" ] loc;
          match get f "val" with
          | Some v -> expr v
          | None -> unsup ~loc "ResTarget without value"
        with Unsup (w, l) ->
          Ast.Unsupported { node = w; loc = (if l >= 0 then l else loc) }
      in
      let alias = try string_field f "name" with Unsup _ -> None in
      { expr = expr_; alias; target_loc = loc }
  | n, _ -> { expr = Unsupported { node = n; loc = -1 }; alias = None; target_loc = -1 }

and with_clause (f : fields) : Ast.with_clause =
  let loc = loc_of f in
  check_keys "WithClause" f [ "ctes"; "recursive"; "location" ] loc;
  {
    recursive = bool_field f "recursive";
    ctes = List.map cte (list_field f "ctes");
    with_loc = loc;
  }

and cte (j : Yojson.Safe.t) : Ast.cte =
  match as_node j with
  | "CommonTableExpr", f ->
      let loc = loc_of f in
      let cte_name = Option.value (string_field f "ctename") ~default:"" in
      let cte_colnames = strings (list_field f "aliascolnames") in
      let cte_query =
        try
          check_keys "CommonTableExpr" f
            [ "ctename"; "aliascolnames"; "ctematerialized"; "ctequery"; "location" ]
            loc;
          (match string_field f "ctematerialized" with
          | None
          | Some ("CTEMaterializeDefault" | "CTEMaterializeAlways" | "CTEMaterializeNever")
            ->
              ()
          | Some m -> unsup ~loc ("CommonTableExpr.ctematerialized=" ^ m));
          match get f "ctequery" with
          | Some q -> stmt_of_node ~loc q
          | None -> unsup ~loc "CommonTableExpr without query"
        with Unsup (w, l) ->
          Ast.Other { kind = "Unsupported:" ^ w; loc = (if l >= 0 then l else loc) }
      in
      { cte_name; cte_colnames; cte_query; cte_loc = loc }
  | n, _ -> unsup ("WITH item " ^ n)

and select ~loc (f : fields) : Ast.select =
  check_keys "SelectStmt" f
    [
      "distinctClause";
      "intoClause";
      "targetList";
      "fromClause";
      "whereClause";
      "groupClause";
      "havingClause";
      "windowClause";
      "valuesLists";
      "sortClause";
      "limitOffset";
      "limitCount";
      "limitOption";
      "lockingClause";
      "withClause";
      "op";
      "all";
      "larg";
      "rarg";
    ]
    loc;
  (match string_field f "limitOption" with
  | None | Some ("LIMIT_OPTION_DEFAULT" | "LIMIT_OPTION_COUNT") -> ()
  | Some o -> unsup ~loc ("SelectStmt.limitOption=" ^ o));
  let with_ = Option.map with_clause (obj_field f "withClause") in
  let order_by = List.map sort_by (list_field f "sortClause") in
  let limit_count, limit_all =
    match get f "limitCount" with
    | None -> (None, false)
    | Some (`Assoc [ ("A_Const", `Assoc cf) ])
      when try a_const cf = Null with Unsup _ -> false ->
        (* LIMIT ALL (and LIMIT NULL, which means the same) *)
        (None, true)
    | Some e -> (Some (expr e), false)
  in
  let limit_offset = expr_opt f "limitOffset" in
  let locking =
    List.map
      (fun j ->
        match as_node j with
        | "LockingClause", lf -> (
            check_keys "LockingClause" lf [ "lockedRels"; "strength"; "waitPolicy" ] loc;
            match string_field lf "strength" with
            | Some s -> locking_strength s
            | None -> unsup ~loc "LockingClause.strength")
        | n, _ -> unsup ~loc ("lockingClause item " ^ n))
      (list_field f "lockingClause")
  in
  let simple_keys =
    [
      "distinctClause";
      "intoClause";
      "targetList";
      "fromClause";
      "whereClause";
      "groupClause";
      "havingClause";
      "windowClause";
    ]
  in
  let has k = Option.is_some (get f k) in
  let body : Ast.select_body =
    match string_field f "op" with
    | None | Some "SETOP_NONE" ->
        if has "larg" || has "rarg" || bool_field f "all" then
          unsup ~loc "SelectStmt (set-operation arguments without operator)";
        if has "valuesLists" then begin
          List.iter
            (fun k -> if has k then unsup ~loc ("VALUES with SelectStmt." ^ k))
            simple_keys;
          Values
            (List.map
               (fun j ->
                 match as_node j with
                 | "List", lf ->
                     check_keys "List" lf [ "items" ] loc;
                     exprs (list_field lf "items")
                 | n, _ -> unsup ~loc ("VALUES row " ^ n))
               (list_field f "valuesLists"))
        end
        else Simple (simple_select ~loc f)
    | Some op ->
        let op =
          match op with
          | "SETOP_UNION" -> Ast.Union
          | "SETOP_INTERSECT" -> Intersect
          | "SETOP_EXCEPT" -> Except
          | o -> unsup ~loc ("SelectStmt.op=" ^ o)
        in
        List.iter
          (fun k -> if has k then unsup ~loc ("set operation with SelectStmt." ^ k))
          ("valuesLists" :: simple_keys);
        let arg k =
          match obj_field f k with
          | Some a -> select ~loc a
          | None -> unsup ~loc ("set operation without " ^ k)
        in
        let larg = arg "larg" in
        let rarg = arg "rarg" in
        Set_op { op; all = bool_field f "all"; larg; rarg }
  in
  { with_; body; order_by; limit_count; limit_all; limit_offset; locking; sel_loc = loc }

and simple_select ~loc (f : fields) : Ast.simple_select =
  let distinct =
    match get f "distinctClause" with
    | None -> None
    | Some (`List [ n ]) when is_null_node n -> Some []
    | Some (`List l) -> Some (exprs l)
    | Some _ -> unsup ~loc "malformed distinctClause"
  in
  let group_item j =
    match j with
    | `Assoc [ ("GroupingSet", `Assoc gf) ] ->
        Ast.Unsupported { node = "GroupingSet"; loc = loc_of gf }
    | e -> expr e
  in
  {
    distinct;
    targets = List.map target (list_field f "targetList");
    into = Option.is_some (get f "intoClause");
    from = List.map from_item (list_field f "fromClause");
    where = expr_opt f "whereClause";
    group_by = List.map group_item (list_field f "groupClause");
    having = expr_opt f "havingClause";
    windows =
      List.map
        (fun j ->
          match as_node j with
          | "WindowDef", wf -> window_def wf
          | n, _ -> unsup ~loc ("windowClause item " ^ n))
        (list_field f "windowClause");
  }

and from_item (j : Yojson.Safe.t) : Ast.from_item =
  match j with
  | `Assoc [ (name, `Assoc f) ] -> (
      let loc = try loc_of f with Unsup _ -> -1 in
      try from_node name f
      with Unsup (what, l) ->
        Unsupported_from { node = what; loc = (if l >= 0 then l else loc) })
  | _ -> Unsupported_from { node = "malformed FROM item"; loc = -1 }

and from_node name (f : fields) : Ast.from_item =
  match name with
  | "RangeVar" ->
      let rel, alias, inh, loc = range_var f in
      Relation { rel; alias; inh; loc }
  | "JoinExpr" ->
      let loc = -1 in
      check_keys "JoinExpr" f
        [ "jointype"; "isNatural"; "larg"; "rarg"; "usingClause"; "quals"; "alias" ]
        loc;
      let natural = bool_field f "isNatural" in
      let using = strings (list_field f "usingClause") in
      let quals = expr_opt f "quals" in
      let kind =
        match string_field f "jointype" with
        | Some "JOIN_INNER" ->
            if (not natural) && using = [] && quals = None then Ast.Cross else Inner
        | Some "JOIN_LEFT" -> Left
        | Some "JOIN_RIGHT" -> Right
        | Some "JOIN_FULL" -> Full
        | Some k -> unsup ("JoinExpr.jointype=" ^ k)
        | None -> unsup "JoinExpr without jointype"
      in
      let side k =
        match get f k with
        | Some s -> from_item s
        | None -> unsup ("JoinExpr without " ^ k)
      in
      let left = side "larg" in
      let right = side "rarg" in
      (* JoinExpr has no location in libpg_query; use the left input's. *)
      (* a nested Join already carries its own first location: O(1) *)
      let first_loc : Ast.from_item -> int = function
        | Relation { loc; _ }
        | Subquery { loc; _ }
        | Function { loc; _ }
        | Unsupported_from { loc; _ }
        | Join { loc; _ } ->
            loc
      in
      Join
        {
          kind;
          natural;
          left;
          right;
          quals;
          using;
          alias = alias_field f;
          loc = first_loc left;
        }
  | "RangeSubselect" ->
      check_keys "RangeSubselect" f [ "lateral"; "subquery"; "alias" ] (-1);
      let query =
        match get f "subquery" with
        | Some q -> (
            match as_node q with
            | "SelectStmt", sf -> select ~loc:(-1) sf
            | n, _ -> unsup ("RangeSubselect.subquery " ^ n))
        | None -> unsup "RangeSubselect without subquery"
      in
      let loc = query_loc query in
      Subquery { lateral = bool_field f "lateral"; query; alias = alias_field f; loc }
  | "RangeFunction" ->
      check_keys "RangeFunction" f
        [ "lateral"; "ordinality"; "is_rowsfrom"; "functions"; "alias" ]
        (-1);
      if bool_field f "is_rowsfrom" then unsup "RangeFunction (ROWS FROM)";
      let calls =
        List.map
          (fun j ->
            match as_node j with
            | "List", lf -> (
                check_keys "List" lf [ "items" ] (-1);
                match list_field lf "items" with
                | [ call ] -> expr call
                | [ call; coldef ] when is_null_node coldef -> expr call
                | _ -> unsup "RangeFunction (column definition list)")
            | n, _ -> unsup ("RangeFunction item " ^ n))
          (list_field f "functions")
      in
      if calls = [] then unsup "RangeFunction without function";
      let loc = match calls with Func_call { loc; _ } :: _ -> loc | _ -> -1 in
      Function
        {
          lateral = bool_field f "lateral";
          calls;
          ordinality = bool_field f "ordinality";
          alias = alias_field f;
          loc;
        }
  | other -> unsup other

(** Best-effort location of a select that has none in libpg_query: the first target / FROM
    item. *)
and query_loc (s : Ast.select) : int =
  match s.body with
  | Simple { targets = t :: _; _ } -> t.target_loc
  | Simple { from = Relation { loc; _ } :: _; _ } -> loc
  | Set_op { larg; _ } -> query_loc larg
  | _ -> -1

(* ------------------------------------------------------------------------ *)
(* Statements                                                                *)

and target_rel (f : fields) k =
  match obj_field f k with
  | Some r ->
      let rel, alias, _inh, loc = range_var r in
      (rel, alias, loc)
  | None -> unsup ("statement without " ^ k)

and returning f = List.map target (list_field f "returningList")

and insert ~loc (f : fields) : Ast.insert =
  check_keys "InsertStmt" f
    [
      "relation";
      "cols";
      "selectStmt";
      "onConflictClause";
      "returningList";
      "withClause";
      "override";
    ]
    loc;
  (match string_field f "override" with
  | None | Some "OVERRIDING_NOT_SET" -> ()
  | Some o -> unsup ~loc ("InsertStmt.override=" ^ o));
  let ins_rel, ins_alias, _ = target_rel f "relation" in
  let ins_cols =
    List.map
      (fun j ->
        match as_node j with
        | "ResTarget", rf -> (
            let rloc = loc_of rf in
            check_keys "ResTarget" rf [ "name"; "location" ] rloc;
            match string_field rf "name" with
            | Some n -> n
            | None -> unsup ~loc:rloc "INSERT column without name")
        | n, _ -> unsup ~loc ("INSERT column " ^ n))
      (list_field f "cols")
  in
  let ins_source =
    match get f "selectStmt" with
    | None -> None
    | Some j -> (
        match as_node j with
        | "SelectStmt", sf -> Some (select ~loc sf)
        | n, _ -> unsup ~loc ("InsertStmt.selectStmt " ^ n))
  in
  let on_conflict =
    match obj_field f "onConflictClause" with
    | None -> false
    | Some oc ->
        let oloc = loc_of oc in
        check_keys "OnConflictClause" oc [ "action"; "infer"; "location" ] oloc;
        (match string_field oc "action" with
        | Some "ONCONFLICT_NOTHING" -> ()
        | Some a -> unsup ~loc:oloc ("OnConflictClause.action=" ^ a)
        | None -> unsup ~loc:oloc "OnConflictClause without action");
        (match obj_field oc "infer" with
        | None -> ()
        | Some inf ->
            let iloc = loc_of inf in
            check_keys "InferClause" inf [ "indexElems"; "location" ] iloc;
            List.iter
              (fun e ->
                match as_node e with
                | "IndexElem", ef ->
                    check_keys "IndexElem" ef
                      [ "name"; "ordering"; "nulls_ordering" ]
                      iloc;
                    if Option.is_none (get ef "name") then
                      unsup ~loc:iloc "IndexElem without column name"
                | n, _ -> unsup ~loc:iloc ("InferClause item " ^ n))
              (list_field inf "indexElems"));
        true
  in
  {
    ins_with = Option.map with_clause (obj_field f "withClause");
    ins_rel;
    ins_alias;
    ins_cols;
    ins_source;
    on_conflict;
    ins_returning = returning f;
    ins_loc = loc;
  }

and update ~loc (f : fields) : Ast.update =
  check_keys "UpdateStmt" f
    [
      "relation"; "targetList"; "whereClause"; "fromClause"; "returningList"; "withClause";
    ]
    loc;
  let upd_rel, upd_alias, _ = target_rel f "relation" in
  let set_item j =
    match as_node j with
    | "ResTarget", rf ->
        let rloc = loc_of rf in
        let name =
          match string_field rf "name" with
          | Some n -> n
          | None -> unsup ~loc:rloc "SET target without name"
        in
        let value =
          try
            check_keys "ResTarget" rf [ "name"; "val"; "location" ] rloc;
            match get rf "val" with
            | Some (`Assoc [ ("MultiAssignRef", `Assoc mf) ]) -> (
                check_keys "MultiAssignRef" mf [ "source"; "colno"; "ncolumns" ] rloc;
                let colno = Option.value (int_field mf "colno") ~default:0 in
                match get mf "source" with
                | Some (`Assoc [ ("RowExpr", `Assoc xf) ]) -> (
                    let args = list_field xf "args" in
                    match List.nth_opt args (colno - 1) with
                    | Some a when colno >= 1 -> (
                        (* validate the row node itself as well *)
                        match expr_node "RowExpr" xf with
                        | Ast.Row _ -> expr a
                        | e -> e)
                    | _ -> unsup ~loc:rloc "MultiAssignRef column out of range")
                | _ -> unsup ~loc:rloc "MultiAssignRef (sub-select source)")
            | Some v -> expr v
            | None -> unsup ~loc:rloc "SET target without value"
          with Unsup (w, l) ->
            Ast.Unsupported { node = w; loc = (if l >= 0 then l else rloc) }
        in
        (name, value)
    | n, _ -> unsup ~loc ("SET item " ^ n)
  in
  {
    upd_with = Option.map with_clause (obj_field f "withClause");
    upd_rel;
    upd_alias;
    set = List.map set_item (list_field f "targetList");
    upd_from = List.map from_item (list_field f "fromClause");
    upd_where = expr_opt f "whereClause";
    upd_returning = returning f;
    upd_loc = loc;
  }

and delete ~loc (f : fields) : Ast.delete =
  check_keys "DeleteStmt" f
    [ "relation"; "usingClause"; "whereClause"; "returningList"; "withClause" ]
    loc;
  let del_rel, del_alias, _ = target_rel f "relation" in
  {
    del_with = Option.map with_clause (obj_field f "withClause");
    del_rel;
    del_alias;
    using = List.map from_item (list_field f "usingClause");
    del_where = expr_opt f "whereClause";
    del_returning = returning f;
    del_loc = loc;
  }

and explain ~loc (f : fields) : Ast.stmt =
  check_keys "ExplainStmt" f [ "query"; "options" ] loc;
  let opts =
    List.map
      (fun j ->
        match as_node j with
        | "DefElem", df ->
            let dloc = loc_of df in
            check_keys "DefElem" df
              [ "defname"; "arg"; "defaction"; "location"; "arg_location" ]
              dloc;
            let name = Option.value (string_field df "defname") ~default:"" in
            (* An option is "off" only when its argument is explicitly a false
               value; anything else (absent, true, on, 1, unknown) counts as
               on, which is the fail-closed reading for ANALYZE. *)
            let off =
              match get df "arg" with
              | None -> false
              | Some a -> (
                  match as_node a with
                  | "String", _ -> (
                      match String.lowercase_ascii (string_node a) with
                      | "false" | "off" | "no" | "0" -> true
                      | _ -> false)
                  | "Integer", inf -> (
                      match int_field inf "ival" with None | Some 0 -> true | _ -> false)
                  | "Boolean", bf -> not (bool_field bf "boolval")
                  | _ -> false
                  | exception Unsup _ -> false)
            in
            (name, off)
        | n, _ -> unsup ~loc ("EXPLAIN option " ^ n))
      (list_field f "options")
  in
  let analyze =
    List.exists (fun (n, off) -> String.lowercase_ascii n = "analyze" && not off) opts
  in
  let stmt =
    match get f "query" with
    | Some q -> stmt_of_node ~loc q
    | None -> unsup ~loc "EXPLAIN without statement"
  in
  Explain { analyze; options = List.map fst opts; stmt; loc }

(** Convert a wrapped statement node. Raises [Unsup]. *)
and stmt_of_node ~loc (j : Yojson.Safe.t) : Ast.stmt =
  let name, f = as_node j in
  match name with
  | "SelectStmt" -> Select (select ~loc f)
  | "InsertStmt" -> Insert (insert ~loc f)
  | "UpdateStmt" -> Update (update ~loc f)
  | "DeleteStmt" -> Delete (delete ~loc f)
  | "ExplainStmt" -> explain ~loc f
  | other -> Other { kind = other; loc }

let stmt ~loc j : Ast.stmt =
  try stmt_of_node ~loc j
  with Unsup (w, l) ->
    Other { kind = "Unsupported:" ^ w; loc = (if l >= 0 then l else loc) }

(* ------------------------------------------------------------------------ *)
(* Limits                                                                    *)

(** Node depth and node count of the libpg_query JSON tree, computed
    iteratively. A wrapped node ({"Name": {fields}}) counts as one node; an
    unwrapped sub-structure ({fields}, e.g. a set-operation arm) also counts as
    one. Lists and scalars do not count. Stops early once a limit is
    exceeded. *)
let tree_metrics ~max_depth ~max_nodes (j : Yojson.Safe.t) =
  let nodes = ref 0 and depth = ref 0 in
  let stack = ref [ (j, 0) ] in
  let exceeded () = !depth > max_depth || !nodes > max_nodes in
  while !stack <> [] && not (exceeded ()) do
    match !stack with
    | [] -> ()
    | (v, d) :: rest -> (
        stack := rest;
        let push_children d kvs =
          List.iter (fun (_, c) -> stack := (c, d) :: !stack) kvs
        in
        match v with
        | `Assoc [ (k, `Assoc inner) ]
          when String.length k > 0 && Char.uppercase_ascii k.[0] = k.[0] && k.[0] <> '_'
          ->
            incr nodes;
            let d = d + 1 in
            if d > !depth then depth := d;
            push_children d inner
        | `Assoc [] -> ()
        | `Assoc kvs ->
            incr nodes;
            let d = d + 1 in
            if d > !depth then depth := d;
            push_children d kvs
        | `List l -> List.iter (fun c -> stack := (c, d) :: !stack) l
        | _ -> ())
  done;
  (!depth, !nodes)

(* Backstop only. libpg_query runs on large-stack worker threads inside
   Haltsql_pgquery, and normal enforcement is the policy's max_depth /
   max_nodes on the parse tree (measured iteratively, before any recursive
   conversion). This lexical check rejects absurd bracket nesting cheaply,
   before the C parser and Yojson ever see it. Brackets are counted
   everywhere, including inside literals and comments, so it can only
   over-count (fail closed). *)

let hard_nesting_bound = 10_000

let max_bracket_nesting (s : string) =
  let cur = ref 0 and best = ref 0 in
  String.iter
    (function
      | '(' | '[' ->
          incr cur;
          if !cur > !best then best := !cur
      | ')' | ']' -> if !cur > 0 then decr cur
      | _ -> ())
    s;
  !best

let prescan (s : string) : string option =
  let nesting = max_bracket_nesting s in
  if nesting > hard_nesting_bound then
    Some
      (Printf.sprintf "query nests brackets %d deep; the limit is %d" nesting
         hard_nesting_bound)
  else None

let rule = "parse"

let limit_error ?loc msg =
  Error
    (Reason.make ?loc ~rule
       ~hint:"Simplify the query: it is too large or too deeply nested." Reason.E_LIMIT
       msg)

(* ------------------------------------------------------------------------ *)
(* Entry points                                                              *)

let convert_tree (tree : Yojson.Safe.t) : (Ast.stmt list, Reason.t) result =
  match tree with
  | `Assoc top -> (
      match List.assoc_opt "stmts" top with
      | Some (`List raws) ->
          Ok
            (List.map
               (fun raw ->
                 match raw with
                 | `Assoc rf -> (
                     let loc =
                       match List.assoc_opt "stmt_location" rf with
                       | Some (`Int l) -> l
                       | _ -> 0
                     in
                     let unknown =
                       List.find_opt
                         (fun (k, _) ->
                           not (List.mem k [ "stmt"; "stmt_location"; "stmt_len" ]))
                         rf
                     in
                     match (unknown, List.assoc_opt "stmt" rf) with
                     | Some (k, _), _ ->
                         Ast.Other { kind = "Unsupported:RawStmt." ^ k; loc }
                     | None, Some s -> stmt ~loc s
                     | None, None -> Ast.Other { kind = "Unsupported:RawStmt"; loc })
                 | _ -> Ast.Other { kind = "Unsupported:RawStmt"; loc = -1 })
               raws)
      | _ ->
          Error
            (Reason.make ~rule Reason.E_INTERNAL
               "unexpected parser output (no statement list)"))
  | _ -> Error (Reason.make ~rule Reason.E_INTERNAL "unexpected parser output")

let parse_unsafe ~(limits : Policy.limits) (sql : string) =
  let len = String.length sql in
  if len > limits.max_bytes then
    limit_error
      (Printf.sprintf "query is %d bytes; the limit is %d bytes" len limits.max_bytes)
  else
    match prescan sql with
    | Some msg -> limit_error msg
    | None -> (
        match Raw.parse_json sql with
        | Error (msg, cursor) ->
            let loc = if cursor > 0 then Some (cursor - 1) else None in
            Error
              (Reason.make ?loc ~rule
                 ~hint:"Fix the SQL syntax; HaltSQL accepts PostgreSQL only."
                 Reason.E_PARSE msg)
        | Ok json -> (
            match Yojson.Safe.from_string json with
            | exception Yojson.Json_error m ->
                Error
                  (Reason.make ~rule Reason.E_INTERNAL
                     ("could not read parser output: " ^ m))
            | tree ->
                let depth, nodes =
                  tree_metrics ~max_depth:limits.max_depth ~max_nodes:limits.max_nodes
                    tree
                in
                if depth > limits.max_depth then
                  limit_error
                    (Printf.sprintf "query parse tree is deeper than the limit of %d"
                       limits.max_depth)
                else if nodes > limits.max_nodes then
                  limit_error
                    (Printf.sprintf "query parse tree has more than the limit of %d nodes"
                       limits.max_nodes)
                else convert_tree tree))

let parse ~limits sql =
  try parse_unsafe ~limits sql with
  | Stack_overflow ->
      Error (Reason.make ~rule Reason.E_LIMIT "query is too deeply nested to analyze")
  | Out_of_memory ->
      Error (Reason.make ~rule Reason.E_LIMIT "query is too large to analyze")
  | e ->
      Error
        (Reason.make ~rule Reason.E_INTERNAL
           ("internal error while parsing: " ^ Printexc.to_string e))

let fingerprint sql =
  try
    if String.length sql > Policy.default_limits.max_bytes * 64 then None
    else
      match prescan sql with
      | Some _ -> None
      | None -> ( match Raw.fingerprint sql with Ok s -> Some s | Error _ -> None)
  with _ -> None

let postgres_version = Raw.pg_version
