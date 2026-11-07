(* Compact printer for Haltsql_core.Ast, used only in failure messages. *)
open Haltsql_core.Ast

let p = Printf.sprintf
let list f l = "[" ^ String.concat "; " (List.map f l) ^ "]"
let opt f = function None -> "-" | Some x -> f x
let qname q = qname_to_string q
let field = function Name s -> s | Star -> "*"

let const = function
  | Int s -> "Int " ^ s
  | Float s -> "Float " ^ s
  | String s -> p "String %S" s
  | Bool b -> p "Bool %b" b
  | Bit_string s -> "Bits " ^ s
  | Null -> "Null"

let alias a = p "%s(%s)" a.aliasname (String.concat "," a.colnames)

let rec expr = function
  | Column_ref { fields; _ } -> "Col " ^ String.concat "." (List.map field fields)
  | Const { value; _ } -> const value
  | Param { number; _ } -> p "$%d" number
  | A_expr { name; lexpr; rexpr; _ } ->
      p "(A_expr %s %s %s)" (String.concat "." name) (opt expr lexpr) (opt expr rexpr)
  | Bool_expr { op; args; _ } ->
      p "(%s %s)"
        (match op with And -> "AND" | Or -> "OR" | Not -> "NOT")
        (list expr args)
  | Func_call { fname; args; _ } ->
      p "%s(%s)" (qname fname) (String.concat ", " (List.map expr args))
  | Type_cast { arg; type_name; _ } ->
      p "(%s::%s%s)" (expr arg)
        (String.concat "." type_name.type_names)
        (String.concat "" (List.init type_name.array_bounds (fun _ -> "[]")))
  | Sub_link { subselect; _ } -> p "(Sub_link %s)" (select subselect)
  | Case _ -> "Case"
  | Null_test { arg; is_null; _ } ->
      p "(%s IS %sNULL)" (expr arg) (if is_null then "" else "NOT ")
  | Boolean_test { arg; test; _ } -> p "(%s %s)" (expr arg) test
  | Coalesce { args; _ } -> "Coalesce" ^ list expr args
  | Min_max { args; _ } -> "Min_max" ^ list expr args
  | Row { args; _ } -> "Row" ^ list expr args
  | Array { elements; _ } -> "Array" ^ list expr elements
  | Indirection { arg; subscripts; fields; _ } ->
      p "(Ind %s %s %s)" (expr arg) (list expr subscripts) (list field fields)
  | Collate { arg; collation; _ } ->
      p "(%s COLLATE %s)" (expr arg) (String.concat "." collation)
  | Sql_value { op; _ } -> op
  | Unsupported { node; loc } -> p "Unsupported(%s@%d)" node loc

and from = function
  | Relation { rel; alias = a; inh; _ } ->
      p "Rel %s%s%s"
        (if inh then "" else "ONLY ")
        (qname rel)
        (opt (fun x -> " " ^ alias x) a)
  | Subquery { query; _ } -> p "(Subq %s)" (select query)
  | Function { calls; _ } -> "Func " ^ list expr calls
  | Join { left; right; _ } -> p "(Join %s %s)" (from left) (from right)
  | Unsupported_from { node; loc } -> p "Unsupported_from(%s@%d)" node loc

and select s =
  let body =
    match s.body with
    | Simple ss ->
        p "SELECT %s FROM %s WHERE %s"
          (list (fun t -> expr t.expr) ss.targets)
          (list from ss.from) (opt expr ss.where)
    | Values rows -> "VALUES " ^ list (list expr) rows
    | Set_op { larg; rarg; _ } -> p "(%s SETOP %s)" (select larg) (select rarg)
  in
  body

and stmt = function
  | Select s -> select s
  | Insert i -> "INSERT " ^ qname i.ins_rel
  | Update u -> "UPDATE " ^ qname u.upd_rel
  | Delete d -> "DELETE " ^ qname d.del_rel
  | Explain { stmt = s; analyze; _ } ->
      p "EXPLAIN%s %s" (if analyze then " ANALYZE" else "") (stmt s)
  | Other { kind; _ } -> "Other " ^ kind
