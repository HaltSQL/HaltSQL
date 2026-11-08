(* Context-free rules; see rules.mli. *)

open Haltsql_core

let kind_allowed (env : Env.t) k = List.mem k env.policy.statements

let allowed_kinds_text (env : Env.t) =
  match env.policy.statements with
  | [] -> "none"
  | ks -> String.concat ", " (List.map Policy.stmt_kind_to_string ks)

(** Rule A: a SELECT / INSERT / UPDATE / DELETE must be listed in [policy.statements]. *)
let check_stmt_kind (env : Env.t) k loc =
  if not (kind_allowed env k) then
    Env.emit env ~loc ~rule:"statement.kind" Reason.E_STATEMENT_KIND
      (Printf.sprintf "%s statements are not allowed by this policy"
         (String.uppercase_ascii (Policy.stmt_kind_to_string k)))
      ~hint:
        (Printf.sprintf "Only these statement kinds are allowed: %s."
           (allowed_kinds_text env))

(** Rule F: functions. Unqualified or [pg_catalog.]-qualified names must be in
    [policy.functions] by bare name (a [pg_catalog.f] entry is accepted too); any other
    schema [s.f] must be listed as ["s.f"]. *)
let check_function (env : Env.t) (fname : Ast.qname) loc =
  let fs = env.policy.functions in
  let ok, shown =
    match fname.schema with
    | None -> (List.mem fname.name fs, fname.name)
    | Some "pg_catalog" ->
        (List.mem fname.name fs || List.mem ("pg_catalog." ^ fname.name) fs, fname.name)
    | Some s ->
        let q = s ^ "." ^ fname.name in
        (List.mem q fs, q)
  in
  if not ok then
    Env.emit env ~loc ~rule:"functions.allowlist" Reason.E_FUNCTION_DENIED
      (Printf.sprintf "function %s is not in the policy's function allowlist" shown)
      ~hint:
        (Printf.sprintf
           "Rewrite the query without calling %s(); only allowlisted functions may be \
            used."
           shown)

(** Rule F: SQL value functions. Date/time values are allowed; identity and session values
    (CURRENT_USER, SESSION_USER, USER, CURRENT_ROLE, CURRENT_CATALOG, CURRENT_SCHEMA, ...)
    are denied. *)
let check_sql_value (env : Env.t) op loc =
  let allowed =
    List.exists
      (fun sub -> Util.contains_ci ~sub op)
      [
        "CURRENT_DATE"; "CURRENT_TIMESTAMP"; "CURRENT_TIME"; "LOCALTIMESTAMP"; "LOCALTIME";
      ]
  in
  if not allowed then
    Env.emit env ~loc ~rule:"functions.sql_value" Reason.E_FUNCTION_DENIED
      (Printf.sprintf "SQL value function %s is not allowed" op)
      ~hint:
        "Do not reference session or identity values (CURRENT_USER, SESSION_USER, \
         CURRENT_SCHEMA, ...); only \
         CURRENT_DATE/CURRENT_TIME/CURRENT_TIMESTAMP/LOCALTIME[STAMP] are allowed."

let emit_operator_denied (env : Env.t) shown loc =
  Env.emit env ~loc ~rule:"operators.allowlist" Reason.E_OPERATOR_DENIED
    (Printf.sprintf "operator %s is not in the policy's operator allowlist" shown)
    ~hint:(Printf.sprintf "Rewrite the expression without the %s operator." shown)

(** Check one operator name ([["="]] or [["pg_catalog"; "="]]). A schema other than
    pg_catalog is always denied. *)
let check_operator_name (env : Env.t) (name : string list) loc =
  let shown = String.concat "." name in
  match List.rev name with
  | [] -> emit_operator_denied env "<empty>" loc
  | [ sym ] ->
      if not (List.mem sym env.policy.operators) then emit_operator_denied env shown loc
  | [ sym; "pg_catalog" ] ->
      if not (List.mem sym env.policy.operators) then emit_operator_denied env shown loc
  | _ :: _ :: _ -> emit_operator_denied env shown loc

(** Rule G: operators. Op / Op_any / Op_all / In and the pattern operators (LIKE = [~~],
    ILIKE = [~~*], SIMILAR TO = [~], and their negations) are checked against the
    allowlist; the remaining kinds are built-in syntax. *)
let check_aexpr (env : Env.t) (kind : Ast.aexpr_kind) name loc =
  match kind with
  | Ast.Op | Ast.Op_any | Ast.Op_all | Ast.In | Ast.Like | Ast.Ilike | Ast.Similar ->
      check_operator_name env name loc
  | Ast.Distinct | Ast.Not_distinct | Ast.Nullif | Ast.Between | Ast.Not_between
  | Ast.Between_sym | Ast.Not_between_sym ->
      ()

(** Lower-cased last element of a type name ([pg_catalog.] stripped). *)
let type_base (tn : Ast.type_name) =
  match Util.last tn.type_names with Some n -> String.lowercase_ascii n | None -> ""

(** Rule H: casts to types in [policy.deny_casts]. *)
let check_cast (env : Env.t) (tn : Ast.type_name) loc =
  let base = type_base tn in
  if List.mem base env.policy.deny_casts then
    Env.emit env ~loc ~rule:"casts.deny" Reason.E_CAST_DENIED
      (Printf.sprintf "cast to %s is denied by policy" base)
      ~hint:
        (Printf.sprintf
           "Remove the ::%s cast; object-identifier and other denied types may not be \
            used."
           base)

(** Rule C: LIMIT on the outermost SELECT. *)
let check_limit (env : Env.t) (s : Ast.select) =
  match env.policy.require_limit with
  | None -> ()
  | Some max -> (
      let required () =
        Env.emit env ~loc:s.sel_loc ~rule:"limit.required" Reason.E_LIMIT_REQUIRED
          (Printf.sprintf "the outermost SELECT must have a constant LIMIT <= %d" max)
          ~hint:
            (Printf.sprintf "Add `LIMIT %d` (or smaller) to the outermost SELECT." max)
      in
      let too_high what loc =
        Env.emit env ~loc ~rule:"limit.max" Reason.E_LIMIT_TOO_HIGH
          (Printf.sprintf
             "LIMIT %s is not allowed; it must be an integer constant between 0 and %d"
             what max)
          ~hint:(Printf.sprintf "Use a literal `LIMIT %d` or smaller." max)
      in
      let rec const_int (e : Ast.expr) =
        match e with
        | Ast.Const { value = Ast.Int n; _ } -> Some n
        | Ast.Type_cast { arg; _ } -> const_int arg
        | Ast.Const
            {
              value =
                Ast.Float _ | Ast.String _ | Ast.Bool _ | Ast.Bit_string _ | Ast.Null;
              _;
            }
        | Ast.Column_ref _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _
        | Ast.Func_call _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _
        | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _
        | Ast.Indirection _ | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ ->
            None
      in
      let rec is_null (e : Ast.expr) =
        match e with
        | Ast.Const { value = Ast.Null; _ } -> true
        | Ast.Type_cast { arg; _ } -> is_null arg
        | Ast.Const
            {
              value =
                Ast.Int _ | Ast.Float _ | Ast.String _ | Ast.Bool _ | Ast.Bit_string _;
              _;
            }
        | Ast.Column_ref _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _
        | Ast.Func_call _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _
        | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _
        | Ast.Indirection _ | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ ->
            false
      in
      if s.limit_all then required ()
      else
        match s.limit_count with
        | None -> required ()
        | Some e when is_null e -> required ()
        | Some e -> (
            match const_int e with
            | None -> too_high "with a non-constant value" s.sel_loc
            | Some n -> (
                let n' = Util.normalize_int n in
                match int_of_string_opt n' with
                | Some v when v >= 0 && v <= max -> ()
                | Some _ | None -> too_high n' s.sel_loc)))
