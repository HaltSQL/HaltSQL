(* Tenant isolation proofs and tenant writes; see tenancy.mli for the proof rules. *)

open Haltsql_core

let safe_cast_types =
  [ "text"; "int2"; "int4"; "int8"; "smallint"; "integer"; "int"; "bigint"; "uuid" ]

let rec strip_safe_casts (e : Ast.expr) =
  match e with
  | Ast.Type_cast { arg; type_name; _ } ->
      if List.mem (Rules.type_base type_name) safe_cast_types then strip_safe_casts arg
      else None
  | Ast.Column_ref _ | Ast.Const _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _
  | Ast.Func_call _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _ | Ast.Boolean_test _
  | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _ | Ast.Indirection _
  | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ ->
      Some e

(** Top-level AND chain of a predicate. *)
let rec conjuncts (e : Ast.expr) =
  match e with
  | Ast.Bool_expr { op = Ast.And; args; _ } -> List.concat_map conjuncts args
  | Ast.Bool_expr { op = Ast.Or | Ast.Not; _ }
  | Ast.Column_ref _ | Ast.Const _ | Ast.Param _ | Ast.A_expr _ | Ast.Func_call _
  | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _ | Ast.Boolean_test _
  | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _ | Ast.Indirection _
  | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ ->
      [ e ]

let is_eq_name = function [ "=" ] | [ "pg_catalog"; "=" ] -> true | _ -> false

type value_side =
  | V_param of int * int  (** [(n, loc)] of the [$n] node *)
  | V_lit of [ `Int of string | `Str of string ]
  | V_other

let value_side (e : Ast.expr) =
  match strip_safe_casts e with
  | Some (Ast.Param { number; loc }) -> V_param (number, loc)
  | Some (Ast.Const { value = Ast.Int s; _ }) -> V_lit (`Int s)
  | Some (Ast.Const { value = Ast.String s; _ }) -> V_lit (`Str s)
  | Some
      ( Ast.Const { value = Ast.Float _ | Ast.Bool _ | Ast.Bit_string _ | Ast.Null; _ }
      | Ast.Column_ref _ | Ast.A_expr _ | Ast.Bool_expr _ | Ast.Func_call _
      | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _
      | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _
      | Ast.Indirection _ | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ )
  | None ->
      V_other

(** Elements of an IN list / ARRAY constructor, whatever node the parser uses. *)
let list_elements (e : Ast.expr) =
  match strip_safe_casts e with
  | Some (Ast.Row { args; _ }) -> Some args
  | Some (Ast.Array { elements; _ }) -> Some elements
  | Some
      ( Ast.Column_ref _ | Ast.Const _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _
      | Ast.Func_call _ | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _
      | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _ | Ast.Indirection _
      | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ )
  | None ->
      None

type col_side = C_this | C_cast_on_col | C_other

let rec col_side scope ~item ~col (e : Ast.expr) =
  match e with
  | Ast.Column_ref { fields; _ } ->
      if Scope.resolves_to scope fields ~item ~col then C_this else C_other
  | Ast.Type_cast { arg; _ } | Ast.Collate { arg; _ } -> (
      match col_side scope ~item ~col arg with
      | C_this | C_cast_on_col -> C_cast_on_col
      | C_other -> C_other)
  | Ast.Const _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _ | Ast.Func_call _
  | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _ | Ast.Boolean_test _ | Ast.Coalesce _
  | Ast.Min_max _ | Ast.Row _ | Ast.Array _ | Ast.Indirection _ | Ast.Sql_value _
  | Ast.Unsupported _ ->
      C_other

(** Outcome of examining one conjunct for one (occurrence, column). *)
type outcome =
  | Proof of (int * Context.value * int) list
      (** bound params: [(n, value, loc of the $n node)] *)
  | Mismatch of string  (** literal value that is not the tenant's *)
  | Cast_on_column
  | Needs_any  (** [= $n] / [IN ($n)] with a multi-valued context *)
  | Literal_in_bound
  | Param_in_literal
  | No_match

let allowed_values = function Context.One v -> [ v ] | Context.Many vs -> vs

let lit_matches allowed = function
  | `Str s -> List.mem s allowed
  | `Int s ->
      let n = Util.normalize_int s in
      List.exists
        (fun v -> Util.is_int_literal v && String.equal (Util.normalize_int v) n)
        allowed

let lit_text = function `Str s -> "'" ^ s ^ "'" | `Int s -> s

(** Literal / bound evaluation of a list of value expressions ([IN], [ANY(ARRAY[..])]). *)
let eval_literal_list mode allowed (vs : Ast.expr list) =
  let sides = List.map value_side vs in
  match mode with
  | Policy.Bound ->
      if List.exists (function V_lit _ -> true | V_param _ | V_other -> false) sides
      then Literal_in_bound
      else No_match
  | Policy.Literal -> (
      if
        List.exists (function V_other -> true | V_lit _ | V_param _ -> false) sides
        || sides = []
      then No_match
      else if
        List.exists (function V_param _ -> true | V_lit _ | V_other -> false) sides
      then Param_in_literal
      else
        let lits =
          List.filter_map
            (function V_lit l -> Some l | V_param _ | V_other -> None)
            sides
        in
        match List.filter (fun l -> not (lit_matches allowed l)) lits with
        | [] -> Proof []
        | bad -> Mismatch (String.concat ", " (List.map lit_text bad)))

let examine (env : Env.t) scope ~item ~col (v : Context.value) (c : Ast.expr) =
  let mode = env.policy.tenancy.mode in
  let allowed = allowed_values v in
  let side = col_side scope ~item ~col in
  let eq_value (value : Ast.expr) =
    match (value_side value, mode, v) with
    | V_param (n, pl), Policy.Bound, Context.One s -> Proof [ (n, Context.One s, pl) ]
    | V_param _, Policy.Bound, Context.Many _ -> Needs_any
    | V_param _, Policy.Literal, _ -> Param_in_literal
    | V_lit _, Policy.Bound, _ -> Literal_in_bound
    | V_lit l, Policy.Literal, _ ->
        if lit_matches allowed l then Proof [] else Mismatch (lit_text l)
    | V_other, (Policy.Bound | Policy.Literal), _ -> No_match
  in
  let with_col_side e k =
    match side e with
    | C_this -> k ()
    | C_cast_on_col -> Cast_on_column
    | C_other -> No_match
  in
  match c with
  | Ast.A_expr { kind = Ast.Op; name; lexpr = Some l; rexpr = Some r; _ }
    when is_eq_name name -> (
      match (side l, side r) with
      | C_this, _ -> eq_value r
      | _, C_this -> eq_value l
      | C_cast_on_col, _ | _, C_cast_on_col -> Cast_on_column
      | C_other, C_other -> No_match)
  | Ast.A_expr { kind = Ast.Op_any; name; lexpr = Some l; rexpr = Some r; _ }
    when is_eq_name name ->
      with_col_side l (fun () ->
          match value_side r with
          | V_param (n, pl) -> (
              match mode with
              | Policy.Bound -> Proof [ (n, Context.Many allowed, pl) ]
              | Policy.Literal -> Param_in_literal)
          | V_lit _ -> No_match
          | V_other -> (
              match list_elements r with
              | Some es -> eval_literal_list mode allowed es
              | None -> No_match))
  | Ast.A_expr { kind = Ast.In; name = [ "=" ]; lexpr = Some l; rexpr = Some r; _ } ->
      with_col_side l (fun () ->
          match list_elements r with
          | Some [ single ] -> eq_value single
          | Some es -> eval_literal_list mode allowed es
          | None -> eq_value r)
  | Ast.A_expr _ | Ast.Column_ref _ | Ast.Const _ | Ast.Param _ | Ast.Bool_expr _
  | Ast.Func_call _ | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _
  | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _
  | Ast.Indirection _ | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ ->
      No_match

(** Look up the context value for a tenancy key; reports E_CONTEXT_MISSING once per key.
*)
let context_value (env : Env.t) key loc =
  let field = List.assoc_opt key env.policy.tenancy.keys in
  let v = match field with Some f -> Context.find env.ctx f | None -> None in
  match v with
  | Some (Context.Many []) | None ->
      if not (List.mem key env.missing_keys) then begin
        env.missing_keys <- key :: env.missing_keys;
        let fname = match field with Some f -> f | None -> key in
        Env.emit env ~loc ~rule:"tenancy.context" Reason.E_CONTEXT_MISSING
          (Printf.sprintf "the request context has no value for %S (tenancy key %S)" fname
             key)
          ~hint:
            "This is a caller configuration problem, not a query problem: the host \
             application must supply the tenant context."
      end;
      None
  | Some v -> Some v

let qualifier (it : Scope.item) (tb : Policy.table) =
  match it.name with Some n -> n | None -> tb.name

let suggestion (env : Env.t) (v : Context.value) q col =
  match (env.policy.tenancy.mode, v) with
  | Policy.Bound, Context.One _ -> Printf.sprintf "%s.%s = $1" q col
  | Policy.Bound, Context.Many _ -> Printf.sprintf "%s.%s = ANY($1)" q col
  | Policy.Literal, Context.One _ -> Printf.sprintf "%s.%s = <tenant value>" q col
  | Policy.Literal, Context.Many _ -> Printf.sprintf "%s.%s IN (<tenant values>)" q col

type pending = {
  p_item : Scope.item;
  p_table : Policy.table;
  p_col : string;
  p_key : string;
  p_value : Context.value;
  p_conjuncts : Ast.expr list;  (** top-level conjuncts of the occurrence's locations *)
  p_outcomes : (Ast.expr * outcome) list;
}
(** One tenant column of one base occurrence, with what each candidate conjunct says about
    it. *)

let has_direct_proof (p : pending) =
  List.exists
    (fun (_, o) ->
      match o with
      | Proof _ -> true
      | Mismatch _ | Cast_on_column | Needs_any | Literal_in_bound | Param_in_literal
      | No_match ->
          false)
    p.p_outcomes

(** Is [c] the plain equality [p.col = q.col] (either order, no cast on either side)? *)
let links scope (p : pending) (q : pending) (c : Ast.expr) =
  let is_col (x : pending) (e : Ast.expr) =
    match e with
    | Ast.Column_ref { fields; _ } ->
        Scope.resolves_to scope fields ~item:x.p_item ~col:x.p_col
    | Ast.Const _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _ | Ast.Func_call _
    | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _ | Ast.Boolean_test _
    | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _ | Ast.Indirection _
    | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ ->
        false
  in
  match c with
  | Ast.A_expr { kind = Ast.Op; name; lexpr = Some l; rexpr = Some r; _ }
    when is_eq_name name ->
      (is_col p l && is_col q r) || (is_col p r && is_col q l)
  | Ast.A_expr _ | Ast.Column_ref _ | Ast.Const _ | Ast.Param _ | Ast.Bool_expr _
  | Ast.Func_call _ | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _
  | Ast.Boolean_test _ | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _
  | Ast.Indirection _ | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ ->
      false

(** Occurrences proven through another occurrence of the same level: [p] is proven when
    one of its own conjuncts is [p.col = q.col], [q] is proven, and both columns carry the
    same tenancy key. The conjunct sits in one of [p]'s locations, so every row of [p]
    that survives has [p.col] equal to the [q.col] of a real (not null-extended) row of
    [q], and that value is the tenant's. Starts from direct proofs only, so two unproven
    occurrences cannot vouch for each other. Returns the ids proven this way. *)
let transitive_proofs scope (ps : pending list) =
  let key (p : pending) = (p.p_item.id, p.p_col) in
  let proven =
    ref (List.filter_map (fun p -> if has_direct_proof p then Some (key p) else None) ps)
  in
  let derived = ref [] in
  let changed = ref true in
  while !changed do
    changed := false;
    List.iter
      (fun p ->
        if not (List.mem (key p) !proven) then
          let via =
            List.exists
              (fun q ->
                q.p_item.id <> p.p_item.id && String.equal q.p_key p.p_key
                && List.mem (key q) !proven
                && List.exists (links scope p q) p.p_conjuncts)
              ps
          in
          if via then begin
            proven := key p :: !proven;
            derived := key p :: !derived;
            changed := true
          end)
      ps
  done;
  !derived

(** Check every tenant-scoped base occurrence among [items]. [where] is the level's WHERE;
    [quals] maps item ids to the join quals that are candidate locations for them. *)
let check_level (env : Env.t) (scope : Scope.t) ~(items : Scope.item list)
    ~(where : Ast.expr option) ~(quals : (int * Ast.expr) list) =
  let pendings =
    List.concat_map
      (fun (it : Scope.item) ->
        match it.source with
        | Scope.Derived _ | Scope.Denied -> []
        | Scope.Base { table = tb; _ } ->
            let locations =
              Util.opt_list where
              @ List.filter_map (fun (id, q) -> if id = it.id then Some q else None) quals
            in
            let cs = List.concat_map conjuncts locations in
            List.filter_map
              (fun (col, key) ->
                match context_value env key it.loc with
                | None -> None
                | Some v ->
                    Some
                      {
                        p_item = it;
                        p_table = tb;
                        p_col = col;
                        p_key = key;
                        p_value = v;
                        p_conjuncts = cs;
                        p_outcomes =
                          List.map (fun c -> (c, examine env scope ~item:it ~col v c)) cs;
                      })
              tb.tenant_columns)
      items
  in
  let derived = transitive_proofs scope pendings in
  List.iter
    (fun (p : pending) ->
      let it = p.p_item and tb = p.p_table and col = p.p_col and v = p.p_value in
      let outcomes = p.p_outcomes in
      let q = qualifier it tb in
      let tname = Policy.table_qualified_name tb in
      let proofs =
        List.filter_map
          (fun (_, o) ->
            match o with
            | Proof bs -> Some bs
            | Mismatch _ | Cast_on_column | Needs_any | Literal_in_bound
            | Param_in_literal | No_match ->
                None)
          outcomes
      in
      List.iter
        (fun (c, o) ->
          match o with
          | Mismatch lit ->
              Env.emit env ~loc:(Ast_util.expr_loc c) ~rule:"tenancy.mismatch"
                Reason.E_TENANT_MISMATCH
                (Printf.sprintf
                   "%s.%s is compared to %s, which is not the caller's tenant value \
                    (table %s)"
                   q col lit tname)
                ~hint:
                  (Printf.sprintf
                     "Compare %s.%s only to the tenant value from the request context." q
                     col)
          | Literal_in_bound ->
              Env.emit env ~loc:(Ast_util.expr_loc c) ~rule:"tenancy.mismatch"
                Reason.E_TENANT_MISMATCH
                (Printf.sprintf
                   "%s.%s is compared to a literal, but this policy uses bound mode \
                    (table %s)"
                   q col tname)
                ~hint:
                  (Printf.sprintf
                     "Use a $n placeholder (e.g. %s) instead of a tenant literal; \
                      HaltSQL returns the value to bind."
                     (suggestion env v q col))
          | Proof _ | Cast_on_column | Needs_any | Param_in_literal | No_match -> ())
        outcomes;
      let any_mismatch =
        List.exists
          (fun (_, o) ->
            match o with
            | Mismatch _ | Literal_in_bound -> true
            | Proof _ | Cast_on_column | Needs_any | Param_in_literal | No_match -> false)
          outcomes
      in
      if proofs <> [] then
        List.iter
          (List.iter (fun (n, value, pl) -> Env.add_binding env n value ~ploc:pl it.loc))
          proofs
      else if List.mem (it.id, col) derived then ()
      else if not any_mismatch then begin
        let has f = List.exists (fun (_, o) -> f o) outcomes in
        let detail =
          if has (function Cast_on_column -> true | _ -> false) then
            " (a cast or COLLATE on the tenant column does not count)"
          else if has (function Needs_any -> true | _ -> false) then
            " (the context holds several tenant values: use = ANY($n))"
          else if has (function Param_in_literal -> true | _ -> false) then
            " (this policy uses literal mode: compare to the tenant literal, not a \
             placeholder)"
          else ""
        in
        Env.emit env ~loc:it.loc ~rule:"tenancy.predicate" Reason.E_TENANT_MISSING
          (Printf.sprintf
             "%s (as %s) has no provable tenant predicate on %s.%s in the same SELECT%s"
             tname q q col detail)
          ~hint:
            (Printf.sprintf
               "Add `WHERE %s` as a top-level AND condition inside the same SELECT that \
                reads %s (not in an outer query, not under OR/NOT, not in the ON of the \
                preserved side of an outer join)."
               (suggestion env v q col) tname)
      end)
    pendings

(** Rule M (INSERT): the value written to a tenant column must be the tenant value.
    Returns unit; emits E_TENANT_WRITE / binds params. *)
let check_insert_value (env : Env.t) ~(tb : Policy.table) ~col ~key ~loc
    (e : Ast.expr option) =
  match context_value env key loc with
  | None -> ()
  | Some v -> (
      let tname = Policy.table_qualified_name tb in
      let bad why =
        Env.emit env ~loc ~rule:"tenancy.write" Reason.E_TENANT_WRITE
          (Printf.sprintf "INSERT into %s must set %s to the caller's tenant value%s"
             tname col why)
          ~hint:
            (match env.policy.tenancy.mode with
            | Policy.Bound ->
                Printf.sprintf "Write a $n placeholder for %s in every VALUES row." col
            | Policy.Literal ->
                Printf.sprintf "Write the tenant literal for %s in every VALUES row." col)
      in
      let single =
        match v with
        | Context.One s -> Some s
        | Context.Many [ s ] -> Some s
        | Context.Many _ -> None
      in
      match e with
      | None -> bad " (the row has no value for it)"
      | Some e -> (
          match (value_side e, env.policy.tenancy.mode) with
          | V_param (n, pl), Policy.Bound -> (
              match single with
              | Some s -> Env.add_binding env n (Context.One s) ~ploc:pl loc
              | None ->
                  bad
                    " (the context holds several tenant values; a placeholder is \
                     ambiguous)")
          | V_param _, Policy.Literal ->
              bad " (literal mode: a placeholder cannot be bound)"
          | V_lit _, Policy.Bound -> bad " (bound mode: use a $n placeholder)"
          | V_lit l, Policy.Literal ->
              if not (lit_matches (allowed_values v) l) then
                bad (Printf.sprintf " (%s is not the tenant value)" (lit_text l))
          | V_other, (Policy.Bound | Policy.Literal) -> bad ""))
