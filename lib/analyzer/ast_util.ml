(** Pure AST helpers: locations and Postgres-compatible output column names. *)

open Haltsql_core

let expr_loc (e : Ast.expr) =
  match e with
  | Ast.Column_ref { loc; _ }
  | Ast.Const { loc; _ }
  | Ast.Param { loc; _ }
  | Ast.A_expr { loc; _ }
  | Ast.Bool_expr { loc; _ }
  | Ast.Func_call { loc; _ }
  | Ast.Type_cast { loc; _ }
  | Ast.Sub_link { loc; _ }
  | Ast.Case { loc; _ }
  | Ast.Null_test { loc; _ }
  | Ast.Boolean_test { loc; _ }
  | Ast.Coalesce { loc; _ }
  | Ast.Min_max { loc; _ }
  | Ast.Row { loc; _ }
  | Ast.Array { loc; _ }
  | Ast.Indirection { loc; _ }
  | Ast.Collate { loc; _ }
  | Ast.Sql_value { loc; _ }
  | Ast.Unsupported { loc; _ } ->
      loc

let from_loc (f : Ast.from_item) =
  match f with
  | Ast.Relation { loc; _ }
  | Ast.Subquery { loc; _ }
  | Ast.Function { loc; _ }
  | Ast.Join { loc; _ }
  | Ast.Unsupported_from { loc; _ } ->
      loc

(** Output name the way Postgres's FigureColname derives it, returning a strength like
    Postgres (2 = a real name, 1 = a type-name fallback, 0 = nothing). We only produce
    names Postgres would produce; anything we are not sure about becomes ["?column?"],
    which can only cause a conservative resolution failure, never a mis-resolution. *)
let rec figure_name (e : Ast.expr) : string option * int =
  match e with
  | Ast.Column_ref { fields; _ } -> (
      match Util.last fields with
      | Some (Ast.Name n) -> (Some n, 2)
      | Some Ast.Star | None -> (None, 0))
  | Ast.Func_call { fname; _ } -> (Some fname.name, 2)
  | Ast.Type_cast { arg; type_name; _ } -> (
      match figure_name arg with
      | (Some _, s) as r when s > 1 -> r
      | (Some _ | None), _ -> (
          match Util.last type_name.type_names with
          | Some n -> (Some n, 1)
          | None -> (None, 0)))
  | Ast.Collate { arg; _ } -> figure_name arg
  | Ast.Indirection { fields; arg; _ } -> (
      match Util.last fields with
      | Some (Ast.Name n) -> (Some n, 2)
      | Some Ast.Star -> (None, 0)
      | None -> figure_name arg)
  | Ast.Sub_link { kind; subselect; _ } -> (
      match kind with
      | Ast.Exists -> (Some "exists", 2)
      | Ast.Array_sublink -> (Some "array", 2)
      | Ast.Expr -> (
          match subselect.body with
          | Ast.Simple { targets = t :: _; _ } -> (
              match t.alias with
              | Some a -> (Some a, 2)
              | None -> (
                  match figure_name t.expr with
                  | Some n, s -> (Some n, s)
                  | None, _ -> (None, 0)))
          | Ast.Simple { targets = []; _ } | Ast.Values _ | Ast.Set_op _ -> (None, 0))
      | Ast.Any | Ast.All | Ast.Other_sublink _ -> (None, 0))
  | Ast.Case _ -> (Some "case", 2)
  | Ast.Coalesce _ -> (Some "coalesce", 2)
  | Ast.Min_max { greatest; _ } -> (Some (if greatest then "greatest" else "least"), 2)
  | Ast.Row _ -> (Some "row", 2)
  | Ast.Array _ -> (Some "array", 2)
  | Ast.A_expr { kind = Ast.Nullif; _ } -> (Some "nullif", 2)
  | Ast.Const _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _ | Ast.Null_test _
  | Ast.Boolean_test _ | Ast.Sql_value _ | Ast.Unsupported _ ->
      (None, 0)

let target_name (t : Ast.target) =
  match t.alias with
  | Some a -> a
  | None -> ( match figure_name t.expr with Some n, _ -> n | None, _ -> "?column?")

let is_star_target (t : Ast.target) =
  match t.expr with
  | Ast.Column_ref { fields; _ } -> (
      match Util.last fields with
      | Some Ast.Star -> true
      | Some (Ast.Name _) | None -> false)
  | Ast.Const _ | Ast.Param _ | Ast.A_expr _ | Ast.Bool_expr _ | Ast.Func_call _
  | Ast.Type_cast _ | Ast.Sub_link _ | Ast.Case _ | Ast.Null_test _ | Ast.Boolean_test _
  | Ast.Coalesce _ | Ast.Min_max _ | Ast.Row _ | Ast.Array _ | Ast.Indirection _
  | Ast.Collate _ | Ast.Sql_value _ | Ast.Unsupported _ ->
      false

(** Purely syntactic output columns of a select (used to pre-bind recursive CTEs before
    their bodies are analyzed). *)
let rec syntactic_columns (s : Ast.select) : Scope.knowledge =
  match s.body with
  | Ast.Simple ss ->
      if List.exists is_star_target ss.targets then
        Scope.At_least
          (List.filter_map
             (fun t -> if is_star_target t then None else Some (target_name t))
             ss.targets)
      else Scope.Exact (List.map target_name ss.targets)
  | Ast.Values rows -> (
      match rows with
      | r :: _ -> Scope.Exact (List.mapi (fun i _ -> Printf.sprintf "column%d" (i + 1)) r)
      | [] -> Scope.Exact [])
  | Ast.Set_op { larg; _ } -> syntactic_columns larg

let stmt_kind_of (s : Ast.stmt) : Policy.stmt_kind option =
  match s with
  | Ast.Select _ -> Some Policy.Select
  | Ast.Insert _ -> Some Policy.Insert
  | Ast.Update _ -> Some Policy.Update
  | Ast.Delete _ -> Some Policy.Delete
  | Ast.Explain _ | Ast.Other _ -> None
