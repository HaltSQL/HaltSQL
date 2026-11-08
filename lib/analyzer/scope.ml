(* Scopes and column-name resolution; see scope.mli for the resolution rules. *)

open Haltsql_core

type knowledge = Exact of string list | At_least of string list

type source =
  | Base of { table : Policy.table; catalog : string list option }
      (** an occurrence of a policy table; [catalog] = full column list if the catalog
          snapshot knows it *)
  | Derived of string  (** subquery / CTE / VALUES / function; description *)
  | Denied  (** a relation that was already reported as E_TABLE_DENIED *)

type item = {
  id : int;  (** unique per occurrence within one analysis *)
  name : string option;  (** the name usable as a qualifier (alias or relation name) *)
  schema : string option;  (** schema usable in [s.t.c]: unaliased base relations only *)
  cols : knowledge;
  source : source;
  loc : int;
}

type col_ref = { item : item; col : string }

type level = {
  items : item list;
  merged : (string * col_ref list) list;
      (** [JOIN ... USING (c)] merged columns: an unqualified [c] reads both sides *)
}

type t = level list

let empty : t = []
let push ?(merged = []) items (scope : t) : t = { items; merged } :: scope

type presence = Yes | Maybe | No

let presence item c =
  match item.cols with
  | Exact l -> if List.mem c l then Yes else No
  | At_least l -> if List.mem c l then Yes else Maybe

let knowledge_names = function Exact l | At_least l -> l

(** Concatenate knowledges (e.g. [*] over several items). *)
let concat_knowledge ks =
  let names = List.concat_map knowledge_names ks in
  if List.for_all (function Exact _ -> true | At_least _ -> false) ks then Exact names
  else At_least names

(** Positional renaming by an alias column list: [AS x(a, b)]. *)
let rename colnames k =
  match colnames with
  | [] -> k
  | _ -> (
      let n = List.length colnames in
      match k with
      | Exact l -> Exact (colnames @ Util.drop n l)
      | At_least l -> At_least (colnames @ Util.drop n l))

let item_display it =
  match (it.source, it.name) with
  | Base { table; _ }, Some n when not (String.equal n table.name) ->
      Policy.table_qualified_name table ^ " AS " ^ n
  | Base { table; _ }, (Some _ | None) -> Policy.table_qualified_name table
  | Derived d, Some n -> d ^ " " ^ n
  | Derived d, None -> d
  | Denied, Some n -> n
  | Denied, None -> "denied relation"

(** Harmless items: reading any of their columns cannot leak anything that is not checked
    elsewhere (derived tables are checked inside; [All] tables allow every column; denied
    relations were already reported). *)
let harmless it =
  match it.source with
  | Derived _ | Denied -> true
  | Base { table; _ } -> (
      match table.columns with Policy.All -> true | Policy.Only _ -> false)

type unqualified =
  | U_col of col_ref  (** definite *)
  | U_maybe of col_ref  (** the only possible candidate anywhere visible *)
  | U_merged of col_ref list  (** USING-merged column *)
  | U_ambiguous of item list  (** candidates *)
  | U_none

let level_may_have lvl c =
  List.mem_assoc c lvl.merged || List.exists (fun it -> presence it c <> No) lvl.items

let level_candidates lvl c = List.filter (fun it -> presence it c <> No) lvl.items

let rec resolve_unqualified (scope : t) c =
  match scope with
  | [] -> U_none
  | lvl :: rest -> (
      match List.assoc_opt c lvl.merged with
      | Some refs -> U_merged refs
      | None -> (
          let yes = List.filter (fun it -> presence it c = Yes) lvl.items in
          let maybe = List.filter (fun it -> presence it c = Maybe) lvl.items in
          match (yes, maybe) with
          | [ it ], _ -> U_col { item = it; col = c }
          | _ :: _ :: _, _ -> U_ambiguous yes
          | [], [] -> resolve_unqualified rest c
          | [], [ it ] ->
              if List.exists (fun l -> level_may_have l c) rest then
                U_ambiguous (it :: List.concat_map (fun l -> level_candidates l c) rest)
              else U_maybe { item = it; col = c }
          | [], its -> U_ambiguous its))

(** Items with qualifier name [t] at the innermost level that has any. *)
let rec find_named (scope : t) t =
  match scope with
  | [] -> []
  | lvl :: rest -> (
      match List.filter (fun it -> it.name = Some t) lvl.items with
      | [] -> find_named rest t
      | its -> its)

let rec find_schema_named (scope : t) s t =
  match scope with
  | [] -> []
  | lvl :: rest -> (
      match List.filter (fun it -> it.name = Some t && it.schema = Some s) lvl.items with
      | [] -> find_schema_named rest s t
      | its -> its)

let innermost_items (scope : t) = match scope with [] -> [] | lvl :: _ -> lvl.items

(** Shape of a column reference: the leading names and whether it ends in [*]. [None] when
    a [*] appears before the last position. Exhaustive over [Ast.field] without wildcards.
*)
let classify_fields (fields : Ast.field list) : (string list * bool) option =
  let rec go acc = function
    | [] -> Some (List.rev acc, false)
    | [ Ast.Star ] -> Some (List.rev acc, true)
    | Ast.Star :: _ :: _ -> None
    | Ast.Name n :: rest -> go (n :: acc) rest
  in
  go [] fields

(** Does a column reference expression resolve (silently) to [item.col]? Used by the
    tenancy prover; it accepts only definite or sole-candidate resolutions to exactly that
    occurrence. *)
let resolves_to (scope : t) (fields : Ast.field list) ~(item : item) ~col =
  let same r = r.item.id = item.id && String.equal r.col col in
  let qualified its c =
    match its with
    | [ it ] -> it.id = item.id && String.equal c col && presence it c <> No
    | [] | _ :: _ :: _ -> false
  in
  match classify_fields fields with
  | Some ([ c ], false) -> (
      match resolve_unqualified scope c with
      | U_col r | U_maybe r -> same r
      | U_merged _ | U_ambiguous _ | U_none -> false)
  | Some ([ t; c ], false) -> qualified (find_named scope t) c
  | Some ([ s; t; c ], false) -> qualified (find_schema_named scope s t) c
  | Some (_, _) | None -> false
