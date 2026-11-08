(** Scopes and column-name resolution (PLAN section 6.4, rule D).

    A scope is a stack of levels, innermost first. Each SELECT level (and the target level
    of an UPDATE / DELETE / INSERT ... RETURNING) contributes one level holding its FROM
    items. Correlated subqueries see enclosing levels because the stack is passed down;
    LATERAL items see earlier siblings because the walker pushes the siblings processed so
    far.

    {2 Column knowledge}

    For each FROM item we track what we know about its column set:
    - [Exact l]: the item has exactly the columns [l] (catalog snapshot, or a derived
      table whose output we computed);
    - [At_least l]: the item has the columns [l] and possibly others we do not know about
      (a policy table without catalog: its [Only] list plus its tenant columns; an [All]
      table without catalog: just its tenant columns; a set-returning function).

    {2 Unqualified column resolution}

    PostgreSQL guarantees that an unqualified name that executes successfully matches
    exactly one item at the innermost level that has the name. We mirror that while
    {b never guessing}:
    - at a level, if exactly one item definitely has the column, it wins (if another item
      also had it, PostgreSQL would reject the query as ambiguous);
    - two definite matches: ambiguous;
    - no definite match but exactly one item that might have it: we assign it to that item
      only if no enclosing level might also supply the name (otherwise the reference may
      be a correlation to an outer column and we cannot tell which, so it is ambiguous);
    - no definite or possible match: try the enclosing level.

    Ambiguity is reported by the walker as [E_COLUMN_UNRESOLVED]: a reference we cannot
    attribute with certainty is denied, never attributed to the more permissive item. *)

open Haltsql_core

(** What is known about an item's column set. *)
type knowledge =
  | Exact of string list  (** exactly these columns, in order *)
  | At_least of string list  (** these columns and possibly others *)

(** Where an item's rows come from. *)
type source =
  | Base of { table : Policy.table; catalog : string list option }
      (** an occurrence of a policy table; [catalog] = its full column list when a trusted
          catalog snapshot knows it *)
  | Derived of string
      (** subquery / CTE / VALUES / function; the string describes it in messages. Its
          contents were checked when it was walked. *)
  | Denied  (** a relation that was already reported as [E_TABLE_DENIED] *)

type item = {
  id : int;  (** unique per occurrence within one analysis ({!Env.fresh_id}) *)
  name : string option;  (** the name usable as a qualifier (alias or relation name) *)
  schema : string option;  (** schema usable in [s.t.c]: unaliased base relations only *)
  cols : knowledge;
  source : source;
  loc : int;
}
(** One FROM item occurrence. *)

type col_ref = { item : item; col : string }
(** A column of a specific occurrence. *)

type level = {
  items : item list;
  merged : (string * col_ref list) list;
      (** [JOIN ... USING (c)] merged columns: an unqualified [c] reads both sides *)
}
(** One scope level. *)

type t = level list
(** Innermost level first. *)

val empty : t

val push : ?merged:(string * col_ref list) list -> item list -> t -> t
(** [push ?merged items scope] adds an innermost level. *)

(** {1 Column knowledge} *)

(** Whether an item has a column. *)
type presence =
  | Yes
  | Maybe  (** unknown: the item's knowledge is [At_least] and does not list it *)
  | No

val presence : item -> string -> presence
val knowledge_names : knowledge -> string list

val concat_knowledge : knowledge list -> knowledge
(** Concatenation (e.g. [*] over several items): [Exact] only if every part is. *)

val rename : string list -> knowledge -> knowledge
(** Positional renaming by an alias column list ([AS x(a, b)]): the first names are
    replaced, the rest kept. *)

val item_display : item -> string
(** Human-readable description of an item, for messages. *)

val harmless : item -> bool
(** Reading any column of a harmless item cannot leak anything that is not checked
    elsewhere: derived tables are checked inside, [All] tables allow every column, and
    denied relations were already reported. *)

(** {1 Resolution} *)

(** Result of resolving an unqualified column name. *)
type unqualified =
  | U_col of col_ref  (** definite *)
  | U_maybe of col_ref  (** the only possible candidate anywhere visible *)
  | U_merged of col_ref list  (** USING-merged column *)
  | U_ambiguous of item list  (** candidates *)
  | U_none

val resolve_unqualified : t -> string -> unqualified
(** Resolves an unqualified column name with the rules described above. *)

val find_named : t -> string -> item list
(** Items whose qualifier is the given name, at the innermost level that has any. *)

val find_schema_named : t -> string -> string -> item list
(** [find_schema_named scope s t]: like {!find_named} for a schema-qualified [s.t]. *)

val innermost_items : t -> item list

val classify_fields : Ast.field list -> (string list * bool) option
(** Shape of a column reference: the leading names and whether it ends in [*]. [None] when
    a [*] appears before the last position. *)

val resolves_to : t -> Ast.field list -> item:item -> col:string -> bool
(** Does a column reference resolve, with certainty, to column [col] of exactly this
    occurrence [item]? Used by the tenancy prover, so it accepts only definite or
    sole-candidate resolutions (and qualified references to a single matching item);
    anything else is [false], which can only make a proof fail. *)
