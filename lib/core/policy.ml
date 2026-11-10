(** Compiled policy: the validated, normalized, immutable form of a policy document.
    Produced by [Haltsql_load.Policy_load]; consumed by the analyzer.

    Invariants established by the loader (the analyzer may rely on them):
    - every [table.schema] is set (unqualified names are qualified with the first
      [search_path] entry);
    - all identifiers are stored as Postgres would store them (the loader lower-cases
      names that were written unquoted in the policy; names that need case preservation
      are written with double quotes in the policy);
    - every tenancy key referenced by a table exists in [tenancy.keys];
    - [functions] and [operators] are fully expanded (presets resolved), lower-case,
      de-duplicated;
    - [version] is ["sha256:<hex>"] of the normalized policy JSON, identical for the same
      policy written in YAML or JSON.

    The analyzer may rely on these invariants without re-checking them. A [Policy.t] built
    by hand (e.g. in tests) must respect them too. *)

(** Statement kinds a policy can allow. *)
type stmt_kind = Select | Insert | Update | Delete

(** Lower-case name: ["select"], ["insert"], ["update"], ["delete"]. *)

let stmt_kind_to_string = function
  | Select -> "select"
  | Insert -> "insert"
  | Update -> "update"
  | Delete -> "delete"

(** Inverse of {!stmt_kind_to_string}. *)
let stmt_kind_of_string = function
  | "select" -> Some Select
  | "insert" -> Some Insert
  | "update" -> Some Update
  | "delete" -> Some Delete
  | _ -> None

(** A column permission: every column, or only the listed ones. *)
type columns = All | Only of string list

type writes = {
  insert : bool;
  update : columns option;  (** [None] = UPDATE not allowed *)
  delete : bool;
}
(** Write permissions of one table. *)

(** No writes at all. *)
let no_writes = { insert = false; update = None; delete = false }

type table = {
  schema : string;
  name : string;
  columns : columns;  (** readable columns *)
  tenant_columns : (string * string) list;
      (** [(column, tenancy_key)] pairs; empty = global (not tenant-scoped) *)
  writes : writes;
}
(** One allowlisted table. *)

(** How tenant predicates must name the tenant value. *)
type tenancy_mode =
  | Bound
      (** tenant predicates must compare to a [$n] placeholder; HaltSQL returns the value
          to bind. Recommended: the model never sees the tenant id. *)
  | Literal  (** tenant predicates compare to a literal equal to the context value *)

type tenancy = {
  mode : tenancy_mode;
  keys : (string * string) list;
      (** [(key, context_field)], e.g. [("tenant", "tenant_id")] from
          [tenant: ${ctx.tenant_id}] *)
}
(** Tenancy settings. *)

type limits = {
  max_bytes : int;  (** maximum SQL length in bytes, checked before parsing *)
  max_depth : int;  (** maximum parse-tree depth *)
  max_nodes : int;  (** maximum parse-tree node count *)
  max_joins : int;  (** maximum number of joins (including comma joins) *)
}
(** Resource limits applied to each statement. *)

(** 16 KiB, depth 64, 20 000 nodes, 8 joins. *)
let default_limits =
  { max_bytes = 16_384; max_depth = 64; max_nodes = 20_000; max_joins = 8 }

(** [Enforce] denies violations; [Shadow] allows everything but reports would-be denials
    (for rolling out a policy). *)
type mode = Enforce | Shadow

type t = {
  api_version : string;  (** ["haltsql.dev/v1"] *)
  name : string;
  owner : string option;
  description : string option;
  dialect : string;  (** ["postgres"] or ["postgres-17"] *)
  search_path : string list;
  limits : limits;
  statements : stmt_kind list;
  require_limit : int option;  (** [Some max]: every SELECT needs [LIMIT <= max] *)
  tenancy : tenancy;
  tables : table list;
  functions : string list;
      (** allowed function names (lower-case, unqualified or ["schema.fn"]) *)
  operators : string list;  (** allowed operator symbols *)
  casts : string list;
      (** allowed cast target types (lower-case; unqualified built-in name or
          ["schema.type"]). A cast to any other type is denied. *)
  deny_casts : string list;
      (** cast target types denied even when [casts] lists them (lower-case, unqualified)
      *)
  allow_explain : bool;  (** plain EXPLAIN (never ANALYZE) of an allowed statement *)
  mode : mode;
  catalog : Catalog.t;
      (** from the [catalog:] snapshot; {!Catalog.empty} when none is given. Entries are
          COMPLETE column lists of the real tables. *)
  version : string;
}
(** A compiled policy. *)

(** [find_table t ~schema ~name] is the allowlisted table [schema.name], if any (exact
    match on stored names). *)
let find_table t ~schema ~name =
  List.find_opt
    (fun (tb : table) -> String.equal tb.schema schema && String.equal tb.name name)
    t.tables

(** [schema.name] (no quoting), as used in verdicts and messages. *)
let table_qualified_name (tb : table) = tb.schema ^ "." ^ tb.name
