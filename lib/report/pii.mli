(** Which columns must never be suggested because they carry personal or sensitive data.

    The CLI builds a lookup from PII manifests and data-catalog exports with
    [haltsql.catalog_tools] ([Pii], [Pii_import], [Pii.Matcher]); this module only defines
    the lookup and a dependency-free column-name heuristic for callers without those
    libraries (haltsql-server). *)

type lookup = schema:string -> table:string -> column:string -> string option
(** [Some why] (e.g. ["PII, email (dbt)"] or ["column name matches \"email\""]) when the
    column is sensitive. *)

val none : lookup

val union : lookup list -> lookup
(** The first lookup that flags the column wins. *)

val default_terms : string list
(** Same terms as [Pii.Matcher.default_terms] in haltsql.catalog_tools. *)

val name_heuristic : ?terms:string list -> unit -> lookup
(** Flags a column whose name, split into lower-case words (on non-alphanumerics and
    camelCase boundaries), contains a term as a contiguous word sequence. *)
