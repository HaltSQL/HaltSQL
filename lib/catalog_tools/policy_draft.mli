(** [haltsql policy draft]: a reviewable starter policy from a catalog snapshot and PII
    manifests.

    The draft:
    - lists every table, partitioned table, view, materialized view and foreign table of
      the selected schemas with an explicit column list that leaves out every column
      classified as PII by a manifest or matched by the column-name heuristics; a YAML
      comment above each table says what was left out and why;
    - sets [tenant_column] on every table that has the tenant column (the tenant column is
      never excluded, since tenant predicates must reference it; a comment notes it when
      it was flagged) and marks the other tables as GLOBAL in a comment;
    - skips partitions (query the partitioned parent) and sequences, listing them in a
      comment, and skips tables whose every column is excluded;
    - uses bound tenancy ([tenant: ${ctx.tenant_id}] by default), [require_limit: 1000],
      the [aggregates]/[math]/[string]/[datetime] presets, read-only statements, enforce
      mode, and a [catalog:] reference to the snapshot.

    The output is loaded with {!Haltsql_load.Policy_load} before it is returned; a draft
    that does not load is an error, never written. Names coming from the catalog or the
    manifests are quoted as needed and stripped of control characters in comments, so they
    cannot inject YAML. *)

type config = {
  name : string;  (** metadata.name *)
  tenant_column : string;  (** exact stored column name, e.g. ["tenant_id"] *)
  tenancy_key : string;  (** default ["tenant"] *)
  context_field : string;  (** default ["tenant_id"] *)
  schemas : string list;  (** [[]]: every schema in the snapshot *)
  catalog_ref : string;  (** written as [catalog:]; relative to the policy file *)
  require_limit : int;  (** default 1000 *)
  presets : string list;  (** default [aggregates; math; string; datetime] *)
  name_patterns : string list;
      (** column-name heuristics ({!Pii.Matcher.find_match} on the column name); [[]]
          disables them *)
  include_partitions : bool;  (** default [false] *)
  pii_sources : string list;  (** manifest file names, for the header comment *)
}

val default_name_patterns : string list
(** [email; phone; mobile; ssn; password; passwd; secret; token; api_key; apikey; iban;
     card; dob; birth; address; ip]. *)

val default_config : tenant_column:string -> catalog_ref:string -> config
(** A configuration with the defaults documented on each {!config} field. *)

type exclusion = { column : string; reasons : string list }

type table_report = {
  schema : string;
  table : string;
  kind : Snapshot.relkind;
  included : string list;
  excluded : exclusion list;
  tenant_scoped : bool;
  skipped : string option;  (** why the table is not in the policy *)
}

type result = { yaml : string; tables : table_report list; warnings : string list }

val draft :
  ?base_dir:string -> config -> Snapshot.t -> Pii.t -> (result, string) Stdlib.result
(** [base_dir] is the directory the policy will be written to; it resolves [catalog_ref]
    for the validation load (default: the current directory). *)

val relative_path : from_dir:string -> string -> string
(** Path of a file relative to a directory (both made absolute against the current
    directory first), e.g. [relative_path ~from_dir:"policies" "catalog/c.json"] is
    ["../catalog/c.json"]. *)
