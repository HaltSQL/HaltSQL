(** [haltsql schema check]: compare a policy with the database it is meant for.

    HaltSQL verifies SQL against what the {e policy} says the schema is. This module finds
    the places where the database (an authoritative snapshot, see {!Snapshot}) disagrees
    or where the policy relies on something the verifier cannot see. Pure: no IO. *)

open Haltsql_core

type severity = Error | Warning

type finding = {
  severity : severity;
  code : string;  (** stable, e.g. ["E_DRIFT_CATALOG_STALE"] *)
  table : string option;  (** ["schema.table"] the finding is about *)
  message : string;
}

val check : Policy.t -> Snapshot.t -> finding list
(** Findings, errors first, then by table and code.

    Errors (the policy does not describe this database; verdicts cannot be trusted):
    - [E_DRIFT_TABLE_MISSING]: a policy table does not exist;
    - [E_DRIFT_COLUMN_MISSING]: an allowed, tenant or writable column does not exist;
    - [E_DRIFT_CATALOG_STALE]: the policy's own [catalog:] entry for a table lists other
      columns than the database has. The analyzer expands [*] against that entry, so a
      column added since the snapshot would be read without being checked;
    - [E_DRIFT_SHADOWED]: an earlier [search_path] schema has a relation with the same
      name as a policy table, so the unqualified name reaches the other relation.

    Warnings (the verifier cannot see inside):
    - [W_DRIFT_VIEW]: a policy table is a view, materialized view or foreign table: what
      it reads, and whose rows, is decided by its definition, not by the policy;
    - [W_DRIFT_NO_CATALOG]: the policy has no [catalog:] entry for a table;
    - [W_DRIFT_SCHEMA_NOT_PULLED]: a policy schema is not covered by the snapshot. *)

val severity_to_string : severity -> string
val to_json : finding list -> Yojson.Safe.t
