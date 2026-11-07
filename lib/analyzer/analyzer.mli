(** Policy analysis of one parsed statement. Pure and total: never raises (internal
    exceptions become an [E_INTERNAL] reason). *)

open Haltsql_core

type analysis = {
  reasons : Reason.t list;  (** empty iff the statement is allowed *)
  statement_kind : Policy.stmt_kind option;
  tables : string list;  (** qualified relations touched, sorted, unique *)
  columns : string list;  (** ["schema.table.column"] read, sorted, unique *)
  bind_params : (int * Context.value) list;  (** bound tenancy mode *)
}

val analyze : Policy.t -> Context.t -> Ast.stmt -> analysis
