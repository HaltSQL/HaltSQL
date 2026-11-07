(** Generate PostgreSQL role, grant and row-level-security DDL that mirrors a HaltSQL
    policy, as database-level defense in depth.

    The output is idempotent (safe to re-run), deterministic (same policy and options give
    byte-identical SQL), runs in one transaction and targets PostgreSQL 13-17.

    Tenant predicates compare each tenant column with a transaction-local custom setting
    [<prefix>.<context_field>] that the application sets from the same context values it
    passed to [Haltsql.verify]:
    {[
      col = NULLIF(pg_catalog.current_setting('haltsql.tenant_id', true), '')
    ]}
    A missing setting makes [current_setting(..., true)] return NULL (or [''] once the
    placeholder was used earlier in the session, which [NULLIF] maps to NULL), so the
    comparison is NULL and no row is visible or writable. Context fields that carry a set
    of tenants (see {!options.set_fields}) use
    [col = ANY (array_remove(string_to_array(<setting>, ','), ''))]. *)

open Haltsql_core

type options = {
  role : string;  (** role the policies and grants are for; default ["haltsql_agent"] *)
  setting_prefix : string;  (** custom setting namespace; default ["haltsql"] *)
  owner_role : string option;
      (** when set, the table DDL runs under [SET LOCAL ROLE owner] (the role that owns
          the tables; only owners may enable RLS and create policies) *)
  drop_existing : bool;
      (** drop EVERY existing policy on the managed tables, not only the [haltsql_*] ones
      *)
  force_rls : bool;  (** also [FORCE ROW LEVEL SECURITY] (applies RLS to the owner) *)
  set_fields : string list;
      (** context fields whose value is a set (comma-separated in the setting) *)
  catalog : Catalog.t option;
      (** column types used to cast the setting to the tenant column's type; consulted
          before the policy's own [catalog:] snapshot *)
}

val default_options : options

type cmd = Select | Insert | Update | Delete

val cmd_to_string : cmd -> string
(** ["SELECT"], ["INSERT"], ... *)

val policy_name : cmd -> string
(** ["haltsql_tenant_select"], ... *)

type tenant_term = {
  column : string;
  setting : string;  (** full setting name, e.g. ["haltsql.tenant_id"] *)
  context_field : string;
  is_set : bool;
  cast : string option;  (** type the setting is cast to, [None] = compared as text *)
}

type table_plan = {
  schema : string;
  name : string;
  select : Policy.columns;
  insert : Policy.columns option;
  update : Policy.columns option;
  delete : bool;
  tenant : tenant_term list;  (** empty = global table: grants only, no RLS *)
  commands : cmd list;  (** commands that get a tenant policy (tenant tables only) *)
}

type plan = {
  policy_name_meta : string;  (** [metadata.name] *)
  policy_version : string;
  options : options;
  schemas : string list;  (** sorted, distinct *)
  tables : table_plan list;  (** sorted by (schema, name) *)
  settings : (string * string * bool) list;
      (** sorted distinct [(setting, context_field, is_set)] the application must set *)
  warnings : string list;
}

val plan : options -> Policy.t -> (plan, string) result
(** Validates the options (role and setting names, [set_fields] referencing tenancy
    context fields, cast types) and computes what to emit. *)

val predicate : tenant_term list -> string
(** The USING / WITH CHECK expression: one comparison per term, AND-ed. *)

val render : plan -> string
(** The DDL script. *)

val generate : options -> Policy.t -> (string * string list, string) result
(** [plan] then [render]: [(sql, warnings)]. *)

val plan_to_json : plan -> Yojson.Safe.t
