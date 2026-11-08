(** HaltSQL — a policy firewall for LLM-generated PostgreSQL.

    {[
    let policy = Haltsql.Policy_load.of_file "policy.yaml" |> Result.get_ok in
    let ctx = Haltsql.Context.make [ ("tenant_id", One "acme") ] in
    let v =
      Haltsql.verify policy ctx "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10"
    in
    if v.allowed then (* run exactly that string, binding v.bind_params *) ()
    ]}

    [verify] never touches the database and never rewrites SQL.

    {2 Verification pipeline}

    + {!Pg_parse.parse}: size limits, then the real PostgreSQL parser (libpg_query), then
      conversion to the typed {!Ast} (unknown constructs become [Unsupported*] nodes);
    + exactly one statement is required ([E_EMPTY] / [E_MULTI_STATEMENT] otherwise);
    + {!Analyzer.analyze}: deny-by-default policy rules, including tenancy proofs;
    + the {!Verdict.t} is assembled; in shadow mode denials move to [shadow_reasons].

    Policies are loaded with {!Policy_load}; loading fails closed (any error rejects the
    whole document). *)

(** {1 Core types} *)

module Ast = Haltsql_core.Ast
module Reason = Haltsql_core.Reason
module Context = Haltsql_core.Context
module Catalog = Haltsql_core.Catalog
module Policy = Haltsql_core.Policy
module Verdict = Haltsql_core.Verdict
module Load_error = Haltsql_core.Load_error

(** {1 Documents} *)

module Docload = Haltsql_load.Docload
module Policy_load = Haltsql_load.Policy_load
module Catalog_load = Haltsql_load.Catalog_load
module Config = Haltsql_load.Config
module Schemas = Haltsql_load.Schemas
module Test_suite = Haltsql_load.Test_suite

(** {1 Pipeline stages} *)

module Pg_parse = Haltsql_parse.Pg_parse
module Analyzer = Haltsql_analyzer.Analyzer
module Suite_runner = Suite_runner

(** {1 Verification} *)

val version : string
(** HaltSQL release version. *)

val verify : Policy.t -> Context.t -> string -> Verdict.t
(** [verify policy ctx sql] decides whether the exact string [sql] may be executed for the
    caller described by [ctx].

    Total: never raises. Any parse failure, limit breach, unsupported syntax or internal
    error (including [Stack_overflow] / [Out_of_memory]) yields a denial (in shadow mode,
    a shadow denial). Pure apart from reading the clock for [elapsed_us]; safe to call
    concurrently from several domains with the same policy. *)

val sha256_hex : string -> string
(** Lower-case hex SHA-256 of a string (the verdict's [sql_sha256]). *)
