(** HaltSQL — a policy firewall for LLM-generated PostgreSQL.

    {[
    let policy = Haltsql.Policy_load.of_file "policy.yaml" |> Result.get_ok in
    let ctx = Haltsql.Context.make [ ("tenant_id", One "acme") ] in
    let v =
      Haltsql.verify policy ctx "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10"
    in
    if v.allowed then (* run exactly that string, binding v.bind_params *) ()
    ]}

    [verify] never touches the database and never rewrites SQL. *)

module Ast = Haltsql_core.Ast
module Reason = Haltsql_core.Reason
module Context = Haltsql_core.Context
module Catalog = Haltsql_core.Catalog
module Policy = Haltsql_core.Policy
module Verdict = Haltsql_core.Verdict
module Load_error = Haltsql_core.Load_error
module Docload = Haltsql_load.Docload
module Policy_load = Haltsql_load.Policy_load
module Catalog_load = Haltsql_load.Catalog_load
module Config = Haltsql_load.Config
module Schemas = Haltsql_load.Schemas
module Pg_parse = Haltsql_parse.Pg_parse
module Analyzer = Haltsql_analyzer.Analyzer
module Test_suite = Haltsql_load.Test_suite
module Suite_runner = Suite_runner

val version : string
(** HaltSQL release version. *)

val verify : Policy.t -> Context.t -> string -> Verdict.t
(** Total: never raises. Any parse failure, limit breach, unsupported syntax or internal
    error yields a denial (in shadow mode, a shadow denial). *)

val sha256_hex : string -> string
