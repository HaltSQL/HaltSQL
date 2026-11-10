(* Public facade of the core libraries; see haltsql.mli. *)

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

let version = "0.0.2"
let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let multi_statement n =
  Reason.make ~rule:"statement.count" Reason.E_MULTI_STATEMENT
    (Printf.sprintf "expected exactly one statement, found %d" n)
    ~hint:"Send a single SQL statement with no semicolon-separated extras."

let empty_analysis reasons : Analyzer.analysis =
  { reasons; statement_kind = None; tables = []; columns = []; bind_params = [] }

(* The catch-all handler is deliberate: [verify] must never raise, so any
   exception (a bug, or Stack_overflow / Out_of_memory on hostile input) becomes
   an [E_INTERNAL] denial. [Pg_parse.parse] and [Analyzer.analyze] are already
   total; this is the last line of defence. *)
let verify (policy : Policy.t) (ctx : Context.t) (sql : string) : Verdict.t =
  let t0 = Unix.gettimeofday () in
  let parsed = ref false in
  let analysis =
    try
      match Pg_parse.parse ~limits:policy.limits sql with
      | Error r -> empty_analysis [ r ]
      | Ok [ stmt ] ->
          parsed := true;
          Analyzer.analyze policy ctx stmt
      | Ok [] ->
          empty_analysis
            [
              Reason.make ~rule:"statement.count" Reason.E_EMPTY "no SQL statement found";
            ]
      | Ok stmts -> empty_analysis [ multi_statement (List.length stmts) ]
    with e ->
      empty_analysis
        [
          Reason.make ~rule:"internal" Reason.E_INTERNAL
            ("internal error: " ^ Printexc.to_string e);
        ]
  in
  let denied = analysis.reasons <> [] in
  let allowed, reasons, shadow_reasons =
    match policy.mode with
    | Policy.Enforce -> (not denied, analysis.reasons, [])
    | Policy.Shadow -> (true, [], analysis.reasons)
  in
  {
    allowed;
    reasons;
    shadow_reasons;
    policy_name = policy.name;
    policy_version = policy.version;
    statement_kind = Option.map Policy.stmt_kind_to_string analysis.statement_kind;
    tables = analysis.tables;
    columns = analysis.columns;
    bind_params = (if denied then [] else analysis.bind_params);
    (* Only for input that parsed: fingerprinting is a second full parse, and
       oversized or malformed input must stay cheap to reject. *)
    fingerprint =
      (if !parsed then try Pg_parse.fingerprint sql with _ -> None else None);
    sql_sha256 = sha256_hex sql;
    elapsed_us = int_of_float ((Unix.gettimeofday () -. t0) *. 1e6);
  }
