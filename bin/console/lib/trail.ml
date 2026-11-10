(* Decision trail of one audit record: which stage of verification stopped (or would have
   stopped) the statement, and the detailed reasons.

   The record's own codes always decide what happened. When raw SQL and the named policy
   are available, the SQL is re-verified ({!Haltsql.verify}) only to name the objects
   (messages, rules, hints, tables); see {!Haltsql_report.Record.with_details}. *)

module Record = Haltsql_report.Record

type stage = Parse | Tables | Tenancy | Limit | Functions | Opa | Verdict

let stage_name = function
  | Parse -> "parse"
  | Tables -> "tables"
  | Tenancy -> "tenancy"
  | Limit -> "limit"
  | Functions -> "functions"
  | Opa -> "opa"
  | Verdict -> "verdict"

(** The stage a reason code belongs to (see lib/core/reason.ml). Unknown codes belong to
    the verdict. *)
let stage_of_code = function
  | "E_PARSE" | "E_EMPTY" | "E_LIMIT" | "E_MULTI_STATEMENT" | "E_STATEMENT_KIND"
  | "E_DATA_MODIFYING_CTE" | "E_LOCKING_CLAUSE" | "E_SELECT_INTO" | "E_UNSUPPORTED"
  | "E_INTERNAL" ->
      Parse
  | "E_TABLE_DENIED" | "E_COLUMN_DENIED" | "E_COLUMN_UNRESOLVED" | "E_WRITE_DENIED" ->
      Tables
  | "E_TENANT_MISSING" | "E_TENANT_MISMATCH" | "E_TENANT_WRITE" | "E_CONTEXT_MISSING"
  | "E_PARAM_UNBOUND" ->
      Tenancy
  | "E_LIMIT_REQUIRED" | "E_LIMIT_TOO_HIGH" | "E_JOIN_BUDGET" -> Limit
  | "E_FUNCTION_DENIED" | "E_OPERATOR_DENIED" | "E_CAST_DENIED" -> Functions
  | "E_EXTERNAL_POLICY" -> Opa
  | _ -> Verdict

(* Codes after which the analyzer does not look further. *)
let hard_stop = function
  | "E_PARSE" | "E_EMPTY" | "E_LIMIT" | "E_MULTI_STATEMENT" | "E_UNSUPPORTED"
  | "E_INTERNAL" ->
      true
  | _ -> false

(** A generic description of a code, used when no detailed reason is known. *)
let describe = function
  | "E_PARSE" -> "The SQL did not parse."
  | "E_EMPTY" -> "There was no statement."
  | "E_LIMIT" -> "A size, depth or node-count limit was exceeded."
  | "E_MULTI_STATEMENT" -> "More than one statement was sent."
  | "E_STATEMENT_KIND" -> "This kind of statement is not allowed."
  | "E_DATA_MODIFYING_CTE" -> "A CTE writes data and writes are not allowed."
  | "E_TABLE_DENIED" -> "A relation is not in the allowlist."
  | "E_COLUMN_DENIED" -> "A column is not allowed (or * expands to a denied column)."
  | "E_COLUMN_UNRESOLVED" -> "A column is ambiguous or unknown."
  | "E_FUNCTION_DENIED" -> "A function is not in the allowlist."
  | "E_OPERATOR_DENIED" -> "An operator is not in the allowlist."
  | "E_CAST_DENIED" -> "A cast to a denied type was used."
  | "E_TENANT_MISSING" -> "A tenant-scoped relation lacks a provable tenant predicate."
  | "E_TENANT_MISMATCH" -> "A tenant value differs from the caller's context."
  | "E_TENANT_WRITE" -> "A write would set or change a tenant column incorrectly."
  | "E_CONTEXT_MISSING" -> "A context value the policy needs was not supplied."
  | "E_PARAM_UNBOUND" -> "The query uses a parameter HaltSQL cannot bind."
  | "E_LIMIT_REQUIRED" -> "LIMIT is missing."
  | "E_LIMIT_TOO_HIGH" -> "LIMIT is larger than allowed, or not a constant."
  | "E_LOCKING_CLAUSE" -> "FOR UPDATE / FOR SHARE is not allowed."
  | "E_SELECT_INTO" -> "SELECT ... INTO is not allowed."
  | "E_JOIN_BUDGET" -> "Too many joins, or an unconstrained cross join."
  | "E_WRITE_DENIED" -> "A write to a table or column the policy does not allow."
  | "E_UNSUPPORTED" -> "Syntax HaltSQL does not analyze (always denied)."
  | "E_INTERNAL" -> "Analyzer error (fails closed)."
  | "E_EXTERNAL_POLICY" ->
      "The external policy engine (OPA) denied the query, or could not be asked and \
       on_error is deny."
  | c -> Printf.sprintf "Reason %s." c

(* ---- re-verification ---- *)

type reverified = { verdict : Haltsql.Verdict.t; record : Record.t }

(** Re-verifies the record's SQL against its policy when both are available. *)
let reverify (policies : (string * Haltsql.Policy.t) list) (e : Index.entry) =
  match (Index.raw_sql e, List.assoc_opt e.record.policy policies) with
  | Some sql, Some policy -> (
      let context =
        match Api.member "context" e.raw with
        | Some (`Assoc _ as c) -> (
            match Haltsql.Context.of_json c with
            | Ok c -> c
            | Error _ -> Haltsql_report.Suggest.probe_context policy)
        | _ -> Haltsql_report.Suggest.probe_context policy
      in
      try
        let verdict = Haltsql.verify policy context sql in
        Some { verdict; record = Record.with_details e.record verdict }
      with _ -> None)
  | _ -> None

(* ---- building the trail ---- *)

type reason = {
  code : string;
  rule : string option;
  message : string;
  hint : string option;
}

(** One entry per recorded code, detailed from re-verification when available. With
    [~redact:true], re-verified details keep only their rule: the message is the generic
    {!describe} and there is no hint, since analyzer messages quote SQL literals. *)
let reasons ?reverified ?(redact = false) (r : Record.t) =
  let details, verdict_reasons =
    match reverified with
    | Some rv -> (rv.record.details, rv.verdict.reasons @ rv.verdict.shadow_reasons)
    | None -> (r.details, [])
  in
  List.concat_map
    (fun code ->
      match List.filter (fun (d : Record.reason) -> d.code = code) details with
      | [] -> [ { code; rule = None; message = describe code; hint = None } ]
      | ds when redact && reverified <> None ->
          List.sort_uniq compare (List.map (fun (d : Record.reason) -> d.rule) ds)
          |> List.map (fun rule ->
              { code; rule = Some rule; message = describe code; hint = None })
      | ds ->
          List.map
            (fun (d : Record.reason) ->
              let hint =
                List.find_map
                  (fun (vr : Haltsql.Reason.t) ->
                    if
                      Haltsql.Reason.code_to_string vr.code = code
                      && vr.message = d.message
                    then vr.hint
                    else None)
                  verdict_reasons
              in
              { code; rule = Some d.rule; message = d.message; hint })
            ds)
    r.codes

let reason_to_json r : Yojson.Safe.t =
  `Assoc
    [
      ("code", `String r.code);
      ("rule", Api.opt_string r.rule);
      ("message", `String r.message);
      ("hint", Api.opt_string r.hint);
    ]

type step = { stage : stage; state : string; detail : string }

let step_to_json s : Yojson.Safe.t =
  `Assoc
    [
      ("stage", `String (stage_name s.stage));
      ("state", `String s.state);
      ("detail", `String s.detail);
    ]

let compute ?policy ?reverified (r : Record.t) (reasons : reason list) =
  let shadow = r.outcome = Record.Shadow_denied in
  let codes_in st = List.filter (fun c -> stage_of_code c = st) r.codes in
  let messages st =
    List.filter_map
      (fun (x : reason) -> if stage_of_code x.code = st then Some x.message else None)
      reasons
    |> List.sort_uniq compare
  in
  let denied st =
    let msgs = String.concat " " (messages st) in
    let prefix = if shadow then "Shadow mode: would deny. " else "" in
    {
      stage = st;
      state = "denied";
      detail = Printf.sprintf "%s%s (%s)" prefix msgs (String.concat ", " (codes_in st));
    }
  in
  let stopped = List.exists hard_stop r.codes in
  let tables =
    match (r.tables, reverified) with [], Some rv -> rv.verdict.tables | t, _ -> t
  in
  let parse =
    if codes_in Parse <> [] then denied Parse
    else
      let kind =
        match reverified with
        | Some rv -> (
            match rv.verdict.statement_kind with
            | Some k -> Printf.sprintf "One %s statement." (String.uppercase_ascii k)
            | None -> "Parsed.")
        | None -> "Parsed."
      in
      { stage = Parse; state = "passed"; detail = kind }
  in
  let analyzer st ~passed =
    if codes_in st <> [] then denied st
    else if stopped then
      {
        stage = st;
        state = "not_run";
        detail = "Not evaluated: the statement was rejected while parsing.";
      }
    else { stage = st; state = "passed"; detail = passed }
  in
  let tables_step =
    analyzer Tables
      ~passed:
        (if tables = [] then "Every relation and column is allowed."
         else
           Printf.sprintf "Every relation and column is allowed (%s)."
             (String.concat ", " tables))
  in
  let tenancy_step =
    match policy with
    | Some (p : Haltsql.Policy.t)
      when p.tenancy.keys = [] && codes_in Tenancy = [] && not stopped ->
        { stage = Tenancy; state = "skipped"; detail = "The policy has no tenancy keys." }
    | _ ->
        analyzer Tenancy
          ~passed:"Every tenant-scoped relation is filtered on the caller's tenant."
  in
  let limit_step =
    analyzer Limit
      ~passed:
        (match policy with
        | Some { Haltsql.Policy.require_limit = Some n; _ } ->
            Printf.sprintf "LIMIT present and at most %d; join budget respected." n
        | Some { require_limit = None; _ } -> "No LIMIT required; join budget respected."
        | None -> "LIMIT and join budget respected.")
  in
  let functions_step =
    analyzer Functions ~passed:"Every function, operator and cast is allowed."
  in
  let haltsql_denied =
    r.outcome = Record.Denied && List.exists (fun c -> stage_of_code c <> Opa) r.codes
  in
  let opa_step =
    if codes_in Opa <> [] then denied Opa
    else if haltsql_denied then
      {
        stage = Opa;
        state = "not_run";
        detail = "OPA is only asked after HaltSQL allows a statement.";
      }
    else
      {
        stage = Opa;
        state = "passed";
        detail = "No external policy denial recorded (OPA allowed or is not configured).";
      }
  in
  let unknown = codes_in Verdict in
  let verdict_step =
    let extra =
      if unknown = [] then ""
      else Printf.sprintf " Other reasons: %s." (String.concat ", " unknown)
    in
    match r.outcome with
    | Record.Allowed -> { stage = Verdict; state = "passed"; detail = "Allowed." ^ extra }
    | Record.Shadow_denied ->
        {
          stage = Verdict;
          state = "passed";
          detail =
            Printf.sprintf "Allowed in shadow mode; enforce mode would deny (%s).%s"
              (String.concat ", " r.codes) extra;
        }
    | Record.Denied ->
        {
          stage = Verdict;
          state = "denied";
          detail = Printf.sprintf "Denied (%s).%s" (String.concat ", " r.codes) extra;
        }
  in
  [ parse; tables_step; tenancy_step; limit_step; functions_step; opa_step; verdict_step ]
