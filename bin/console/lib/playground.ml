(* Playground: verify a query against live, shadow or draft policies, with OPA like the
   server. Owner: PR console/05-build. See docs/console/api.md (Playground).

   Nothing touches a database. The verdict JSON is [Haltsql.Verdict.to_json], exactly what
   haltsql-server returns from /v1/verify, after the same OPA step
   ([Haltsql_opa.Opa.enforce]) when the console has an [opa] block. *)

open Lwt.Syntax
module Policy = Haltsql.Policy
module Verdict = Haltsql.Verdict
module Reason = Haltsql.Reason
module Opa = Haltsql_opa.Opa

(* ---- OPA configuration (same block as the server's) ---- *)

(* Placeholders in the [opa] block (e.g. a bearer token) are resolved on every check
   ({!Console_config.resolve}, cached for at most five minutes). *)
let opa_config (ctx : Ctx.t) =
  match ctx.config.opa with
  | None -> Lwt.return_none
  | Some j -> (
      let+ j = Console_config.resolve_json ctx.config j in
      let j = match j with Ok j -> j | Error m -> Api.not_configured "opa: %s" m in
      let base_dir =
        match ctx.config.file with Some f -> Filename.dirname f | None -> Sys.getcwd ()
      in
      let doc =
        `Assoc
          [
            ("apiVersion", `String "haltsql.dev/v1");
            ("kind", `String "Config");
            ("opa", j);
          ]
      in
      match Haltsql.Config.of_json ~base_dir ~env:(fun _ -> None) doc with
      | Ok c -> c.opa
      | Error e ->
          Api.not_configured "opa is invalid: %s"
            (String.concat "; " (List.map Haltsql.Load_error.to_string e)))

(* ---- stages ---- *)

let stage_of_code (c : Reason.code) =
  match c with
  | E_PARSE | E_EMPTY | E_LIMIT | E_MULTI_STATEMENT | E_UNSUPPORTED | E_INTERNAL ->
      "parse"
  | E_STATEMENT_KIND | E_DATA_MODIFYING_CTE | E_TABLE_DENIED | E_COLUMN_DENIED
  | E_COLUMN_UNRESOLVED | E_WRITE_DENIED | E_SELECT_INTO | E_LOCKING_CLAUSE ->
      "tables"
  | E_TENANT_MISSING | E_TENANT_MISMATCH | E_TENANT_WRITE | E_CONTEXT_MISSING
  | E_PARAM_UNBOUND ->
      "tenancy"
  | E_FUNCTION_DENIED | E_OPERATOR_DENIED | E_CAST_DENIED -> "functions"
  | E_LIMIT_REQUIRED | E_LIMIT_TOO_HIGH | E_JOIN_BUDGET -> "limit"
  | E_EXTERNAL_POLICY -> "opa"

let stage name state detail =
  `Assoc [ ("stage", `String name); ("state", `String state); ("detail", `String detail) ]

(** [opa_state]: [`Not_asked why] or [`Asked (allowed, detail)]. *)
let stages (p : Policy.t) (v : Verdict.t) ~haltsql_reasons opa_state =
  let shadow = p.mode = Policy.Shadow in
  let in_stage s =
    List.filter (fun (r : Reason.t) -> stage_of_code r.code = s) haltsql_reasons
  in
  let messages rs = String.concat "; " (List.map (fun (r : Reason.t) -> r.message) rs) in
  let denied s rs =
    stage s "denied" ((if shadow then "Would deny (shadow): " else "") ^ messages rs)
  in
  let parse_failed = in_stage "parse" <> [] in
  let analysis name passed_detail =
    if parse_failed then stage name "not_run" "The statement did not parse."
    else
      match in_stage name with
      | [] -> stage name "passed" passed_detail
      | rs -> denied name rs
  in
  let kind =
    match v.statement_kind with Some k -> String.uppercase_ascii k | None -> "statement"
  in
  let tables =
    match v.tables with
    | [] -> "No tables."
    | l -> "Allowed: " ^ String.concat ", " l ^ "."
  in
  let tenancy =
    match p.tenancy.keys with
    | [] -> "The policy has no tenancy."
    | _ -> (
        match v.bind_params with
        | [] -> "Tenant predicates proven."
        | l ->
            Printf.sprintf "Tenant predicates proven; bind %s."
              (String.concat ", " (List.map (fun (n, _) -> Printf.sprintf "$%d" n) l)))
  in
  let limit =
    match p.require_limit with
    | Some m -> Printf.sprintf "LIMIT within %d." m
    | None -> "No LIMIT required."
  in
  [
    (match in_stage "parse" with
    | [] -> stage "parse" "passed" (Printf.sprintf "One %s." kind)
    | rs -> denied "parse" rs);
    analysis "tables" tables;
    analysis "tenancy" tenancy;
    analysis "functions" "Functions and operators allowed.";
    analysis "limit" limit;
    (match opa_state with
    | `Not_asked (st, why) -> stage "opa" st why
    | `Asked (true, d) -> stage "opa" "passed" d
    | `Asked (false, d) -> stage "opa" "denied" d);
  ]

(* ---- targets ---- *)

(* Limits of one check: targets compared, size of a draft policy, and the time all of the
   check's OPA calls together may take (targets after that are not sent to OPA). *)
let max_targets = 10
let max_draft_bytes = 256 * 1024
let opa_budget_seconds = 10.

type target = { policy : Policy.t; where : string; label : string }

let invalid_draft errs =
  Api.json ~status:`Bad_request
    (`Assoc
       [
         ( "error",
           `Assoc
             [
               ("code", `String "BAD_REQUEST");
               ("message", `String "draft policy is invalid");
               ("errors", Api.strings errs);
             ] );
       ])

exception Draft_invalid of string list

let target_of_json ctx j =
  let name =
    match Api.member "policy" j with
    | Some (`String s) when s <> "" -> Some s
    | None | Some `Null -> None
    | Some _ -> Api.bad_request "targets[].policy must be a string"
  in
  match Api.member "draft" j with
  | Some (`String draft) when String.length draft > max_draft_bytes ->
      Api.bad_request "targets[].draft is %d bytes; the limit is %d" (String.length draft)
        max_draft_bytes
  | Some (`String draft) -> (
      match
        Haltsql.Policy_load.of_string ~file:"draft.yaml" Haltsql.Docload.Yaml draft
      with
      | Ok p ->
          let n = Option.value name ~default:p.name in
          { policy = p; where = "draft"; label = n ^ " (draft)" }
      | Error e -> raise (Draft_invalid (List.map Haltsql.Load_error.to_string e)))
  | Some `Null | None -> (
      match name with
      | None -> Api.bad_request "each target needs policy or draft"
      | Some n -> (
          match Policies.find ctx n with
          | Some i ->
              let where = if i.policy.mode = Policy.Shadow then "shadow" else "live" in
              { policy = i.policy; where; label = Printf.sprintf "%s (%s)" n where }
          | None -> Api.not_found "policy %s is not loaded" n))
  | Some _ -> Api.bad_request "targets[].draft must be a string (policy YAML)"

let default_targets ctx caller =
  match caller with
  | None -> Api.bad_request "give targets, or a caller (agent name) to use its policies"
  | Some name -> (
      match Agents.find ctx name with
      | None -> Api.not_found "no agent %s" name
      | Some a ->
          let names =
            Option.to_list (Agents.enforced_policy a) @ Agents.shadow_policies ctx a
          in
          if names = [] then Api.bad_request "agent %s has no known policy" name;
          let names = List.filteri (fun i _ -> i < max_targets) names in
          List.map (fun n -> target_of_json ctx (`Assoc [ ("policy", `String n) ])) names)

(* ---- columns ---- *)

let catalog_entry (ctx : Ctx.t) column =
  match Data.columns_doc ctx with
  | None -> None
  | Some j -> (
      match Api.member "columns" j with
      | Some (`List l) ->
          List.find_opt (fun c -> Api.member "column" c = Some (`String column)) l
      | _ -> None)

let allows_column (p : Policy.t) column =
  match String.rindex_opt column '.' with
  | None -> false
  | Some i -> (
      let tbl = String.sub column 0 i
      and col = String.sub column (i + 1) (String.length column - i - 1) in
      match String.index_opt tbl '.' with
      | None -> false
      | Some k -> (
          let schema = String.sub tbl 0 k
          and name = String.sub tbl (k + 1) (String.length tbl - k - 1) in
          match Policy.find_table p ~schema ~name with
          | Some { columns = Policy.All; _ } -> true
          | Some { columns = Policy.Only l; _ } -> List.mem col l
          | None -> false))

let columns_json ctx columns =
  List.map
    (fun c ->
      let entry = catalog_entry ctx c in
      let list k =
        match Option.bind entry (Api.member k) with
        | Some (`List l) -> `List l
        | _ -> `List []
      in
      `Assoc
        [
          ("column", `String c);
          ("tags", list "tags");
          ("sources", list "sources");
          ( "allowed_by",
            Api.strings
              (List.filter_map
                 (fun (i : Policies.info) ->
                   if allows_column i.policy c then Some i.name else None)
                 (Policies.all ctx)) );
        ])
    columns

(* ---- test case ---- *)

let test_case ~sql ~context_json ~(target : target) (v : Verdict.t) =
  let reasons = v.reasons @ v.shadow_reasons in
  let expect = if reasons = [] then "allow" else "deny" in
  let codes =
    List.sort_uniq compare
      (List.map (fun (r : Reason.t) -> Reason.code_to_string r.code) reasons)
  in
  let q = Haltsql_report.Suggest.yaml_scalar in
  let name =
    Printf.sprintf "%s %s (playground %s)"
      (Option.value v.statement_kind ~default:"statement")
      (if expect = "allow" then "is allowed" else "is denied")
      (String.sub v.sql_sha256 0 8)
  in
  String.concat ""
    ([
       Printf.sprintf "- name: %s\n" (q name);
       Printf.sprintf "  # policy: %s\n" target.policy.name;
       Printf.sprintf "  context: %s\n" (Yojson.Safe.to_string context_json);
       Printf.sprintf "  sql: %s\n" (q sql);
       Printf.sprintf "  expect: %s\n" expect;
     ]
    @
    if codes = [] then []
    else [ Printf.sprintf "  codes: [%s]\n" (String.concat ", " codes) ])

(* ---- check ---- *)

let run_target ~opa_cfg ~use_opa ~opa_deadline ~caller ~context (t : target) sql =
  let v = Haltsql.verify t.policy context sql in
  let haltsql_reasons = v.reasons @ v.shadow_reasons in
  let* v, opa_json, opa_state =
    match (opa_cfg, use_opa) with
    | Some _, true when Unix.gettimeofday () > opa_deadline ->
        Lwt.return
          ( v,
            `Assoc
              [
                ("asked", `Bool false);
                ("allowed", `Null);
                ("ms", `Null);
                ("error", `String "time budget spent");
              ],
            `Not_asked
              ( "not_run",
                Printf.sprintf
                  "OPA was not asked: this check's OPA calls already took %.0f s."
                  opa_budget_seconds ) )
    | None, _ ->
        Lwt.return
          ( v,
            `Assoc
              [
                ("asked", `Bool false); ("allowed", `Null); ("ms", `Null); ("error", `Null);
              ],
            `Not_asked ("skipped", "OPA is not configured in the console.") )
    | Some _, false ->
        Lwt.return
          ( v,
            `Assoc
              [
                ("asked", `Bool false); ("allowed", `Null); ("ms", `Null); ("error", `Null);
              ],
            `Not_asked ("skipped", "OPA was not requested.") )
    | Some cfg, true ->
        let t0 = Unix.gettimeofday () in
        let* v', outcome =
          Opa.enforce ~code:Reason.E_EXTERNAL_POLICY ~mode:t.policy.mode ~cfg ~caller
            ~context v
        in
        let ms = (Unix.gettimeofday () -. t0) *. 1000. in
        let asked, allowed, error, reasons =
          match outcome with
          | Opa.Skipped -> (false, `Null, `Null, [])
          | Opa.Allowed -> (true, `Bool true, `Null, [])
          | Opa.Denied rs -> (true, `Bool false, `Null, rs)
          | Opa.Failed_open e -> (true, `Bool true, `String e, [])
          | Opa.Failed_closed e -> (true, `Bool false, `String e, [])
        in
        let state =
          match outcome with
          | Opa.Skipped ->
              `Not_asked ("not_run", "HaltSQL denied; OPA is only asked after an allow.")
          | Opa.Allowed -> `Asked (true, "OPA allowed.")
          | Opa.Denied rs ->
              `Asked
                ( false,
                  "OPA denied"
                  ^ match rs with [] -> "." | l -> ": " ^ String.concat "; " l )
          | Opa.Failed_open e ->
              `Asked (true, "OPA failed (" ^ e ^ "); on_error keeps HaltSQL's verdict.")
          | Opa.Failed_closed e ->
              `Asked (false, "OPA failed (" ^ e ^ "); on_error denies.")
        in
        Lwt.return
          ( v',
            `Assoc
              [
                ("asked", `Bool asked);
                ("allowed", allowed);
                ("ms", if asked then `Float (Float.round (ms *. 100.) /. 100.) else `Null);
                ("error", error);
                ("outcome", `String (Opa.outcome_label outcome));
                ("reasons", Api.strings reasons);
              ],
            state )
  in
  let allowed = v.reasons = [] && v.shadow_reasons = [] in
  Lwt.return
    ( v,
      `Assoc
        [
          ("label", `String t.label);
          ("policy", `String t.policy.name);
          ("version", `String t.policy.version);
          ("where", `String t.where);
          ("allowed", `Bool allowed);
          ("stages", `List (stages t.policy v ~haltsql_reasons opa_state));
          ("verdict", Verdict.to_json v);
          ("opa", opa_json);
        ] )

let check (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let* body = Router.json_body r in
  let _ = Ctx.require ~body p r.http Rbac.Use_playground in
  let sql = Option.get (Api.str_field ~required:true "sql" body) in
  let context_json = Option.value (Api.member "context" body) ~default:(`Assoc []) in
  let context_json = if context_json = `Null then `Assoc [] else context_json in
  let context =
    match Haltsql.Context.of_json context_json with
    | Ok c -> c
    | Error e -> Api.bad_request "invalid context: %s" e
  in
  let caller = Api.str_field "caller" body in
  let use_opa = Option.value (Api.bool_field "opa" body) ~default:true in
  match
    match Api.member "targets" body with
    | None | Some `Null | Some (`List []) -> default_targets ctx caller
    | Some (`List l) when List.compare_length_with l max_targets > 0 ->
        Api.bad_request "at most %d targets per check (got %d)" max_targets
          (List.length l)
    | Some (`List l) -> List.map (target_of_json ctx) l
    | Some _ -> Api.bad_request "targets must be a list"
  with
  | exception Draft_invalid errs -> invalid_draft errs
  | targets ->
      let* opa_cfg = opa_config ctx in
      let opa_caller =
        {
          Opa.caller_name = Option.value caller ~default:("console:" ^ p.id);
          caller_type = "playground";
        }
      in
      let opa_deadline = Unix.gettimeofday () +. opa_budget_seconds in
      let* results =
        Lwt_list.map_s
          (fun t ->
            run_target ~opa_cfg ~use_opa ~opa_deadline ~caller:opa_caller ~context t sql)
          targets
      in
      let columns =
        List.sort_uniq compare
          (List.concat_map (fun ((v : Verdict.t), _) -> v.columns) results)
      in
      let test_case =
        match (targets, results) with
        | t :: _, (v, _) :: _ -> `String (test_case ~sql ~context_json ~target:t v)
        | _ -> `Null
      in
      let sql_sha256 = Haltsql.sha256_hex sql in
      let* () =
        Activity.log ctx p ~action:"playground.check"
          ~target:(String.concat "," (List.map (fun t -> t.label) targets))
          ~detail:
            (`Assoc
               [
                 ("sql_sha256", `String sql_sha256);
                 ("caller", Api.opt_string caller);
                 ( "results",
                   `List
                     (List.map2
                        (fun t (_, j) ->
                          `Assoc
                            [
                              ("label", `String t.label);
                              ( "allowed",
                                Option.value (Api.member "allowed" j) ~default:`Null );
                            ])
                        targets results) );
               ])
          ()
      in
      Api.json
        (`Assoc
           [
             ("sql_sha256", `String sql_sha256);
             ("results", `List (List.map snd results));
             ("columns", `List (columns_json ctx columns));
             ("test_case", test_case);
           ])

let routes : Router.route list = [ Router.post "/api/v1/playground/check" check ]
let start (_ : Ctx.t) : unit Lwt.t = Lwt.return_unit
