(* Policy loading, shadow reports, suggestions and pull requests. Owner: PR console/05-build.
   See docs/console/api.md (Policies and rollouts) and docs/console/config.md (policies).

   Policies come from [policies.server_config] (a haltsql-server config: its inline and
   path policies and its local signed bundles, loaded with the same libraries as the
   server) and [policies.files] (policy files or directories). They are reloaded every 60
   seconds; a load that fails anywhere keeps the previous set, like the server's reload.
   [Policy_set] holds the compiled policies by name; this module also keeps, per policy,
   where it came from and its source text for detail views. *)

open Lwt.Syntax
module Policy = Haltsql.Policy
module Docload = Haltsql.Docload
module R = Haltsql_report

type info = {
  name : string;
  policy : Policy.t;
  origin : string;  (** "config" (server config), "bundle" (signed bundle), "file" *)
  file : string option;  (** absolute path; only its basename is ever shown *)
  bundle : string option;  (** bundle file basename *)
  source : string;  (** the policy document as written (normalized YAML when inline) *)
  format : Docload.format;
}

type state = {
  mutable infos : info list;
  mutable loaded_at : float option;
  mutable errors : string list;
  mutable notes : string list;
  pr_cache : (string, float * Yojson.Safe.t) Hashtbl.t;
      (** policy name -> (fetched at, live PR state from GitHub) *)
}

(* Feature state per console, in the Ctx registry under a private key. *)
let key : state Ctx.Key.t = Ctx.Key.create "policies"

let state (ctx : Ctx.t) =
  match Ctx.get ctx key with
  | Some s -> s
  | None ->
      let s =
        {
          infos = [];
          loaded_at = None;
          errors = [];
          notes = [];
          pr_cache = Hashtbl.create 8;
        }
      in
      Ctx.set ctx key s;
      s

let log level fmt =
  Printf.ksprintf
    (fun m ->
      Printf.eprintf "{\"ts\":%S,\"level\":%S,\"msg\":%s}\n%!"
        (Api.iso8601 (Unix.gettimeofday ()))
        level
        (Yojson.Safe.to_string (`String m)))
    fmt

let all ctx = (state ctx).infos
let find ctx name = List.find_opt (fun i -> i.name = name) (all ctx)

let mode_string (p : Policy.t) =
  match p.mode with Policy.Enforce -> "enforce" | Policy.Shadow -> "shadow"

(** Shadow siblings of [name]: loaded shadow-mode policies named [name-*], [name_*] or
    [name.*]. *)
let shadow_siblings ctx name =
  List.filter
    (fun i ->
      i.name <> name && i.policy.mode = Policy.Shadow
      && List.exists
           (fun sep -> String.starts_with ~prefix:(name ^ sep) i.name)
           [ "-"; "_"; "." ])
    (all ctx)

(* ---- loading ---- *)

let read_file f = In_channel.with_open_bin f In_channel.input_all
let errs_to_strings = List.map Haltsql.Load_error.to_string
let format_of f = Option.value (Docload.format_of_path f) ~default:Docload.Yaml

(* Error messages may carry absolute paths; show basenames only. *)
let sanitize msg =
  String.split_on_char ' ' msg
  |> List.map (fun tok ->
      if String.length tok > 1 && tok.[0] = '/' then Filename.basename tok
      else if String.length tok > 2 && tok.[0] = '"' && tok.[1] = '/' then
        "\"" ^ Filename.basename (String.sub tok 1 (String.length tok - 1))
      else tok)
  |> String.concat " "

let of_policy_file ~origin f (p : Policy.t) =
  {
    name = p.name;
    policy = p;
    origin;
    file = Some f;
    bundle = None;
    source = (try read_file f with Sys_error _ -> "");
    format = format_of f;
  }

let normalized ~origin ?bundle (p : Policy.t) =
  {
    name = p.name;
    policy = p;
    origin;
    file = None;
    bundle;
    source = Docload.to_string Docload.Yaml (Haltsql.Policy_load.to_json p);
    format = Docload.Yaml;
  }

let resolve (cfg : Console_config.t) p =
  if Filename.is_relative p then
    match cfg.file with Some f -> Filename.concat (Filename.dirname f) p | None -> p
  else p

(* In a directory, only YAML/JSON documents with [kind: Policy] are policies (suites and
   catalogs may sit next to them); an unreadable document is left to the loader. *)
let is_policy_doc f =
  match Docload.of_file f with
  | Ok j -> (
      match Api.member "kind" j with Some (`String "Policy") -> true | _ -> false)
  | Error _ -> true

let policy_paths entry =
  if Sys.is_directory entry then
    Sys.readdir entry |> Array.to_list |> List.sort compare
    |> List.filter (fun n -> n <> "" && n.[0] <> '.' && Docload.format_of_path n <> None)
    |> List.map (Filename.concat entry)
    |> List.filter (fun f -> (not (Sys.is_directory f)) && is_policy_doc f)
  else [ entry ]

let load_files (cfg : Console_config.t) =
  List.fold_left
    (fun (ok, errs) entry ->
      let entry = resolve cfg entry in
      if not (Sys.file_exists entry) then
        (ok, errs @ [ Printf.sprintf "%s: no such file or directory" entry ])
      else
        List.fold_left
          (fun (ok, errs) f ->
            match Haltsql.Policy_load.of_file f with
            | Ok p -> (ok @ [ of_policy_file ~origin:"file" f p ], errs)
            | Error e -> (ok, errs @ errs_to_strings e))
          (ok, errs) (policy_paths entry))
    ([], []) cfg.policies.policy_files

let load_server_config file =
  let* r = Haltsql_cloud.Secrets.load_config file in
  match r with
  | Error e -> Lwt.return (Error (errs_to_strings e))
  | Ok (c : Haltsql.Config.t) ->
      let by_name =
        List.filter_map
          (fun f ->
            match Haltsql.Policy_load.of_file f with
            | Ok p -> Some (p.Policy.name, f)
            | Error _ -> None)
          c.policy_files
      in
      let plain =
        List.map
          (fun (n, p) ->
            match List.assoc_opt n by_name with
            | Some f -> of_policy_file ~origin:"config" f p
            | None -> normalized ~origin:"config" p)
          c.policies
      in
      let bundled, errs =
        List.fold_left
          (fun (ok, errs) (b : Haltsql.Config.bundle_ref) ->
            let bn = Filename.basename b.bundle_path in
            match Haltsql_bundle.load_config_ref b with
            | Ok ps -> (ok @ List.map (normalized ~origin:"bundle" ~bundle:bn) ps, errs)
            | Error e ->
                ( ok,
                  errs
                  @ [
                      Printf.sprintf "bundle %s: %s" bn (Haltsql_bundle.error_to_string e);
                    ] ))
          ([], []) c.policy_bundles
      in
      let dup_errs =
        List.filter_map
          (fun b ->
            if List.exists (fun p -> p.name = b.name) plain then
              Some
                (Printf.sprintf
                   "bundle policy %S duplicates a policy defined in the config file"
                   b.name)
            else None)
          bundled
      in
      let notes =
        match c.bundle_sources with
        | [] -> []
        | l ->
            [
              Printf.sprintf
                "%d remote bundle_source(s) in the server config are not fetched by the \
                 console; their policies are listed from fleet status only"
                (List.length l);
            ]
      in
      if errs @ dup_errs <> [] then Lwt.return (Error (errs @ dup_errs))
      else Lwt.return (Ok (plain @ bundled, notes))

let duplicates names =
  let rec go seen acc = function
    | [] -> List.rev acc
    | n :: t ->
        if List.mem n seen && not (List.mem n acc) then go seen (n :: acc) t
        else go (n :: seen) acc t
  in
  go [] [] names

(** Reloads every source. Replaces the loaded set only when everything loaded. *)
let reload (ctx : Ctx.t) =
  let st = state ctx and cfg = ctx.config in
  let* from_server =
    match cfg.policies.server_config with
    | None -> Lwt.return (Ok ([], []))
    | Some f ->
        Lwt.catch
          (fun () -> load_server_config (resolve cfg f))
          (fun e -> Lwt.return (Error [ Printexc.to_string e ]))
  in
  let files, file_errs = try load_files cfg with e -> ([], [ Printexc.to_string e ]) in
  let result =
    match from_server with
    | Error e -> Error (e @ file_errs)
    | Ok _ when file_errs <> [] -> Error file_errs
    | Ok (base, notes) -> (
        match duplicates (List.map (fun i -> i.name) files) with
        | _ :: _ as d ->
            Error
              (List.map
                 (fun n -> Printf.sprintf "policy %S is defined by more than one file" n)
                 d)
        | [] ->
            (* policies.files replace server-config policies of the same name, like the
               server's --policy flags *)
            let base =
              List.filter
                (fun i -> not (List.exists (fun f -> f.name = i.name) files))
                base
            in
            Ok (base @ files, notes))
  in
  match result with
  | Ok (infos, notes) ->
      st.infos <- infos;
      st.notes <- notes;
      st.errors <- [];
      st.loaded_at <- Some (Ctx.now ());
      Policy_set.set ctx (List.map (fun i -> (i.name, i.policy)) infos);
      Lwt.return (Ok ())
  | Error errs ->
      let errs = List.map sanitize errs in
      st.errors <- errs;
      log "warn" "policies: load failed, keeping %d loaded policies: %s"
        (List.length st.infos) (String.concat "; " errs);
      Lwt.return (Error errs)

let start (ctx : Ctx.t) : unit Lwt.t =
  let p = ctx.config.policies in
  if p.server_config = None && p.policy_files = [] then (
    (state ctx).loaded_at <- Some (Ctx.now ());
    Lwt.return_unit)
  else
    let rec loop () =
      let* () =
        Lwt.catch
          (fun () ->
            let* _ = reload ctx in
            Lwt.return_unit)
          (fun e ->
            log "error" "policies: reload raised %s" (Printexc.to_string e);
            Lwt.return_unit)
      in
      let* () = Lwt_unix.sleep 60. in
      loop ()
    in
    loop ()

(* ---- fleet ---- *)

let fleet_verifiers (ctx : Ctx.t) =
  match Fleet.snapshot ctx with
  | Some j -> ( match Api.member "verifiers" j with Some (`List l) -> l | _ -> [])
  | None -> []

let str k j = match Api.member k j with Some (`String s) -> Some s | _ -> None

let verifier_policies v =
  match Api.member "policies" v with Some (`List l) -> l | _ -> []

(** Names of the verifiers that serve [name], from the last fleet snapshot. *)
let verifiers_serving ctx name =
  List.filter_map
    (fun v ->
      if List.exists (fun p -> str "name" p = Some name) (verifier_policies v) then
        str "name" v
      else None)
    (fleet_verifiers ctx)

(* ---- JSON ---- *)

let summary_json ctx i =
  `Assoc
    [
      ("name", `String i.name);
      ("version", `String i.policy.version);
      ("mode", `String (mode_string i.policy));
      ("origin", `String i.origin);
      ("file", Api.opt_string (Option.map Filename.basename i.file));
      ("bundle", Api.opt_string i.bundle);
      ("verifiers", Api.strings (verifiers_serving ctx i.name));
      ("owner", Api.opt_string i.policy.owner);
      ("shadow", Api.strings (List.map (fun s -> s.name) (shadow_siblings ctx i.name)));
      ("loaded", `Bool true);
    ]

(* Policies a verifier reports that the console did not load itself. *)
let fleet_only ctx =
  let local = List.map (fun i -> i.name) (all ctx) in
  List.fold_left
    (fun acc v ->
      List.fold_left
        (fun acc p ->
          match str "name" p with
          | Some n when (not (List.mem n local)) && not (List.mem_assoc n acc) ->
              acc @ [ (n, p) ]
          | _ -> acc)
        acc (verifier_policies v))
    [] (fleet_verifiers ctx)
  |> List.map (fun (n, p) ->
      `Assoc
        [
          ("name", `String n);
          ("version", Api.opt_string (str "version" p));
          ("mode", Api.opt_string (str "mode" p));
          ("origin", Api.opt_string (str "origin" p));
          ("file", `Null);
          ("bundle", `Null);
          ("verifiers", Api.strings (verifiers_serving ctx n));
          ("owner", `Null);
          ("shadow", `List []);
          ("loaded", `Bool false);
        ])

let columns_json = function Policy.All -> `String "*" | Policy.Only l -> Api.strings l

let detail_json ctx i =
  let p = i.policy in
  let tables =
    List.map
      (fun (t : Policy.table) ->
        `Assoc
          [
            ("table", `String (Policy.table_qualified_name t));
            ("columns", columns_json t.columns);
            ( "tenant_columns",
              `List
                (List.map
                   (fun (c, k) -> `Assoc [ ("column", `String c); ("key", `String k) ])
                   t.tenant_columns) );
            ( "writes",
              `Assoc
                [
                  ("insert", `Bool t.writes.insert);
                  ( "update",
                    match t.writes.update with None -> `Null | Some c -> columns_json c );
                  ("delete", `Bool t.writes.delete);
                ] );
          ])
      p.tables
  in
  match summary_json ctx i with
  | `Assoc base ->
      `Assoc
        (base
        @ [
            ("description", Api.opt_string p.description);
            ( "format",
              `String (match i.format with Docload.Yaml -> "yaml" | Json -> "json") );
            ("yaml", `String i.source);
            ("statements", Api.strings (List.map Policy.stmt_kind_to_string p.statements));
            ("require_limit", Api.opt_int p.require_limit);
            ( "tenancy",
              `Assoc
                [
                  ( "mode",
                    `String
                      (match p.tenancy.mode with
                      | Policy.Bound -> "bound"
                      | Policy.Literal -> "literal") );
                  ( "keys",
                    `List
                      (List.map
                         (fun (k, f) ->
                           `Assoc [ ("key", `String k); ("context_field", `String f) ])
                         p.tenancy.keys) );
                ] );
            ("tables", `List tables);
            ("functions", Api.strings p.functions);
          ])
  | j -> j

(* ---- report ---- *)

let make_verify () =
  let cache = Hashtbl.create 64 in
  fun (p : Policy.t) (c : Haltsql.Context.t) sql ->
    let k = (p.version, Haltsql.Context.to_json c, sql) in
    match Hashtbl.find_opt cache k with
    | Some v -> v
    | None ->
        let v = Haltsql.verify p c sql in
        Hashtbl.replace cache k v;
        v

let records_of (ctx : Ctx.t) ~since name =
  Index.fold ctx.index ~init:[] ~f:(fun acc (e : Index.entry) ->
      if e.record.policy = name && e.ts >= since then e.record :: acc else acc)
  |> List.rev

(** Adds detailed reasons by re-verifying raw SQL (like [haltsql report]), then shares
    them with records of the same policy and fingerprint. *)
let enrich ~policies ~verify (records : R.Record.t list) =
  let records = List.map (R.Live.enrich ~policies ~verify) records in
  let by_fp = Hashtbl.create 64 in
  List.iter
    (fun (r : R.Record.t) ->
      if r.details <> [] && R.Record.fingerprint_key r <> "(none)" then
        Hashtbl.replace by_fp (r.policy, R.Record.fingerprint_key r) r.details)
    records;
  List.map
    (fun (r : R.Record.t) ->
      match
        (r.details, Hashtbl.find_opt by_fp (r.policy, R.Record.fingerprint_key r))
      with
      | [], Some ds ->
          {
            r with
            details =
              List.filter (fun (d : R.Record.reason) -> List.mem d.code r.codes) ds;
          }
      | _ -> r)
    records

(* Columns the data catalogs tag are never suggested. *)
let catalog_pii (ctx : Ctx.t) : R.Pii.lookup =
  let tagged = Hashtbl.create 64 in
  (match Data.columns_doc ctx with
  | Some j -> (
      match Api.member "columns" j with
      | Some (`List cols) ->
          List.iter
            (fun c ->
              match (Api.member "column" c, Api.member "tags" c) with
              | Some (`String col), Some (`List (_ :: _ as tags)) ->
                  Hashtbl.replace tagged (String.lowercase_ascii col)
                    (String.concat ", "
                       (List.filter_map (function `String s -> Some s | _ -> None) tags))
              | _ -> ())
            cols
      | _ -> ())
  | None -> ());
  fun ~schema ~table ~column ->
    Option.map
      (fun t -> t ^ " (data catalog)")
      (Hashtbl.find_opt tagged
         (String.lowercase_ascii (schema ^ "." ^ table ^ "." ^ column)))

let compute_suggest (ctx : Ctx.t) ~verify records =
  let policies = Policy_set.get ctx in
  let records = enrich ~policies ~verify records in
  R.Suggest.compute
    {
      R.Suggest.default_config with
      policies;
      pii = R.Pii.union [ catalog_pii ctx; R.Pii.name_heuristic () ];
      verify = Some verify;
    }
    records

let suggestion_kind (c : R.Suggest.change) =
  match c with
  | Add_column _ -> "column"
  | Add_function _ -> "function"
  | Set_limit_max _ -> "limit"
  | Add_table _ -> "table"

let never_category code (cat : R.Suggest.category) =
  if String.starts_with ~prefix:"E_TENANT_" code || code = "E_CONTEXT_MISSING" then
    "tenancy"
  else if code = "E_EXTERNAL_POLICY" then "external_policy"
  else match cat with R.Suggest.Pii -> "sensitive_column" | _ -> "query_fix"

let never_json (sg : R.Suggest.t) =
  let rows =
    List.map
      (fun (c : R.Suggest.code_row) ->
        `Assoc
          [
            ("category", `String (never_category c.c_code c.c_category));
            ("codes", Api.strings [ c.c_code ]);
            ("records", `Int c.c_records);
            ("advice", `String c.advice);
            ("target", `Null);
          ])
      sg.codes
  in
  let items cat (l : R.Suggest.item list) =
    List.map
      (fun (i : R.Suggest.item) ->
        `Assoc
          [
            ("category", `String cat);
            ("codes", Api.strings [ i.i_code ]);
            ("records", `Int i.i_evidence.records);
            ("advice", `String i.reason);
            ("target", `String i.target);
          ])
      l
  in
  items "sensitive_column" sg.pii_flagged
  @ rows
  @ items "query_fix"
      (List.filter
         (fun (i : R.Suggest.item) -> i.category = R.Suggest.Unsafe)
         sg.not_suggested)

let tenant_code c = String.starts_with ~prefix:"E_TENANT_" c

(** Re-verifies the records' raw SQL under [cp]. The context is {!R.Suggest.probe_context}
    (placeholder tenancy values): records do not carry context values. *)
let comparison ~verify (cp : Policy.t) (records : R.Record.t list) =
  let compared = ref 0 and dna = ref 0 and adn = ref 0 and relaxed = ref 0 in
  List.iter
    (fun (r : R.Record.t) ->
      match r.sql with
      | None -> ()
      | Some sql ->
          incr compared;
          let v = verify cp (R.Suggest.probe_context cp) sql in
          let compare_allows =
            v.Haltsql.Verdict.reasons = [] && v.Haltsql.Verdict.shadow_reasons = []
          in
          let denied_now = r.outcome <> R.Record.Allowed in
          if denied_now && compare_allows then begin
            incr dna;
            if List.exists tenant_code r.codes then incr relaxed
          end;
          if (not denied_now) && not compare_allows then incr adn)
    records;
  `Assoc
    [
      ("records", `Int (List.length records));
      ("compared", `Int !compared);
      ("denied_now_allowed", `Int !dna);
      ("allowed_now_denied", `Int !adn);
      ("tenancy_relaxed", `Int !relaxed);
    ]

(* ---- pull request state ---- *)

let pr_collection = "pull_requests"
let pr_cache_seconds = 30.
let stored_pr (ctx : Ctx.t) name = Store.get ctx.store pr_collection name
let stored_int k j = match Api.member k j with Some (`Int n) -> Some n | _ -> None

let stored_suggestions j =
  match Api.member "suggestions" j with
  | Some (`List l) -> List.filter_map (function `String s -> Some s | _ -> None) l
  | _ -> []

(** The PR state for the report: the stored PR plus live state, checks and approvals from
    GitHub (cached for 30 s). *)
let pr_state (ctx : Ctx.t) name =
  match stored_pr ctx name with
  | None -> Lwt.return `Null
  | Some doc -> (
      let number = Option.value (stored_int "number" doc) ~default:0 in
      let base =
        [
          ("number", `Int number);
          ("url", Api.opt_string (str "url" doc));
          ("branch", Api.opt_string (str "branch" doc));
          ("head_sha", Api.opt_string (str "head_sha" doc));
        ]
      in
      let* gh = Github.config ctx in
      match gh with
      | None | Some (Error _) ->
          Lwt.return
            (`Assoc
               (base
               @ [
                   ("state", `String "unknown");
                   ("checks", `List []);
                   ("approvals", `List []);
                   ("required_approvals", `Null);
                   ("error", `String "GitHub integration is not configured");
                 ]))
      | Some (Ok gh) -> (
          let key = Printf.sprintf "%s|%s|%d" gh.api gh.repo number in
          match Hashtbl.find_opt (state ctx).pr_cache key with
          | Some (at, j) when Ctx.now () -. at < pr_cache_seconds -> Lwt.return j
          | _ ->
              let live =
                let* pr = Github.get_pr gh number in
                match pr with
                | None ->
                    Lwt.return
                      [
                        ("state", `String "missing");
                        ("checks", `List []);
                        ("approvals", `List []);
                      ]
                | Some pr ->
                    let sha =
                      match pr.head_sha with
                      | Some s -> Some s
                      | None -> str "head_sha" doc
                    in
                    let* checks =
                      match sha with
                      | Some s -> Github.checks gh s
                      | None -> Lwt.return []
                    in
                    let* approvals = Github.approvals gh number in
                    Lwt.return
                      [
                        ("state", `String pr.state);
                        ("checks", `List checks);
                        ("approvals", `List approvals);
                      ]
              in
              let* fields =
                Lwt.catch
                  (fun () ->
                    let* l = live in
                    Lwt.return (l @ [ ("error", `Null) ]))
                  (function
                    | Api.Error (_, _, m) ->
                        Lwt.return
                          [
                            ("state", `String "unknown");
                            ("checks", `List []);
                            ("approvals", `List []);
                            ("error", `String m);
                          ]
                    | e -> Lwt.fail e)
              in
              let j =
                `Assoc
                  (base @ fields @ [ ("required_approvals", `Int gh.required_approvals) ])
              in
              Hashtbl.replace (state ctx).pr_cache key (Ctx.now (), j);
              Lwt.return j))

let suggestion_json ~pr (s : R.Suggest.suggestion) =
  let review =
    match pr with
    | Some doc when List.mem s.id (stored_suggestions doc) ->
        `Assoc
          [
            ("pull_request", Api.opt_int (stored_int "number" doc));
            ("url", Api.opt_string (str "url" doc));
          ]
    | _ -> `Null
  in
  `Assoc
    [
      ("id", `String s.id);
      ("kind", `String (suggestion_kind s.change));
      ("title", `String s.summary);
      ("code", `String s.code);
      ( "evidence",
        `Assoc
          [
            ("records", `Int s.evidence.records);
            ("distinct_queries", `Int s.evidence.queries);
            ("callers", `Int (List.length s.evidence.callers));
            ("denied", `Int s.evidence.denied);
            ("shadow_denied", `Int s.evidence.shadow_denied);
          ] );
      ("yaml", `String s.yaml);
      ("applicable", `Bool s.applicable);
      ("notes", Api.strings s.notes);
      ("review", review);
    ]

let parse_since req =
  match Api.query req "since" with
  | None | Some "" -> neg_infinity
  | Some s -> (
      match R.Live.parse_since ~now:(Ctx.now ()) s with
      | Ok t -> t
      | Error m -> Api.bad_request "since: %s" m)

let report (ctx : Ctx.t) (r : Router.req) =
  let name = Router.param r "name" in
  let since = parse_since r.http in
  let records = records_of ctx ~since name in
  let info = find ctx name in
  if info = None && records = [] then Api.not_found "policy %s is not loaded" name;
  let compare =
    match Api.query r.http "compare" with
    | Some c when c <> "" -> (
        match find ctx c with
        | Some i -> Some i
        | None -> Api.not_found "compare policy %s is not loaded" c)
    | _ -> ( match shadow_siblings ctx name with s :: _ -> Some s | [] -> None)
  in
  let verify = make_verify () in
  let sg = compute_suggest ctx ~verify records in
  let pr = stored_pr ctx name in
  let suggestions =
    List.filter (fun (s : R.Suggest.suggestion) -> s.policy = name) sg.suggestions
  in
  let days_in_shadow =
    match compare with
    | None -> `Null
    | Some c -> (
        let oldest =
          Index.fold ctx.index ~init:None ~f:(fun acc (e : Index.entry) ->
              if e.record.policy = c.name then
                match acc with Some t when t <= e.ts -> acc | _ -> Some e.ts
              else acc)
        in
        match oldest with
        | None -> `Int 0
        | Some t -> `Int (int_of_float ((Ctx.now () -. t) /. 86400.)))
  in
  let comparison =
    match compare with None -> `Null | Some c -> comparison ~verify c.policy records
  in
  let* pull_request = pr_state ctx name in
  Api.json
    (`Assoc
       [
         ("policy", `String name);
         ("version", Api.opt_string (Option.map (fun i -> i.policy.version) info));
         ("compare", Api.opt_string (Option.map (fun c -> c.name) compare));
         ("since", if since = neg_infinity then `Null else `String (Api.iso8601 since));
         ("records", `Int (List.length records));
         ("days_in_shadow", days_in_shadow);
         ("comparison", comparison);
         ("suggestions", `List (List.map (suggestion_json ~pr) suggestions));
         ("never", `List (never_json sg));
         ("missing_detail", `Int sg.missing_detail);
         ("pull_request", pull_request);
       ])

(* ---- pull requests ---- *)

let yaml_list items = Docload.to_string Docload.Yaml (`List items)

let indent n text =
  let pad = String.make n ' ' in
  String.split_on_char '\n' text
  |> List.map (fun l -> if l = "" then l else pad ^ l)
  |> String.concat "\n"

(** Each test is one case or a list of cases in the [haltsql test] suite format. Returns
    the cases as JSON after checking they decode as suite cases. *)
let parse_tests tests =
  let cases =
    List.concat_map
      (fun t ->
        match Docload.of_string ~file:"test" Docload.Yaml t with
        | Ok (`List l) -> l
        | Ok (`Assoc _ as c) -> [ c ]
        | Ok _ -> Api.bad_request "each test must be a test case or a list of test cases"
        | Error e ->
            Api.bad_request "invalid test YAML: %s"
              (String.concat "; " (errs_to_strings e)))
      tests
  in
  let suite =
    `Assoc
      [
        ("apiVersion", `String "haltsql.dev/v1");
        ("kind", `String "TestSuite");
        ("metadata", `Assoc [ ("name", `String "check") ]);
        ("policy", `String "policy.yaml");
        ("cases", `List cases);
      ]
  in
  match Haltsql.Test_suite.of_json ~base_dir:"/" suite with
  | Ok _ -> cases
  | Error e ->
      Api.bad_request "invalid test case: %s" (String.concat "; " (errs_to_strings e))

let count_cases text =
  match Docload.of_string ~file:"suite" Docload.Yaml text with
  | Ok j -> (
      match Api.member "cases" j with Some (`List l) -> Some (List.length l) | _ -> None)
  | Error _ -> None

(* Appends cases to an existing suite as text, so its comments survive, when [cases:] is
   the last top-level key; otherwise re-serializes the suite. *)
let append_cases existing cases =
  let lines = String.split_on_char '\n' existing in
  let top_level l = l <> "" && l.[0] <> ' ' && l.[0] <> '#' && l.[0] <> '-' in
  let rec after_cases = function
    | [] -> None
    | l :: rest when String.trim l = "cases:" && l.[0] = 'c' -> Some rest
    | _ :: rest -> after_cases rest
  in
  let as_text =
    match after_cases lines with
    | Some rest when not (List.exists top_level rest) ->
        let item_indent =
          List.find_map
            (fun l ->
              let t = String.trim l in
              if String.length t > 0 && t.[0] = '-' then (
                let n = ref 0 in
                while !n < String.length l && l.[!n] = ' ' do
                  incr n
                done;
                Some !n)
              else None)
            rest
        in
        let n = Option.value item_indent ~default:2 in
        let base =
          if String.ends_with ~suffix:"\n" existing then existing else existing ^ "\n"
        in
        Some (base ^ indent n (yaml_list cases))
    | _ -> None
  in
  let old = count_cases existing in
  match (as_text, old) with
  | Some t, Some o when count_cases t = Some (o + List.length cases) -> t
  | _ -> (
      match Docload.of_string ~file:"suite" Docload.Yaml existing with
      | Ok (`Assoc kv) ->
          let prev =
            match List.assoc_opt "cases" kv with Some (`List l) -> l | _ -> []
          in
          let kv =
            List.map
              (fun (k, v) -> if k = "cases" then (k, `List (prev @ cases)) else (k, v))
              kv
          in
          let kv =
            if List.mem_assoc "cases" kv then kv else kv @ [ ("cases", `List cases) ]
          in
          Docload.to_string Docload.Yaml (`Assoc kv)
      | _ -> Api.conflict "the existing test suite in the repository cannot be read")

let new_suite ~name ~policy_rel cases =
  "# Created by HaltSQL Console. Run with: haltsql test <this file>\n"
  ^ Docload.to_string Docload.Yaml
      (`Assoc
         [
           ("apiVersion", `String "haltsql.dev/v1");
           ("kind", `String "TestSuite");
           ("metadata", `Assoc [ ("name", `String (name ^ "-console")) ]);
           ("policy", `String policy_rel);
           ("cases", `List cases);
         ])

let join_path dir file = if dir = "" then file else dir ^ "/" ^ file

let pr_body ~name ~(by : Ctx.principal) ~applied ~skipped
    ~(chosen : R.Suggest.suggestion list) ~tests =
  let b = Buffer.create 512 in
  let add fmt = Printf.ksprintf (Buffer.add_string b) fmt in
  add "Policy change for `%s`, proposed from HaltSQL Console by %s.\n\n" name by.id;
  if applied <> [] then begin
    add "### Suggestions applied\n\n";
    List.iter
      (fun (s : R.Suggest.suggestion) ->
        if List.mem s.id applied then
          add "- `%s`: %s (%d records, %d distinct queries)\n" s.id s.summary
            s.evidence.records s.evidence.queries)
      chosen;
    add "\n"
  end;
  if skipped <> [] then begin
    add "### Not applied\n\n";
    List.iter (fun (id, why) -> add "- `%s`: %s\n" id why) skipped;
    add "\n"
  end;
  if tests > 0 then add "%d test case(s) added to the policy's test suite.\n\n" tests;
  add
    "Suggestions never relax tenancy, writes, external-policy denials or sensitive \
     columns. Review the evidence before approving.\n";
  Buffer.contents b

let open_pull_request (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let* body = Router.json_body r in
  let _ = Ctx.require ~body p r.http Rbac.Propose_changes in
  let name = Router.param r "name" in
  let* gh = Github.config ctx in
  let gh =
    match gh with
    | None ->
        Api.not_configured "pull requests need integrations.github in the console config"
    | Some (Error m) -> Api.not_configured "integrations.github is invalid: %s" m
    | Some (Ok c) -> c
  in
  let info =
    match find ctx name with
    | Some i -> i
    | None -> Api.not_found "policy %s is not loaded" name
  in
  let ids = Api.str_list_field "suggestions" body in
  let tests = Api.str_list_field "tests" body in
  let title = Api.str_field "title" body in
  if ids = [] && tests = [] then
    Api.bad_request "nothing to propose: give suggestions and/or tests";
  let verify = make_verify () in
  let sg = compute_suggest ctx ~verify (records_of ctx ~since:neg_infinity name) in
  let chosen =
    List.map
      (fun id ->
        match
          List.find_opt
            (fun (s : R.Suggest.suggestion) -> s.id = id && s.policy = name)
            sg.suggestions
        with
        | Some s -> s
        | None -> Api.bad_request "no such suggestion for policy %s: %s" name id)
      ids
  in
  let cases = parse_tests tests in
  (* An open PR for this policy is updated; otherwise a fresh branch from base. *)
  let stored = stored_pr ctx name in
  let* existing =
    match stored with
    | None -> Lwt.return None
    | Some doc -> (
        match (stored_int "number" doc, str "branch" doc) with
        | Some n, Some branch -> (
            let* pr = Github.get_pr gh n in
            match pr with
            | Some pr when pr.state = "open" -> Lwt.return (Some (n, branch))
            | _ -> Lwt.return None)
        | _ -> Lwt.return None)
  in
  let* base_sha =
    let* s = Github.get_ref gh gh.base in
    match s with
    | Some s -> Lwt.return s
    | None -> Api.upstream "base branch %s does not exist in %s" gh.base gh.repo
  in
  let branch = match existing with Some (_, b) -> b | None -> gh.branch_prefix ^ name in
  let* head =
    let* cur = Github.get_ref gh branch in
    match (existing, cur) with
    | Some _, Some sha -> Lwt.return sha
    | _, None ->
        let* () = Github.create_ref gh branch base_sha in
        Lwt.return base_sha
    | None, Some _ ->
        (* a stale branch from a closed PR: start again from base *)
        let* () = Github.update_ref ~force:true gh branch base_sha in
        Lwt.return base_sha
  in
  let file_name =
    match info.file with Some f -> Filename.basename f | None -> name ^ ".yaml"
  in
  let repo_file = join_path gh.path file_name in
  let* policy_change =
    if chosen = [] then Lwt.return ([], [], [])
    else
      let* current = Github.get_file gh ~ref_:head repo_file in
      let text, format =
        match current with
        | Some t -> (t, format_of repo_file)
        | None -> (info.source, info.format)
      in
      let doc =
        match Docload.of_string ~file:file_name format text with
        | Ok d -> d
        | Error e ->
            Api.conflict "%s in the repository cannot be parsed: %s" repo_file
              (String.concat "; " (List.map sanitize (errs_to_strings e)))
      in
      let doc', o = R.Patch.apply info.policy doc chosen in
      if o.applied = [] then
        Api.conflict "none of the suggestions could be applied: %s"
          (String.concat "; " (List.map (fun (id, why) -> id ^ ": " ^ why) o.skipped));
      let base_dir =
        match info.file with Some f -> Filename.dirname f | None -> Sys.getcwd ()
      in
      (match R.Patch.validate ~file:file_name ~base_dir doc' with
      | Ok _ -> ()
      | Error e ->
          Api.conflict "the patched policy does not validate: %s"
            (String.concat "; " (List.map sanitize (errs_to_strings e))));
      Lwt.return
        ( [ (repo_file, R.Patch.render format ~applied:o.applied doc') ],
          o.applied,
          o.skipped )
  in
  let files, applied, skipped = policy_change in
  let* test_files =
    if cases = [] then Lwt.return []
    else
      let tests_file = join_path gh.tests_path (name ^ ".yaml") in
      let* existing_suite = Github.get_file gh ~ref_:head tests_file in
      let text =
        match existing_suite with
        | Some t -> append_cases t cases
        | None ->
            let policy_rel =
              R.Patch.relative_path
                ~from_dir:(join_path "/repo" gh.tests_path)
                (join_path "/repo" repo_file)
            in
            new_suite ~name ~policy_rel cases
      in
      Lwt.return [ (tests_file, text) ]
  in
  let title =
    match title with
    | Some t when String.trim t <> "" -> t
    | _ ->
        Printf.sprintf "haltsql: update policy %s (%d suggestion(s), %d test(s))" name
          (List.length applied) (List.length cases)
  in
  let* commit =
    Github.commit_files gh ~branch ~parent:head ~message:title (files @ test_files)
  in
  let body_text =
    pr_body ~name ~by:p ~applied ~skipped ~chosen ~tests:(List.length cases)
  in
  let* pr, created =
    match existing with
    | Some (n, _) ->
        let* pr = Github.update_pr gh n ~title ~body:body_text in
        Lwt.return (pr, false)
    | None ->
        let* pr = Github.create_pr gh ~title ~head:branch ~base:gh.base ~body:body_text in
        Lwt.return (pr, true)
  in
  let prev_suggestions =
    match stored with Some d when not created -> stored_suggestions d | _ -> []
  in
  let all_suggestions =
    prev_suggestions @ List.filter (fun id -> not (List.mem id prev_suggestions)) applied
  in
  let doc =
    `Assoc
      [
        ("policy", `String name);
        ("number", `Int pr.number);
        ("url", `String pr.url);
        ("branch", `String branch);
        ("head_sha", `String commit);
        ("suggestions", Api.strings all_suggestions);
        ("updated", `String (Api.iso8601 (Ctx.now ())));
        ("updated_by", `String p.id);
      ]
  in
  let* () = Store.put ctx.store pr_collection name doc in
  Hashtbl.remove (state ctx).pr_cache (Printf.sprintf "%s|%s|%d" gh.api gh.repo pr.number);
  let* () =
    Activity.log ctx p ~action:"policy.pull_request" ~target:name
      ~detail:
        (`Assoc
           [
             ("number", `Int pr.number);
             ("url", `String pr.url);
             ("created", `Bool created);
             ("suggestions", Api.strings applied);
             ("tests", `Int (List.length cases));
           ])
      ()
  in
  Api.json
    ~status:(if created then `Created else `OK)
    (`Assoc
       [
         ("number", `Int pr.number);
         ("url", `String pr.url);
         ("branch", `String branch);
         ("head_sha", `String commit);
         ("state", `String "open");
         ("created", `Bool created);
         ("applied", Api.strings applied);
         ( "skipped",
           `List
             (List.map
                (fun (id, why) -> `Assoc [ ("id", `String id); ("reason", `String why) ])
                skipped) );
         ("files", Api.strings (List.map fst (files @ test_files)));
       ])

(* ---- routes ---- *)

let list_json ctx =
  let st = state ctx in
  `Assoc
    [
      ("policies", `List (List.map (summary_json ctx) st.infos @ fleet_only ctx));
      ("loaded", Api.opt_time st.loaded_at);
      ("errors", Api.strings st.errors);
      ("notes", Api.strings st.notes);
    ]

let routes : Router.route list =
  [
    Router.get "/api/v1/policies" (fun ctx _p _r -> Api.json (list_json ctx));
    Router.get "/api/v1/policies/:name" (fun ctx _p r ->
        let name = Router.param r "name" in
        match find ctx name with
        | Some i -> Api.json (detail_json ctx i)
        | None -> (
            match
              List.find_opt
                (fun j -> Api.member "name" j = Some (`String name))
                (fleet_only ctx)
            with
            | Some j -> Api.json j
            | None -> Api.not_found "policy %s is not loaded" name));
    Router.get "/api/v1/policies/:name/report" (fun ctx _p r -> report ctx r);
    Router.post "/api/v1/policies/:name/pull-request" open_pull_request;
  ]
