(* haltsql report: shadow-mode analytics and policy suggestions from audit logs.

   [cmd] is the [report] command (register it in main.ml). Exit codes: 0 ok, 1 when the
   patched policy (--apply-to) fails validation, 2 on usage or load errors. *)

open Cmdliner
open Haltsql
module R = Haltsql_report
module Ct = Haltsql_catalog_tools

let exits =
  [
    Cmd.Exit.info 0 ~doc:"on success.";
    Cmd.Exit.info 1 ~doc:"when the patched policy ($(b,--apply-to)) fails validation.";
    Cmd.Exit.info 2 ~doc:"on usage errors or when an input file cannot be loaded.";
  ]

let man_examples ex =
  `S Manpage.s_examples
  :: List.concat_map (fun e -> [ `Pre (Manpage.escape e); `Noblank ]) ex

exception Failed of string

(* ---- inputs ---- *)

let max_line_bytes = 1 lsl 20
let audit_extensions = [ ".jsonl"; ".ndjson"; ".json"; ".log" ]

let rec expand_input path =
  if path = "-" then [ path ]
  else if not (Sys.file_exists path) then Common.usage "input not found: %s" path
  else if Sys.is_directory path then
    Sys.readdir path |> Array.to_list |> List.sort compare
    |> List.filter (fun n -> n <> "" && n.[0] <> '.')
    |> List.concat_map (fun n ->
        let p = Filename.concat path n in
        if Sys.is_directory p then expand_input p
        else if List.exists (fun e -> Filename.check_suffix n e) audit_extensions then
          [ p ]
        else [])
  else [ path ]

type input = {
  name : string;
  records : R.Record.t list;
  skipped : int;
  chain : string;  (** status of the hash chain *)
}

let chain_status lines =
  let chained =
    List.exists
      (fun l -> String.trim l <> "" && Haltsql_cloud.Audit_chain.hash_of_line l <> None)
      lines
  in
  if not chained then "not hash-chained"
  else
    match Haltsql_cloud.Audit_chain.verify_lines ~initial_prev:None lines with
    | Ok n -> Printf.sprintf "hash chain ok (%d records)" n
    | Error (line, problem) ->
        Printf.sprintf "HASH CHAIN BROKEN at line %d: %s" line problem

let read_input name =
  let read ic =
    let rec go acc =
      match In_channel.input_line ic with None -> List.rev acc | Some l -> go (l :: acc)
    in
    go []
  in
  let lines =
    if name = "-" then read stdin
    else
      try In_channel.with_open_bin name read
      with Sys_error e -> Common.usage "cannot read %s" e
  in
  let records, skipped =
    List.fold_left
      (fun (rs, sk) l ->
        if String.trim l = "" then (rs, sk)
        else if String.length l > max_line_bytes then (rs, sk + 1)
        else
          match R.Record.of_line l with
          | Ok r -> (r :: rs, sk)
          | Error _ ->
              (* Proxy execution records carry no verdict: not a skipped line. *)
              let execution =
                match Yojson.Safe.from_string l with
                | j -> R.Record.is_execution j
                | exception Yojson.Json_error _ -> false
              in
              (rs, if execution then sk else sk + 1))
      ([], 0) lines
  in
  {
    name = (if name = "-" then "(stdin)" else name);
    records = List.rev records;
    skipped;
    chain = chain_status lines;
  }

(* ---- PII ---- *)

let pii_lookup ~manifests ~source ~heuristics : R.Pii.lookup =
  let manifest =
    List.map
      (fun f ->
        if not (Sys.file_exists f) then Common.usage "PII file not found: %s" f;
        match source with
        | None -> (
            match Ct.Pii.of_file f with
            | Ok m -> m
            | Error e ->
                Common.usage
                  "cannot load PII manifest %s: %s (for a raw catalog export, pass \
                   --pii-source)"
                  f e)
        | Some src -> (
            match Ct.Pii_import.import_file src f with
            | Ok r -> r.manifest
            | Error e -> Common.usage "cannot import %s: %s" f e))
      manifests
    |> Ct.Pii.merge
  in
  let from_manifest ~schema ~table ~column =
    match Ct.Pii.find manifest ~schema ~table ~column with
    | Some (e : Ct.Pii.entry) ->
        Some
          (Printf.sprintf "%s in the PII manifest%s"
             (String.concat ", " e.classifications)
             (match e.sources with [] -> "" | s -> " (" ^ String.concat ", " s ^ ")"))
    | None -> None
  in
  let heuristic ~schema:_ ~table:_ ~column =
    match Ct.Pii.Matcher.find_match Ct.Pii.Matcher.default_terms column with
    | Some term -> Some (Printf.sprintf "column name matches %S" term)
    | None -> None
  in
  R.Pii.union ([ from_manifest ] @ if heuristics then [ heuristic ] else [])

(* ---- policies ---- *)

let load_policy_file f =
  if not (Sys.file_exists f) then Common.usage "policy file not found: %s" f;
  match Policy_load.of_file f with
  | Ok p -> p
  | Error errs ->
      Common.usage "cannot load policy:\n%s" (Common.errors_to_string ~file:f errs)

let absolute p = if Filename.is_relative p then Filename.concat (Sys.getcwd ()) p else p

let write_atomic path contents =
  let dir = Filename.dirname path in
  (try Common.mkdir_p dir
   with Unix.Unix_error (e, _, _) ->
     Common.usage "cannot create %s: %s" dir (Unix.error_message e));
  let tmp =
    Filename.concat dir
      (Printf.sprintf ".%s.tmp%d" (Filename.basename path) (Unix.getpid ()))
  in
  try
    Common.write_file tmp contents;
    Sys.rename tmp path
  with Sys_error e ->
    (try Sys.remove tmp with Sys_error _ -> ());
    Common.usage "cannot write %s" e

let tenancy_codes =
  [ "E_TENANT_MISSING"; "E_TENANT_MISMATCH"; "E_TENANT_WRITE"; "E_CONTEXT_MISSING" ]

(* ---- the command ---- *)

let report ~inputs ~since ~until ~policy_filter ~format ~suggest ~policy_files ~apply_to
    ~output ~accept ~pii ~pii_source ~no_heuristics ~min_count ~top ~bucket ~rows =
  Common.run (fun () ->
      try
        if inputs = [] then Common.usage "no input: give audit files, directories or -";
        if output <> None && apply_to = None then
          Common.usage "-o/--output needs --apply-to";
        if apply_to <> None && output = None then
          Common.usage
            "--apply-to needs -o/--output (the patched policy is not written in place)";
        if accept <> [] && apply_to = None then Common.usage "--accept needs --apply-to";
        if min_count < 1 then Common.usage "--min-count must be at least 1";
        if top < 1 || top > 1000 then Common.usage "--top must be between 1 and 1000";
        if List.length (List.filter (( = ) "-") inputs) > 1 then
          Common.usage "stdin (-) can be given only once";
        let now = Unix.gettimeofday () in
        let bound what = function
          | None -> None
          | Some s -> (
              match R.Rtime.parse_bound ~now s with
              | Ok t -> Some t
              | Error e -> Common.usage "%s: %s" what e)
        in
        let since = bound "--since" since and until = bound "--until" until in
        let bucket_seconds =
          match bucket with
          | None -> None
          | Some b -> (
              match R.Rtime.parse_duration b with
              | Ok s -> Some s
              | Error e -> Common.usage "--bucket: %s" e)
        in
        let source =
          match pii_source with
          | None -> None
          | Some s -> (
              match Ct.Pii_import.source_of_string s with
              | Some src -> Some src
              | None ->
                  Common.usage "unknown --pii-source %S (expected one of: %s)" s
                    (String.concat ", "
                       (List.map Ct.Pii_import.source_to_string Ct.Pii_import.all_sources))
              )
        in
        let pii = pii_lookup ~manifests:pii ~source ~heuristics:(not no_heuristics) in
        (* policies: --policy-file and --apply-to *)
        let policy_files =
          List.fold_left
            (fun acc f ->
              if List.mem (absolute f) (List.map absolute acc) then acc else acc @ [ f ])
            []
            (policy_files @ Option.to_list apply_to)
        in
        let policies =
          List.fold_left
            (fun acc f ->
              let p = load_policy_file f in
              if List.mem_assoc p.Policy.name acc then
                Common.usage "two policy files define policy %S" p.name
              else acc @ [ (p.name, p) ])
            [] policy_files
        in
        let files = List.concat_map expand_input inputs in
        if files = [] then
          Common.usage "no audit files (*.jsonl, *.json, *.log) in the inputs";
        let read = List.map read_input files in
        let in_window (r : R.Record.t) =
          (match since with
            | None -> true
            | Some s -> ( match r.ts with Some t -> t >= s | None -> false))
          && (match until with
            | None -> true
            | Some u -> ( match r.ts with Some t -> t < u | None -> false))
          && match policy_filter with Some p -> String.equal r.policy p | None -> true
        in
        let records = List.concat_map (fun i -> List.filter in_window i.records) read in
        (* Re-derive the detailed reasons of denied records that carry their SQL. *)
        let rederived = ref 0 and other_version = ref 0 in
        let enrich_cache = Hashtbl.create 64 in
        let cached_verify (p : Policy.t) ctx sql =
          let k = (p.name, sql) in
          match Hashtbl.find_opt enrich_cache k with
          | Some v -> v
          | None ->
              let v = Haltsql.verify p ctx sql in
              Hashtbl.replace enrich_cache k v;
              v
        in
        let records =
          List.map
            (fun (r : R.Record.t) ->
              let r' = R.Live.enrich ~policies ~verify:cached_verify r in
              if r'.details <> [] && r.details = [] then begin
                incr rederived;
                match (r.policy_version, List.assoc_opt r.policy policies) with
                | Some v, Some p when v <> p.Policy.version -> incr other_version
                | _ -> ()
              end;
              r')
            records
        in
        let summary = R.Summary.compute ?bucket_seconds ~top records in
        let suggest = suggest || apply_to <> None in
        let sg =
          if suggest then
            Some
              (R.Suggest.compute
                 {
                   R.Suggest.default_config with
                   policies;
                   pii;
                   verify = Some Haltsql.verify;
                   min_records = min_count;
                 }
                 records)
          else None
        in
        let notes = ref [] in
        let note fmt = Printf.ksprintf (fun s -> notes := !notes @ [ s ]) fmt in
        if !rederived > 0 then
          note "Detailed reasons re-derived from the raw SQL of %d record(s)%s."
            !rederived
            (if !other_version > 0 then
               Printf.sprintf
                 " (%d of them were logged under a different policy version than the \
                  loaded file)"
                 !other_version
             else "");
        let exit_code = ref 0 in
        (match (apply_to, output, sg) with
        | Some file, Some out, Some g -> (
            let p = load_policy_file file in
            let doc =
              match Docload.of_file file with
              | Ok d -> d
              | Error errs ->
                  Common.usage "cannot read %s:\n%s" file
                    (Common.errors_to_string ~file errs)
            in
            let unknown =
              List.filter
                (fun id ->
                  not
                    (List.exists
                       (fun (s : R.Suggest.suggestion) -> s.id = id)
                       g.suggestions))
                accept
            in
            if unknown <> [] then
              Common.usage "--accept: no such suggestion: %s" (String.concat ", " unknown);
            let chosen =
              List.filter
                (fun (s : R.Suggest.suggestion) ->
                  String.equal s.policy p.name && (accept = [] || List.mem s.id accept))
                g.suggestions
            in
            let doc', o = R.Patch.apply p doc chosen in
            let in_dir = Filename.dirname (absolute file) in
            let out_dir = Filename.dirname (absolute out) in
            let doc' = R.Patch.rebase_catalog ~from_dir:in_dir ~to_dir:out_dir doc' in
            let fmt =
              match Docload.format_of_path out with
              | Some f -> f
              | None -> (
                  match Docload.format_of_path file with
                  | Some f -> f
                  | None -> Docload.Yaml)
            in
            match R.Patch.validate ~file:out ~base_dir:out_dir doc' with
            | Error errs ->
                raise
                  (Failed
                     ("the patched policy does not validate; nothing written:\n"
                     ^ Common.errors_to_string ~file:out errs))
            | Ok patched ->
                write_atomic out (R.Patch.render fmt ~applied:o.applied doc');
                note "Wrote %s (policy %s, version %s): applied %d suggestion(s)%s." out
                  patched.name patched.version (List.length o.applied)
                  (match o.applied with [] -> "" | l -> ": " ^ String.concat ", " l);
                List.iter (fun (id, why) -> note "Not applied: %s: %s." id why) o.skipped;
                (match fmt with
                | Docload.Yaml -> note "YAML comments of %s are not carried over." file
                | Docload.Json -> ());
                (* What-if: re-verify the denied records with SQL under the patched policy. *)
                let mine =
                  List.filter
                    (fun (r : R.Record.t) ->
                      String.equal r.policy p.name && r.sql <> None
                      &&
                      match r.outcome with
                      | Allowed -> false
                      | Denied | Shadow_denied -> true)
                    records
                in
                let resolved = ref 0 and tenancy = ref 0 and tenancy_kept = ref 0 in
                let whatif_cache = Hashtbl.create 64 in
                let pctx = R.Suggest.probe_context patched in
                List.iter
                  (fun (r : R.Record.t) ->
                    let sql = Option.get r.sql in
                    let v =
                      match Hashtbl.find_opt whatif_cache sql with
                      | Some v -> v
                      | None ->
                          let v = Haltsql.verify patched pctx sql in
                          Hashtbl.replace whatif_cache sql v;
                          v
                    in
                    let still =
                      List.filter
                        (fun (x : Reason.t) ->
                          List.mem (Reason.code_to_string x.code) r.codes)
                        (v.reasons @ v.shadow_reasons)
                    in
                    if still = [] then incr resolved;
                    if List.exists (fun c -> List.mem c tenancy_codes) r.codes then begin
                      incr tenancy;
                      if
                        List.exists
                          (fun (x : Reason.t) ->
                            List.mem (Reason.code_to_string x.code) tenancy_codes)
                          (v.reasons @ v.shadow_reasons)
                      then incr tenancy_kept
                    end)
                  mine;
                if mine <> [] then
                  note
                    "Under the patched policy, %d of %d denied record(s) with raw SQL no \
                     longer hit any of their recorded codes; %d of %d tenancy denial(s) \
                     are still denied."
                    !resolved (List.length mine) !tenancy_kept !tenancy;
                if !tenancy_kept <> !tenancy then exit_code := Common.exit_denied)
        | _ -> ());
        let r =
          {
            R.Render.generated_at = now;
            since;
            until;
            policy_filter;
            inputs =
              List.map
                (fun i ->
                  ( i.name,
                    Printf.sprintf "%d record(s), %d skipped line(s), %s"
                      (List.length i.records) i.skipped i.chain ))
                read;
            skipped_lines = List.fold_left (fun n i -> n + i.skipped) 0 read;
            summary;
            suggest = sg;
            notes = !notes;
          }
        in
        (match format with
        | `Json -> print_endline (Yojson.Safe.pretty_to_string (R.Render.to_json r))
        | `Text -> print_string (R.Render.to_text ~rows r)
        | `Markdown -> print_string (R.Render.to_markdown ~rows r));
        !exit_code
      with Failed msg ->
        prerr_endline ("haltsql: " ^ msg);
        Common.exit_denied)

let cmd =
  let inputs =
    Arg.(
      value & pos_all string []
      & info [] ~docv:"INPUT"
          ~doc:
            "Audit files or directories (searched recursively for *.jsonl, *.ndjson, \
             *.json and *.log), or $(b,-) for stdin.")
  in
  let opt_s names docv doc =
    Arg.(value & opt (some string) None & info names ~docv ~doc)
  in
  let since =
    opt_s [ "since" ] "TIME"
      "Only records at or after TIME: RFC 3339, YYYY-MM-DD, or a duration before now \
       (24h, 7d)."
  in
  let until =
    opt_s [ "until" ] "TIME" "Only records before TIME (same forms as $(b,--since))."
  in
  let policy_filter = opt_s [ "policy" ] "NAME" "Only records of policy NAME." in
  let format =
    Arg.(
      value
      & opt (enum [ ("text", `Text); ("json", `Json); ("markdown", `Markdown) ]) `Text
      & info [ "format" ] ~docv:"FORMAT" ~doc:"$(b,text), $(b,json) or $(b,markdown).")
  in
  let suggest =
    Arg.(value & flag & info [ "suggest" ] ~doc:"Add policy suggestions to the report.")
  in
  let policy_files =
    Arg.(
      value & opt_all string []
      & info [ "policy-file" ] ~docv:"FILE"
          ~doc:
            "A policy the records were verified against (repeatable). Needed to name the \
             denied objects from raw SQL and to write exact snippets.")
  in
  let apply_to =
    opt_s [ "apply-to" ] "FILE"
      "Apply the accepted suggestions for this policy file and write the result to \
       $(b,-o). Implies $(b,--suggest). The output is validated before it is written."
  in
  let output =
    opt_s [ "o"; "output" ] "OUT" "Where $(b,--apply-to) writes the patched policy."
  in
  let accept =
    Arg.(
      value & opt_all string []
      & info [ "accept" ] ~docv:"ID"
          ~doc:
            "Only apply this suggestion (repeatable). Default: every applicable \
             suggestion for the policy.")
  in
  let pii =
    Arg.(
      value & opt_all string []
      & info [ "pii" ] ~docv:"FILE"
          ~doc:
            "PII manifest (from $(b,haltsql schema import)); repeatable. Columns it \
             lists are flagged instead of suggested.")
  in
  let pii_source =
    opt_s [ "pii-source" ] "SOURCE"
      "Read the $(b,--pii) files as raw exports of SOURCE (dbt, datahub, unity, atlan, \
       collibra) instead of manifests."
  in
  let no_heuristics =
    Arg.(
      value & flag
      & info [ "no-pii-heuristics" ]
          ~doc:
            "Do not also flag columns whose names look sensitive (email, phone, ssn, \
             ...).")
  in
  let min_count =
    Arg.(
      value & opt int 1
      & info [ "min-count" ] ~docv:"N"
          ~doc:"Only suggest changes seen in at least N records.")
  in
  let top =
    Arg.(value & opt int 20 & info [ "top" ] ~docv:"N" ~doc:"Top denied queries to list.")
  in
  let rows =
    Arg.(
      value & opt int 15
      & info [ "rows" ] ~docv:"N" ~doc:"Rows per breakdown table (text and markdown).")
  in
  let bucket =
    opt_s [ "bucket" ] "DURATION"
      "Time bucket width (e.g. 5m, 1h, 1d). Default: from the span."
  in
  let doc = "Shadow-mode analytics and policy suggestions from audit logs." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Reads the audit records written by haltsql-server (file, stdout, S3/GCS \
         objects) and haltsql-proxy, and prints totals, allowed / denied / shadow-denied \
         counts, breakdowns by reason code, table, column, caller and policy, counts \
         over time, and the most denied queries.";
      `P
        "With $(b,--suggest), it proposes conservative policy changes with evidence \
         counts and the exact YAML to add: columns, functions and tables to allow, and \
         LIMIT raises. Tenancy, writes and codes that need a query fix are never \
         suggested; sensitive columns are flagged instead.";
    ]
    @ man_examples
        [
          "  haltsql report /var/log/haltsql/audit.jsonl --since 7d";
          "  haltsql report audit/ --suggest --policy-file policy.yaml --pii pii.json";
          "  haltsql report audit.jsonl --apply-to policy.yaml -o policy.next.yaml";
          "  haltsql report - --format markdown < audit.jsonl > report.md";
        ]
  in
  let f inputs since until policy_filter format suggest policy_files apply_to output
      accept pii pii_source no_heuristics min_count top bucket rows =
    report ~inputs ~since ~until ~policy_filter ~format ~suggest ~policy_files ~apply_to
      ~output ~accept ~pii ~pii_source ~no_heuristics ~min_count ~top ~bucket ~rows
  in
  Cmd.v
    (Cmd.info "report" ~doc ~man ~exits)
    Term.(
      const f $ inputs $ since $ until $ policy_filter $ format $ suggest $ policy_files
      $ apply_to $ output $ accept $ pii $ pii_source $ no_heuristics $ min_count $ top
      $ bucket $ rows)
