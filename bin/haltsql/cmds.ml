(* Implementations of the haltsql subcommands. Each returns an exit code. *)

open Haltsql
open Common

let pr = Printf.printf

(* ---------------------------------------------------------------- verify *)

let verify ~policy ~context ~context_file ~sql ~file ~json ~batch ~jobs =
  run (fun () ->
      let p = load_policy policy in
      let ctx = load_context ~context ~context_file in
      if batch then begin
        if sql <> None || file <> None then
          usage "--batch reads JSONL from stdin; do not pass --sql or --file";
        if jobs < 1 then usage "--jobs must be >= 1";
        Batch.run ~jobs p ctx
      end
      else begin
        let sql = read_sql ~sql ~file in
        let v = Haltsql.verify p ctx sql in
        if json then print_json (Verdict.to_json v) else Render.verdict v;
        if v.allowed then exit_allowed else exit_denied
      end)

(* --------------------------------------------------------------- explain *)

let explain ~policy ~context ~context_file ~sql ~file ~json =
  run (fun () ->
      let p = load_policy policy in
      let ctx = load_context ~context ~context_file in
      let sql = read_sql ~sql ~file in
      let v = Haltsql.verify p ctx sql in
      if json then print_json (Verdict.to_json v) else Render.explain p v sql;
      if v.allowed then exit_allowed else exit_denied)

(* -------------------------------------------------------------- validate *)

type validated = {
  file : string;
  kind : string option;
  detail : string option;
  errors : Load_error.t list;
}

let schema_keys (schema : Yojson.Safe.t) =
  let props =
    match schema with
    | `Assoc kv -> (
        match List.assoc_opt "properties" kv with
        | Some (`Assoc p) -> List.map fst p
        | _ -> [])
    | _ -> []
  in
  let required =
    match schema with
    | `Assoc kv -> (
        match List.assoc_opt "required" kv with
        | Some (`List l) -> List.filter_map (function `String s -> Some s | _ -> None) l
        | _ -> [])
    | _ -> []
  in
  (props, required)

(* Minimal structural check of a Scenario document: top-level keys only. *)
let validate_scenario file (doc : Yojson.Safe.t) =
  let props, required = schema_keys Schemas.scenario in
  match doc with
  | `Assoc kv ->
      let unknown =
        if props = [] then []
        else
          List.filter_map
            (fun (k, _) ->
              if List.mem k props then None
              else Some (Load_error.make ~file ~path:k "unknown key"))
            kv
      in
      let missing =
        List.filter_map
          (fun k ->
            if List.mem_assoc k kv then None
            else Some (Load_error.make ~file ~path:k "required key is missing"))
          required
      in
      unknown @ missing
  | _ -> [ Load_error.make ~file "document must be a mapping" ]

let validate_one file : validated =
  let mk ?kind ?detail errors = { file; kind; detail; errors } in
  if not (Sys.file_exists file) then mk [ Load_error.make ~file "file not found" ]
  else
    match Docload.of_file file with
    | Error errs -> mk errs
    | Ok doc -> (
        let kind =
          match doc with
          | `Assoc kv -> (
              match List.assoc_opt "kind" kv with
              | Some (`String k) -> Some k
              | Some _ -> Some "<invalid>"
              | None -> if List.mem_assoc "tables" kv then Some "Catalog" else None)
          | _ -> None
        in
        let res ok_detail = function
          | Ok x -> mk ?kind ~detail:(ok_detail x) []
          | Error errs -> mk ?kind errs
        in
        match kind with
        | Some "Policy" ->
            res
              (fun (p : Policy.t) -> Printf.sprintf "%s %s" p.name p.version)
              (Policy_load.of_file file)
        | Some "Config" ->
            res
              (fun (c : Config.t) ->
                Printf.sprintf "%d policies" (List.length c.policies))
              (Config.of_file file)
        | Some "TestSuite" ->
            res
              (fun (t : Test_suite.t) ->
                Printf.sprintf "%s, %d cases" t.suite_name (List.length t.cases))
              (Test_suite.of_file file)
        | Some "Catalog" ->
            res
              (fun (c : Catalog.t) -> Printf.sprintf "%d tables" (List.length c.tables))
              (Catalog_load.of_file file)
        | Some "Scenario" -> mk ?kind (validate_scenario file doc)
        | Some k ->
            mk ?kind
              [
                Load_error.make ~file ~path:"kind"
                  (Printf.sprintf
                     "unknown kind %S (expected Policy, Config, TestSuite, Catalog or \
                      Scenario)"
                     k);
              ]
        | None ->
            mk
              [
                Load_error.make ~file ~path:"kind"
                  "missing \"kind\" (Policy, Config, TestSuite, Catalog or Scenario)";
              ])

let validate ~files ~json =
  run (fun () ->
      if files = [] then usage "validate: at least one FILE is required";
      let results = List.map validate_one files in
      let ok = List.for_all (fun r -> r.errors = []) results in
      if json then
        print_json
          (`Assoc
             [
               ("ok", `Bool ok);
               ( "files",
                 `List
                   (List.map
                      (fun r ->
                        `Assoc
                          [
                            ("file", `String r.file);
                            ( "kind",
                              match r.kind with Some k -> `String k | None -> `Null );
                            ("ok", `Bool (r.errors = []));
                            ("errors", `List (List.map Load_error.to_json r.errors));
                          ])
                      results) );
             ])
      else
        List.iter
          (fun r ->
            if r.errors = [] then
              pr "%s: ok (%s%s)\n" r.file
                (Option.value r.kind ~default:"?")
                (match r.detail with Some d -> ": " ^ d | None -> "")
            else begin
              pr "%s: %d error(s)\n" r.file (List.length r.errors);
              List.iter
                (fun e -> pr "  %s\n" (errors_to_string ~file:r.file [ e ]))
                r.errors
            end)
          results;
      if ok then 0 else 1)

(* --------------------------------------------------------------- convert *)

let convert ~file ~to_ ~out =
  run (fun () ->
      if not (Sys.file_exists file) then usage "file not found: %s" file;
      let doc =
        match Docload.of_file file with
        | Ok d -> d
        | Error errs -> usage "cannot read %s:\n%s" file (errors_to_string ~file errs)
      in
      (* Typed documents are validated first: an invalid one is not converted. *)
      (match doc with
      | `Assoc kv when List.mem_assoc "kind" kv ->
          let r = validate_one file in
          if r.errors <> [] then
            usage "%s is not a valid document; not converting:\n%s" file
              (errors_to_string ~file r.errors)
      | _ -> ());
      let fmt = match to_ with `Json -> Docload.Json | `Yaml -> Docload.Yaml in
      let s = Docload.to_string fmt doc in
      let s = if s <> "" && s.[String.length s - 1] <> '\n' then s ^ "\n" else s in
      (match out with
      | None -> print_string s
      | Some o -> ( try write_file o s with Sys_error e -> usage "cannot write %s" e));
      0)

(* ---------------------------------------------------------------- schema *)

let schema_export ~out =
  run (fun () ->
      (try mkdir_p out
       with Unix.Unix_error (e, _, _) ->
         usage "cannot create %s: %s" out (Unix.error_message e));
      List.iter
        (fun (name, schema) ->
          let path = Filename.concat out name in
          (try write_file path (Yojson.Safe.pretty_to_string schema ^ "\n")
           with Sys_error e -> usage "cannot write %s" e);
          pr "wrote %s\n" path)
        Schemas.all;
      0)

(* ------------------------------------------------------------------ test *)

let is_suite_file f =
  List.exists (Filename.check_suffix f) [ ".suite.yaml"; ".suite.yml"; ".suite.json" ]

let rec collect_suites path =
  if Sys.is_directory path then
    Sys.readdir path |> Array.to_list |> List.sort compare
    |> List.concat_map (fun e ->
        let p = Filename.concat path e in
        if Sys.is_directory p then collect_suites p
        else if is_suite_file p then [ p ]
        else [])
  else [ path ]

let test ~paths ~json ~filter ~verbose =
  run (fun () ->
      if paths = [] then usage "test: at least one SUITE_FILE or directory is required";
      List.iter (fun p -> if not (Sys.file_exists p) then usage "not found: %s" p) paths;
      let files = List.concat_map collect_suites paths in
      if files = [] then usage "no *.suite.yaml / *.suite.json files found";
      let keep (cr : Suite_runner.case_result) =
        match filter with None -> true | Some t -> List.mem t cr.case.tags
      in
      let total_pass = ref 0 and total_fail = ref 0 and load_errors = ref 0 in
      let suite_json = ref [] in
      List.iter
        (fun file ->
          match Suite_runner.run_file ~verify:Haltsql.verify file with
          | Error errs ->
              incr load_errors;
              if json then
                suite_json :=
                  `Assoc
                    [
                      ("file", `String file);
                      ("errors", `List (List.map Load_error.to_json errs));
                    ]
                  :: !suite_json
              else
                pr "ERROR %s\n%s\n" file
                  (String.concat "\n"
                     (List.map (fun e -> "  " ^ errors_to_string ~file [ e ]) errs))
          | Ok r ->
              let results = List.filter keep r.results in
              let passed =
                List.length
                  (List.filter (fun (c : Suite_runner.case_result) -> c.passed) results)
              in
              let failed = List.length results - passed in
              total_pass := !total_pass + passed;
              total_fail := !total_fail + failed;
              if json then
                suite_json :=
                  `Assoc
                    [
                      ("file", `String file);
                      ("name", `String r.suite.suite_name);
                      ("passed", `Int passed);
                      ("failed", `Int failed);
                      ( "cases",
                        `List
                          (List.map
                             (fun (c : Suite_runner.case_result) ->
                               `Assoc
                                 [
                                   ("name", `String c.case.case_name);
                                   ("passed", `Bool c.passed);
                                   ( "failure",
                                     match c.failure with
                                     | Some f -> `String f
                                     | None -> `Null );
                                   ( "tags",
                                     `List (List.map (fun t -> `String t) c.case.tags) );
                                   ("verdict", Verdict.to_json c.verdict);
                                 ])
                             results) );
                    ]
                  :: !suite_json
              else begin
                pr "suite %s (%s)\n" r.suite.suite_name file;
                List.iter
                  (fun (c : Suite_runner.case_result) ->
                    if c.passed then begin
                      pr "  PASS  %s\n" c.case.case_name;
                      if verbose then
                        List.iter
                          (Render.print_reason ~indent:"          ")
                          c.verdict.reasons
                    end
                    else
                      pr "  FAIL  %s\n        %s\n        sql: %s\n" c.case.case_name
                        (Option.value c.failure ~default:"failed")
                        (String.concat " " (String.split_on_char '\n' c.case.sql)))
                  results
              end)
        files;
      let ok = !total_fail = 0 && !load_errors = 0 in
      if json then
        print_json
          (`Assoc
             [
               ("ok", `Bool ok);
               ("passed", `Int !total_pass);
               ("failed", `Int !total_fail);
               ("load_errors", `Int !load_errors);
               ("suites", `List (List.rev !suite_json));
             ])
      else
        pr "\n%d suite(s), %d case(s): %d passed, %d failed%s\n" (List.length files)
          (!total_pass + !total_fail) !total_pass !total_fail
          (if !load_errors > 0 then
             Printf.sprintf ", %d suite(s) failed to load" !load_errors
           else "");
      if ok then 0 else 1)

(* ---------------------------------------------------------------- config *)

let config_show ~config =
  run (fun () ->
      if not (Sys.file_exists config) then usage "config file not found: %s" config;
      match Config.of_file config with
      | Ok c ->
          print_json (Config.to_json_redacted c);
          0
      | Error errs -> usage "cannot load config:\n%s" (errors_to_string ~file:config errs))

(* --------------------------------------------------------------- version *)

let version ~json =
  if json then
    print_json
      (`Assoc
         [
           ("haltsql", `String Haltsql.version);
           ("postgres", `String Pg_parse.postgres_version);
           ("ocaml", `String Sys.ocaml_version);
         ])
  else begin
    pr "haltsql %s\n" Haltsql.version;
    pr "postgres grammar %s (libpg_query)\n" Pg_parse.postgres_version;
    pr "ocaml %s\n" Sys.ocaml_version
  end;
  0

(* ----------------------------------------------------------- lint-policy *)

type finding = { severity : string; code : string; message : string }

let lint (p : Policy.t) =
  let f severity code fmt =
    Printf.ksprintf (fun message -> { severity; code; message }) fmt
  in
  let tables = p.tables in
  let broad =
    List.filter_map
      (fun (t : Policy.table) ->
        match t.columns with
        | Policy.All ->
            Some
              (f "warning" "W_BROAD_COLUMNS"
                 "table %s allows all columns (\"*\"); list columns explicitly so new \
                  sensitive columns are not exposed automatically"
                 (Policy.table_qualified_name t))
        | Policy.Only _ -> None)
      tables
  in
  let scoped = List.filter (fun (t : Policy.table) -> t.tenant_columns <> []) tables in
  let tenancy_info =
    f "info" "I_TENANT_SCOPED" "%d of %d table(s) are tenant-scoped (mode: %s)"
      (List.length scoped) (List.length tables)
      (match p.tenancy.mode with Policy.Bound -> "bound" | Policy.Literal -> "literal")
  in
  let used_keys =
    List.concat_map (fun (t : Policy.table) -> List.map snd t.tenant_columns) tables
  in
  let unused =
    List.filter_map
      (fun (k, field) ->
        if List.mem k used_keys then None
        else
          Some
            (f "warning" "W_TENANCY_KEY_UNUSED"
               "tenancy key %S (from ctx.%s) is not used by any table" k field))
      p.tenancy.keys
  in
  let nfun = List.length p.functions in
  let funcs =
    if nfun > 60 then
      f "warning" "W_FUNCTIONS_LARGE"
        "functions allowlist has %d entries; large allowlists widen the attack surface"
        nfun
    else f "info" "I_FUNCTIONS" "functions allowlist has %d entries" nfun
  in
  let shadow =
    match p.mode with
    | Policy.Shadow ->
        [
          f "warning" "W_SHADOW_MODE"
            "policy is in shadow mode: violations are reported but NOT enforced (every \
             query is allowed)";
        ]
    | Policy.Enforce -> []
  in
  let limit =
    match p.require_limit with
    | None ->
        [
          f "warning" "W_NO_REQUIRE_LIMIT"
            "require_limit is not set: SELECTs may return unbounded result sets";
        ]
    | Some _ -> []
  in
  let missing_catalog =
    if p.catalog.tables = [] then []
    else
      List.filter_map
        (fun (t : Policy.table) ->
          match Catalog.find p.catalog ~schema:t.schema ~name:t.name with
          | Some _ -> None
          | None ->
              Some
                (f "warning" "W_TABLE_NOT_IN_CATALOG"
                   "table %s is not in the catalog snapshot"
                   (Policy.table_qualified_name t)))
        tables
  in
  let writes =
    List.filter_map
      (fun (t : Policy.table) ->
        let w = t.writes in
        if w.insert || w.update <> None || w.delete then
          Some
            (f "info" "I_WRITES" "table %s allows writes (%s)"
               (Policy.table_qualified_name t)
               (String.concat ", "
                  (List.filter_map Fun.id
                     [
                       (if w.insert then Some "insert" else None);
                       (if w.update <> None then Some "update" else None);
                       (if w.delete then Some "delete" else None);
                     ])))
        else None)
      tables
  in
  broad @ [ tenancy_info ] @ unused @ [ funcs ] @ shadow @ limit @ missing_catalog
  @ writes

let lint_policy ~file ~json =
  run (fun () ->
      let p = load_policy file in
      let findings = lint p in
      if json then
        print_json
          (`Assoc
             [
               ("policy", `String p.name);
               ("version", `String p.version);
               ( "findings",
                 `List
                   (List.map
                      (fun x ->
                        `Assoc
                          [
                            ("severity", `String x.severity);
                            ("code", `String x.code);
                            ("message", `String x.message);
                          ])
                      findings) );
             ])
      else begin
        pr "policy %s (%s)\n" p.name p.version;
        List.iter (fun x -> pr "%s: %s: %s\n" x.severity x.code x.message) findings;
        let w = List.length (List.filter (fun x -> x.severity = "warning") findings) in
        pr "%d warning(s)\n" w
      end;
      0)
