(* haltsql policy draft: a reviewable starter policy from a catalog snapshot and PII
   manifests. [cmd] is the [policy] group; [draft_cmd] the subcommand alone. *)

open Cmdliner
module Ct = Haltsql_catalog_tools

let exits =
  [
    Cmd.Exit.info 0 ~doc:"on success.";
    Cmd.Exit.info 1 ~doc:"when the drafted policy fails validation.";
    Cmd.Exit.info 2 ~doc:"on usage errors or when an input file cannot be loaded.";
  ]

let man_examples ex =
  `S Manpage.s_examples
  :: List.concat_map (fun e -> [ `Pre (Manpage.escape e); `Noblank ]) ex

let draft ~catalog ~pii ~tenant_column ~tenancy_key ~context_field ~schemas ~output ~name
    ~require_limit ~no_heuristics ~name_patterns ~include_partitions ~catalog_ref ~json =
  Common.run (fun () ->
      if not (Sys.file_exists catalog) then
        Common.usage "catalog file not found: %s" catalog;
      let snap =
        match Ct.Snapshot.of_file catalog with
        | Ok s -> s
        | Error e -> Common.usage "cannot load catalog %s:\n%s" catalog e
      in
      let manifests =
        List.map
          (fun f ->
            if not (Sys.file_exists f) then Common.usage "PII manifest not found: %s" f;
            match Ct.Pii.of_file f with Ok m -> m | Error e -> Common.usage "%s" e)
          pii
      in
      let out_dir = match output with Some o -> Filename.dirname o | None -> "." in
      let catalog_ref =
        match catalog_ref with
        | Some r -> r
        | None -> Ct.Policy_draft.relative_path ~from_dir:out_dir catalog
      in
      let name =
        match (name, output) with
        | Some n, _ -> n
        | None, Some o -> Filename.remove_extension (Filename.basename o)
        | None, None -> "draft-policy"
      in
      let d = Ct.Policy_draft.default_config ~tenant_column ~catalog_ref in
      let cfg =
        {
          d with
          name;
          tenancy_key;
          context_field;
          schemas;
          require_limit;
          name_patterns =
            (if no_heuristics then []
             else if name_patterns = [] then d.name_patterns
             else name_patterns);
          include_partitions;
          pii_sources = List.map Filename.basename pii;
        }
      in
      match Ct.Policy_draft.draft ~base_dir:out_dir cfg snap (Ct.Pii.merge manifests) with
      | Error e ->
          prerr_endline ("haltsql: " ^ e);
          Common.exit_denied
      | Ok r ->
          List.iter (fun w -> prerr_endline ("haltsql: warning: " ^ w)) r.warnings;
          let kept =
            List.filter
              (fun (t : Ct.Policy_draft.table_report) -> t.skipped = None)
              r.tables
          in
          let scoped =
            List.length
              (List.filter
                 (fun (t : Ct.Policy_draft.table_report) -> t.tenant_scoped)
                 kept)
          in
          let excluded =
            List.fold_left
              (fun n (t : Ct.Policy_draft.table_report) -> n + List.length t.excluded)
              0 kept
          in
          let skipped = List.length r.tables - List.length kept in
          (match output with
          | None -> print_string r.yaml
          | Some path ->
              Cmd_schema.write_atomic path r.yaml;
              if json then
                Common.print_json
                  (`Assoc
                     [
                       ("output", `String path);
                       ("tables", `Int (List.length kept));
                       ("tenant_scoped", `Int scoped);
                       ("global", `Int (List.length kept - scoped));
                       ("excluded_columns", `Int excluded);
                       ("skipped_relations", `Int skipped);
                       ("warnings", `List (List.map (fun w -> `String w) r.warnings));
                     ])
              else
                Printf.printf
                  "wrote %s: %d tables (%d tenant-scoped, %d global), %d PII column(s) \
                   excluded, %d relation(s) skipped. Review it before use.\n"
                  path (List.length kept) scoped
                  (List.length kept - scoped)
                  excluded skipped);
          0)

let draft_cmd =
  let catalog =
    Arg.(
      required
      & opt (some string) None
      & info [ "catalog" ] ~docv:"FILE"
          ~doc:"Catalog snapshot (from $(b,haltsql schema pull)).")
  in
  let pii =
    Arg.(
      value & opt_all string []
      & info [ "pii" ] ~docv:"FILE"
          ~doc:"PII manifest (from $(b,haltsql schema import)); repeatable, merged.")
  in
  let tenant_column =
    Arg.(
      required
      & opt (some string) None
      & info [ "tenant-column" ] ~docv:"COLUMN"
          ~doc:"Tenant column; every table that has it becomes tenant-scoped.")
  in
  let tenancy_key =
    Arg.(
      value & opt string "tenant"
      & info [ "tenancy-key" ] ~docv:"KEY" ~doc:"Tenancy key name.")
  in
  let context_field =
    Arg.(
      value & opt string "tenant_id"
      & info [ "context-field" ] ~docv:"FIELD"
          ~doc:"Request-context field holding the tenant id (the ctx.FIELD placeholder).")
  in
  let schemas =
    Arg.(
      value & opt_all string []
      & info [ "schema" ] ~docv:"SCHEMA"
          ~doc:
            "Only tables of this schema (repeatable); also the search_path. Default: all.")
  in
  let output =
    Arg.(
      value
      & opt (some string) None
      & info [ "o"; "output" ] ~docv:"FILE"
          ~doc:"Write the policy to FILE (default: stdout).")
  in
  let name_arg =
    Arg.(
      value
      & opt (some string) None
      & info [ "name" ] ~docv:"NAME" ~doc:"metadata.name (default: the output file name).")
  in
  let require_limit =
    Arg.(
      value & opt int 1000 & info [ "require-limit" ] ~docv:"N" ~doc:"require_limit.max.")
  in
  let no_heuristics =
    Arg.(
      value & flag
      & info [ "no-name-heuristics" ]
          ~doc:"Do not exclude columns by name (email, phone, ssn, password, token, ...).")
  in
  let name_patterns =
    Arg.(
      value & opt_all string []
      & info [ "name-pattern" ] ~docv:"WORD"
          ~doc:
            (Printf.sprintf "Column-name word that marks PII (repeatable; replaces: %s)."
               (String.concat ", " Ct.Policy_draft.default_name_patterns)))
  in
  let include_partitions =
    Arg.(
      value & flag
      & info [ "include-partitions" ] ~doc:"Also list partitions (default: parents only).")
  in
  let catalog_ref =
    Arg.(
      value
      & opt (some string) None
      & info [ "catalog-ref" ] ~docv:"PATH"
          ~doc:
            "Value of catalog: (default: the catalog path relative to the output file).")
  in
  let json =
    Arg.(value & flag & info [ "json" ] ~doc:"Machine-readable JSON summary (with -o).")
  in
  let doc =
    "Draft a reviewable starter policy from a catalog snapshot and PII manifests."
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Lists every table and view with an explicit column list that leaves out PII \
         columns (with a YAML comment saying which and why), sets tenant_column where \
         the column exists, and uses bound tenancy, require_limit 1000, the aggregates, \
         math, string and datetime presets and a catalog: reference. The draft is \
         validated by loading it before it is written. It is a starting point: review \
         every table.";
    ]
    @ man_examples
        [
          "  haltsql schema pull --dsn postgres://ro@db/app --schema app -o catalog.json";
          "  haltsql schema import --from dbt target/manifest.json -o pii.json";
          "  haltsql policy draft --catalog catalog.json --pii pii.json \\";
          "      --tenant-column tenant_id --schema app -o policy.yaml";
          "  haltsql lint-policy policy.yaml";
        ]
  in
  Cmd.v
    (Cmd.info "draft" ~doc ~man ~exits)
    Term.(
      const
        (fun
          catalog
          pii
          tenant_column
          tenancy_key
          context_field
          schemas
          output
          name
          require_limit
          no_heuristics
          name_patterns
          include_partitions
          catalog_ref
          json
        ->
          draft ~catalog ~pii ~tenant_column ~tenancy_key ~context_field ~schemas ~output
            ~name ~require_limit ~no_heuristics ~name_patterns ~include_partitions
            ~catalog_ref ~json)
      $ catalog $ pii $ tenant_column $ tenancy_key $ context_field $ schemas $ output
      $ name_arg $ require_limit $ no_heuristics $ name_patterns $ include_partitions
      $ catalog_ref $ json)

let cmd = Cmd.group (Cmd.info "policy" ~doc:"Policy authoring tools.") [ draft_cmd ]
