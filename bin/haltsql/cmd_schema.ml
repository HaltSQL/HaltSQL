(** haltsql schema pull / schema import.

    [cmds] holds the two subcommands; they belong in the existing [schema] group next to
    [schema export] (see main.ml). *)

open Cmdliner
module Ct = Haltsql_catalog_tools

let exits =
  [
    Cmd.Exit.info 0 ~doc:"on success.";
    Cmd.Exit.info 1
      ~doc:"when the result fails validation (e.g. no relations or no column metadata).";
    Cmd.Exit.info 2 ~doc:"on usage errors, unreadable input, or connection failures.";
  ]

let man_examples ex =
  `S Manpage.s_examples
  :: List.concat_map (fun e -> [ `Pre (Manpage.escape e); `Noblank ]) ex

let json_arg = Arg.(value & flag & info [ "json" ] ~doc:"Machine-readable JSON summary.")

let output_arg ~doc =
  Arg.(value & opt (some string) None & info [ "o"; "output" ] ~docv:"FILE" ~doc)

(* Write via a temporary file + rename so a failed run never leaves a truncated file. *)
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

let warn_all ws = List.iter (fun w -> prerr_endline ("haltsql: warning: " ^ w)) ws

(* ---------------------------------------------------------------- pull *)

let pull ~dsn ~schemas ~output ~timeout ~json =
  Common.run (fun () ->
      let dsn_s =
        match dsn with
        | Some d -> d
        | None -> Common.usage "--dsn (or HALTSQL_DSN) is required"
      in
      let dsn =
        match Ct.Pg_dsn.parse dsn_s with
        | Ok d -> d
        | Error e -> Common.usage "invalid DSN: %s" e
      in
      if timeout <= 0. || timeout > 3600. then
        Common.usage "--timeout must be in (0, 3600]";
      List.iter
        (fun s -> if s = "" then Common.usage "--schema must not be empty")
        schemas;
      match Ct.Schema_pull.pull ~timeout ~schemas dsn with
      | Error e ->
          Common.usage "schema pull from %s failed: %s" (Ct.Pg_dsn.redacted dsn) e
      | Ok (snap, warnings) ->
          warn_all warnings;
          let j = Ct.Snapshot.to_json snap in
          (* Fail closed: what we write must load with the catalog loader. *)
          (match Ct.Snapshot.of_json j with
          | Ok _ -> ()
          | Error e -> Common.usage "internal error: pulled snapshot does not load: %s" e);
          let ntables = List.length snap.catalog.tables in
          let ncols =
            List.fold_left
              (fun n (t : Haltsql.Catalog.table) -> n + List.length t.columns)
              0 snap.catalog.tables
          in
          let text = Yojson.Safe.pretty_to_string j ^ "\n" in
          (match output with
          | None -> print_string text
          | Some path ->
              write_atomic path text;
              if json then
                Common.print_json
                  (`Assoc
                     [
                       ("output", `String path);
                       ("source", `String (Ct.Pg_dsn.redacted dsn));
                       ("relations", `Int ntables);
                       ("columns", `Int ncols);
                       ("schemas", `List (List.map (fun s -> `String s) snap.schemas));
                       ("warnings", `List (List.map (fun w -> `String w) warnings));
                     ])
              else
                Printf.printf "wrote %s: %d relations, %d columns from %s\n" path ntables
                  ncols (Ct.Pg_dsn.redacted dsn));
          if ntables = 0 then begin
            prerr_endline
              "haltsql: no relations found (check --schema and the database name)";
            Common.exit_denied
          end
          else 0)

let pull_cmd =
  let dsn =
    Arg.(
      value
      & opt (some string) None
      & info [ "dsn" ] ~docv:"DSN" ~env:(Cmd.Env.info "HALTSQL_DSN")
          ~doc:
            "PostgreSQL connection string: \
             $(b,postgres://user@host:5432/db?sslmode=verify-full) or $(b,host=... \
             dbname=... sslmode=...). Prefer $(b,PGPASSWORD) (or $(b,HALTSQL_DSN)) over \
             a password in the command line. sslmode: disable, prefer, require, \
             verify-ca, verify-full (default: prefer on loopback, require elsewhere); \
             sslrootcert=FILE sets the trusted CAs.")
  in
  let schemas =
    Arg.(
      value & opt_all string []
      & info [ "schema" ] ~docv:"SCHEMA"
          ~doc:"Only this schema (repeatable). Default: every non-system schema.")
  in
  let timeout =
    Arg.(
      value & opt float 10.
      & info [ "timeout" ] ~docv:"SECONDS" ~doc:"Connection timeout in seconds.")
  in
  let doc = "Snapshot tables, views and their typed columns from a live database." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Connects with a read-only transaction and writes a catalog snapshot (kind: \
         Catalog) listing every table, partitioned table, partition, view, materialized \
         view, foreign table and sequence of the selected schemas with the complete, \
         typed column list from pg_catalog. Reference it from a policy with \
         $(b,catalog:) so $(b,SELECT *) expands precisely. The password is never \
         printed. Supports SCRAM-SHA-256, MD5 and TLS.";
    ]
    @ man_examples
        [
          "  PGPASSWORD=... haltsql schema pull --dsn postgres://ro@db:5432/app \\";
          "      --schema app -o catalog.json";
          "  haltsql schema pull --dsn 'host=db.internal dbname=app user=ro \
           sslmode=verify-full' \\";
          "      --schema app --schema billing -o catalog.json --json";
        ]
  in
  Cmd.v
    (Cmd.info "pull" ~doc ~man ~exits)
    Term.(
      const (fun dsn schemas output timeout json ->
          pull ~dsn ~schemas ~output ~timeout ~json)
      $ dsn $ schemas
      $ output_arg ~doc:"Write the snapshot to FILE (default: stdout)."
      $ timeout $ json_arg)

(* ---------------------------------------------------------------- import *)

let import ~from ~file ~output ~tags ~terms ~json =
  Common.run (fun () ->
      if not (Sys.file_exists file) then Common.usage "file not found: %s" file;
      let text = Common.read_file file in
      let doc =
        match Yojson.Safe.from_string ~fname:file text with
        | j -> j
        | exception Yojson.Json_error e -> Common.usage "%s is not valid JSON: %s" file e
      in
      List.iter
        (fun t ->
          if String.trim t = "" then Common.usage "--pii-tag/--pii-term must not be empty")
        (tags @ terms);
      let d = Ct.Pii.Matcher.default in
      let config =
        {
          Ct.Pii.Matcher.tags = (if tags = [] then d.tags else tags);
          terms = (if terms = [] then d.terms else terms);
        }
      in
      match Ct.Pii_import.import ~config from doc with
      | Error e ->
          prerr_endline ("haltsql: " ^ file ^ ": " ^ e);
          Common.exit_denied
      | Ok r ->
          warn_all r.warnings;
          let src = Ct.Pii_import.source_to_string from in
          let j =
            Ct.Pii.to_json
              ~metadata:
                [
                  ("source", `String src);
                  ("file", `String (Filename.basename file));
                  ("generated_by", `String "haltsql schema import");
                ]
              r.manifest
          in
          let text = Yojson.Safe.pretty_to_string j ^ "\n" in
          let n = List.length r.manifest in
          (match output with
          | None -> print_string text
          | Some path ->
              write_atomic path text;
              if json then
                Common.print_json
                  (`Assoc
                     [
                       ("output", `String path);
                       ("source", `String src);
                       ("scanned_columns", `Int r.scanned_columns);
                       ("pii_columns", `Int n);
                       ("warnings", `List (List.map (fun w -> `String w) r.warnings));
                     ])
              else
                Printf.printf "wrote %s: %d PII column(s) out of %d scanned (%s)\n" path n
                  r.scanned_columns src);
          0)

let import_cmd =
  let from =
    Arg.(
      required
      & opt
          (some
             (enum
                (List.map
                   (fun s -> (Ct.Pii_import.source_to_string s, s))
                   Ct.Pii_import.all_sources)))
          None
      & info [ "from" ] ~docv:"TOOL"
          ~doc:
            "Export format: $(b,dbt), $(b,datahub), $(b,unity), $(b,atlan) or \
             $(b,collibra).")
  in
  let file = Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE") in
  let tags =
    Arg.(
      value & opt_all string []
      & info [ "pii-tag" ] ~docv:"TERM"
          ~doc:
            (Printf.sprintf
               "A tag/classification term that marks PII (repeatable; replaces the \
                defaults: %s). Matched word by word, so $(b,pii) matches \
                $(b,contains_pii) and $(b,urn:li:tag:PII)."
               (String.concat ", " Ct.Pii.Matcher.default_terms)))
  in
  let terms =
    Arg.(
      value & opt_all string []
      & info [ "pii-term" ] ~docv:"TERM"
          ~doc:
            "A business-glossary term that marks PII (repeatable; replaces the defaults).")
  in
  let doc = "Import PII classifications from a data catalog export." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Reads dbt (manifest.json, catalog.json), DataHub (file-sink MCE/MCP, GraphQL), \
         Databricks Unity Catalog (information_schema.column_tags rows, REST table \
         JSON), Atlan (asset search JSON) or Collibra (asset export) metadata and writes \
         a PII manifest: {tables: {\"schema.table\": {columns: {col: {classifications, \
         source}}}}}. Feed it to $(b,haltsql policy draft --pii). See \
         docs/schema-and-pii.md.";
    ]
    @ man_examples
        [
          "  haltsql schema import --from dbt target/manifest.json -o pii.dbt.json";
          "  haltsql schema import --from datahub export.json --pii-tag pii --pii-tag \
           gdpr";
          "  haltsql schema import --from unity column_tags.json -o pii.unity.json --json";
        ]
  in
  Cmd.v
    (Cmd.info "import" ~doc ~man ~exits)
    Term.(
      const (fun from file output tags terms json ->
          import ~from ~file ~output ~tags ~terms ~json)
      $ from $ file
      $ output_arg ~doc:"Write the manifest to FILE (default: stdout)."
      $ tags $ terms $ json_arg)

(* --------------------------------------------------------------- check *)

let check ~policy ~dsn ~snapshot ~timeout ~strict ~json =
  Common.run (fun () ->
      let p = Common.load_policy policy in
      let schemas =
        List.sort_uniq String.compare
          (List.map (fun (t : Haltsql.Policy.table) -> t.schema) p.tables
          @ List.filter (fun s -> s <> "pg_catalog") p.search_path)
      in
      let snap, source =
        match (snapshot, dsn) with
        | Some _, Some _ -> Common.usage "--snapshot and --dsn are mutually exclusive"
        | Some file, None -> (
            match Ct.Snapshot.of_file file with
            | Ok s -> (s, file)
            | Error e -> Common.usage "cannot load snapshot %s: %s" file e)
        | None, Some d -> (
            let dsn =
              match Ct.Pg_dsn.parse d with
              | Ok d -> d
              | Error e -> Common.usage "invalid DSN: %s" e
            in
            if timeout <= 0. || timeout > 3600. then
              Common.usage "--timeout must be in (0, 3600]";
            match Ct.Schema_pull.pull ~timeout ~schemas dsn with
            | Ok (s, _) -> (s, Ct.Pg_dsn.redacted dsn)
            | Error e ->
                Common.usage "schema pull from %s failed: %s" (Ct.Pg_dsn.redacted dsn) e)
        | None, None ->
            Common.usage "one of --dsn (or HALTSQL_DSN) and --snapshot is required"
      in
      let findings = Ct.Policy_drift.check p snap in
      let count sev =
        List.length
          (List.filter (fun (f : Ct.Policy_drift.finding) -> f.severity = sev) findings)
      in
      let errors = count Ct.Policy_drift.Error
      and warnings = count Ct.Policy_drift.Warning in
      if json then
        Common.print_json
          (`Assoc
             [
               ("policy", `String p.name);
               ("policy_version", `String p.version);
               ("source", `String source);
               ("errors", `Int errors);
               ("warnings", `Int warnings);
               ("findings", Ct.Policy_drift.to_json findings);
             ])
      else begin
        Printf.printf "policy %s (%s) against %s\n" p.name p.version source;
        List.iter
          (fun (f : Ct.Policy_drift.finding) ->
            Printf.printf "%s: %s: %s\n"
              (Ct.Policy_drift.severity_to_string f.severity)
              f.code f.message)
          findings;
        Printf.printf "%d error(s), %d warning(s)\n" errors warnings
      end;
      if errors > 0 || (strict && warnings > 0) then Common.exit_denied else 0)

let check_cmd =
  let policy =
    Arg.(
      required
      & opt (some string) None
      & info [ "p"; "policy" ] ~docv:"FILE" ~doc:"The policy to check.")
  in
  let dsn =
    Arg.(
      value
      & opt (some string) None
      & info [ "dsn" ] ~docv:"DSN" ~env:(Cmd.Env.info "HALTSQL_DSN")
          ~doc:"PostgreSQL connection string (see $(b,haltsql schema pull)).")
  in
  let snapshot =
    Arg.(
      value
      & opt (some string) None
      & info [ "snapshot" ] ~docv:"FILE"
          ~doc:
            "Compare against a snapshot written by $(b,haltsql schema pull) instead of \
             connecting.")
  in
  let timeout =
    Arg.(
      value & opt float 10.
      & info [ "timeout" ] ~docv:"SECONDS" ~doc:"Connection timeout in seconds.")
  in
  let strict =
    Arg.(value & flag & info [ "strict" ] ~doc:"Exit 1 on warnings as well as errors.")
  in
  let doc = "Check that a policy still describes the database." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "HaltSQL verifies SQL against the schema the policy describes, never against the \
         database. This command finds where the two disagree: policy tables or columns \
         that do not exist, a $(b,catalog:) snapshot that is out of date (a new column \
         would be read by $(b,SELECT *) unchecked), a relation in an earlier search_path \
         schema that captures an unqualified table name, and policy tables that are \
         views (their definition is invisible to HaltSQL). Run it in CI after every \
         migration and before every policy release. Exit status 1 when there are errors.";
    ]
    @ man_examples
        [
          "  PGPASSWORD=... haltsql schema check -p policy.yaml --dsn \
           postgres://ro@db:5432/app";
          "  haltsql schema check -p policy.yaml --snapshot catalog.json --strict --json";
        ]
  in
  Cmd.v
    (Cmd.info "check" ~doc ~man ~exits)
    Term.(
      const (fun policy dsn snapshot timeout strict json ->
          check ~policy ~dsn ~snapshot ~timeout ~strict ~json)
      $ policy $ dsn $ snapshot $ timeout $ strict $ json_arg)

let cmds = [ pull_cmd; check_cmd; import_cmd ]
