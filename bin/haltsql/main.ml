(** haltsql — command-line interface for the HaltSQL policy firewall. *)

open Cmdliner

let exits =
  [
    Cmd.Exit.info 0 ~doc:"on success (for $(b,verify)/$(b,explain): the SQL is allowed).";
    Cmd.Exit.info 1 ~doc:"when the SQL is denied, validation failed, or a test failed.";
    Cmd.Exit.info 2 ~doc:"on usage errors or when an input file cannot be loaded.";
  ]

let man_examples ex =
  `S Manpage.s_examples
  :: List.concat_map (fun e -> [ `Pre (Manpage.escape e); `Noblank ]) ex

(* ---- common arguments ---- *)

let policy_arg =
  Arg.(
    required
    & opt (some string) None
    & info [ "p"; "policy" ] ~docv:"FILE" ~doc:"Policy file (YAML or JSON).")

let context_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "c"; "context" ] ~docv:"JSON"
        ~doc:"Request context as a JSON object, e.g. '{\"tenant_id\":\"acme\"}'.")

let context_file_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "context-file" ] ~docv:"FILE"
        ~doc:"Request context from a YAML or JSON file.")

let sql_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "s"; "sql" ] ~docv:"SQL"
        ~doc:"SQL to verify. Default: read from $(b,--file) or stdin.")

let file_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "f"; "file" ] ~docv:"FILE" ~doc:"Read SQL from FILE.")

let json_arg = Arg.(value & flag & info [ "json" ] ~doc:"Machine-readable JSON output.")

(* ---- verify ---- *)

let verify_cmd =
  let batch =
    Arg.(
      value & flag
      & info [ "batch" ]
          ~doc:
            "Read JSONL from stdin, one {\"id\":..,\"sql\":..,\"context\":{..}} per \
             line, and write one compact JSON verdict per line (with \"id\" first). \
             Malformed lines produce {\"id\":..,\"error\":..} and do not stop the batch. \
             A line without \"context\" uses $(b,--context).")
  in
  let jobs =
    Arg.(
      value & opt int 1
      & info [ "j"; "jobs" ] ~docv:"N"
          ~doc:
            "With $(b,--batch): verify on N OCaml domains in parallel. Output order is \
             preserved.")
  in
  let doc = "Verify one SQL statement against a policy." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Prints $(b,ALLOWED) or $(b,DENIED) with the reasons (code, message, hint) and, \
         in bound tenancy mode, the parameters the caller MUST bind. Exit code 0 means \
         allowed, 1 denied, 2 usage or load error. In shadow mode violations are \
         reported but the exit code is 0.";
    ]
    @ man_examples
        [
          "  haltsql verify -p policy.yaml -c '{\"tenant_id\":\"acme\"}' \\";
          "      --sql 'SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10'";
          "  echo 'SELECT * FROM pg_shadow' | haltsql verify -p policy.yaml --json";
          "  haltsql verify -p policy.yaml --batch --jobs 4 < queries.jsonl > \
           verdicts.jsonl";
        ]
  in
  let f policy context context_file sql file json batch jobs =
    Cmds.verify ~policy ~context ~context_file ~sql ~file ~json ~batch ~jobs
  in
  Cmd.v
    (Cmd.info "verify" ~doc ~man ~exits)
    Term.(
      const f $ policy_arg $ context_arg $ context_file_arg $ sql_arg $ file_arg
      $ json_arg $ batch $ jobs)

(* ---- explain ---- *)

let explain_cmd =
  let doc =
    "Explain a verdict: statement kind, tables, columns and each reason with a caret."
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Like $(b,verify), but prints a readable report for debugging denials: the \
         verdict, statement kind, tables and columns touched, bind parameters, and every \
         reason with its code, rule, message and hint, with a caret under the SQL at the \
         reported position.";
    ]
    @ man_examples
        [ "  haltsql explain -p policy.yaml -c '{\"tenant_id\":\"acme\"}' -f query.sql" ]
  in
  let f policy context context_file sql file json =
    Cmds.explain ~policy ~context ~context_file ~sql ~file ~json
  in
  Cmd.v
    (Cmd.info "explain" ~doc ~man ~exits)
    Term.(
      const f $ policy_arg $ context_arg $ context_file_arg $ sql_arg $ file_arg
      $ json_arg)

(* ---- validate ---- *)

let validate_cmd =
  let files = Arg.(value & pos_all string [] & info [] ~docv:"FILE") in
  let doc = "Validate Policy, Config, TestSuite, Catalog or Scenario documents." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Detects each document's $(b,kind) and loads it with the matching loader, \
         printing $(b,ok) or located errors (file:line:column: key.path: message). Exits \
         1 if any file has errors.";
    ]
    @ man_examples
        [
          "  haltsql validate policies/*.yaml config.yaml";
          "  haltsql validate --json policy.json";
        ]
  in
  Cmd.v
    (Cmd.info "validate" ~doc ~man ~exits)
    Term.(const (fun files json -> Cmds.validate ~files ~json) $ files $ json_arg)

(* ---- convert ---- *)

let convert_cmd =
  let file = Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE") in
  let to_ =
    Arg.(
      required
      & opt (some (enum [ ("json", `Json); ("yaml", `Yaml) ])) None
      & info [ "to" ] ~docv:"FORMAT" ~doc:"Target format: $(b,json) or $(b,yaml).")
  in
  let out =
    Arg.(
      value
      & opt (some string) None
      & info [ "o"; "output" ] ~docv:"OUT" ~doc:"Write to OUT instead of stdout.")
  in
  let doc = "Convert a document between YAML and JSON (lossless)." in
  let man = man_examples [ "  haltsql convert policy.yaml --to json -o policy.json" ] in
  Cmd.v
    (Cmd.info "convert" ~doc ~man ~exits)
    Term.(const (fun file to_ out -> Cmds.convert ~file ~to_ ~out) $ file $ to_ $ out)

(* ---- schema export ---- *)

let schema_cmd =
  let out =
    Arg.(
      required
      & opt (some string) None
      & info [ "out" ] ~docv:"DIR"
          ~doc:"Directory to write the JSON Schemas into (created if needed).")
  in
  let export =
    Cmd.v
      (Cmd.info "export" ~doc:"Write the JSON Schemas for every document kind."
         ~man:(man_examples [ "  haltsql schema export --out schemas/" ])
         ~exits)
      Term.(const (fun out -> Cmds.schema_export ~out) $ out)
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "$(b,pull) snapshots a live database catalog, $(b,import) converts PII metadata \
         from other tools into manifests, and $(b,export) writes the JSON Schemas of \
         every HaltSQL document kind (for editor validation).";
    ]
    @ man_examples
        [
          "  haltsql schema pull --dsn \"$DATABASE_URL\" -o catalog.json";
          "  haltsql schema export --out schemas/";
        ]
  in
  Cmd.group
    (Cmd.info "schema" ~man ~exits
       ~doc:"Catalog snapshots, PII metadata import and JSON Schema tooling.")
    ([ export ] @ Cmd_schema.cmds)

(* ---- test ---- *)

let test_cmd =
  let paths = Arg.(value & pos_all string [] & info [] ~docv:"SUITE_FILE") in
  let filter =
    Arg.(
      value
      & opt (some string) None
      & info [ "filter" ] ~docv:"TAG" ~doc:"Only run cases tagged TAG.")
  in
  let verbose =
    Arg.(
      value & flag & info [ "v"; "verbose" ] ~doc:"Show reasons for passing cases too.")
  in
  let doc = "Run policy test suites (kind: TestSuite)." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Runs each case through the verifier and checks the expectation (allow/deny, \
         required reason codes, bind parameters). Directories are searched recursively \
         for $(b,*.suite.yaml), $(b,*.suite.yml) and $(b,*.suite.json). Exits 1 if any \
         case fails or any suite fails to load.";
    ]
    @ man_examples
        [
          "  haltsql test tests/policy.suite.yaml";
          "  haltsql test tests/ --filter tenancy --json";
        ]
  in
  Cmd.v
    (Cmd.info "test" ~doc ~man ~exits)
    Term.(
      const (fun paths json filter verbose -> Cmds.test ~paths ~json ~filter ~verbose)
      $ paths $ json_arg $ filter $ verbose)

(* ---- config show ---- *)

let config_cmd =
  let config =
    Arg.(
      required
      & opt (some string) None
      & info [ "config" ] ~docv:"FILE" ~doc:"Config file (YAML or JSON).")
  in
  let effective =
    Arg.(
      value & flag
      & info [ "effective" ]
          ~doc:"Accepted for compatibility: the output always merges HALTSQL_* env vars.")
  in
  let show =
    Cmd.v
      (Cmd.info "show" ~doc:"Print the effective configuration with secrets redacted."
         ~man:
           (man_examples
              [ "  HALTSQL_LISTEN=0.0.0.0:9000 haltsql config show --config config.yaml" ])
         ~exits)
      Term.(const (fun config _ -> Cmds.config_show ~config) $ config $ effective)
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Inspects the haltsql-server configuration as the server would load it: the \
         config file merged with HALTSQL_* environment variables, with secrets redacted.";
    ]
    @ man_examples [ "  haltsql config show --config config.yaml" ]
  in
  Cmd.group (Cmd.info "config" ~doc:"Inspect runtime configuration." ~man ~exits) [ show ]

(* ---- version ---- *)

let version_cmd =
  Cmd.v
    (Cmd.info "version" ~doc:"Print HaltSQL, Postgres grammar and OCaml versions." ~exits)
    Term.(const (fun json -> Cmds.version ~json) $ json_arg)

(* ---- lint-policy ---- *)

let lint_cmd =
  let file = Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE") in
  let doc = "Report risky or suspicious settings in a policy." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Warns about tables exposing all columns, unused tenancy keys, shadow mode, a \
         missing require_limit, large function allowlists and tables missing from the \
         catalog. Exits 0 unless the policy fails to load.";
    ]
    @ man_examples [ "  haltsql lint-policy policy.yaml" ]
  in
  Cmd.v
    (Cmd.info "lint-policy" ~doc ~man ~exits)
    Term.(const (fun file json -> Cmds.lint_policy ~file ~json) $ file $ json_arg)

let main =
  let doc = "policy firewall for LLM-generated PostgreSQL" in
  let man =
    [
      `S Manpage.s_description;
      `P
        "HaltSQL verifies that an exact SQL string is allowed for a caller under a \
         declarative policy, using the real PostgreSQL parser. It never rewrites SQL and \
         never connects to the database.";
    ]
    @ man_examples
        [
          "  haltsql verify -p policy.yaml -c '{\"tenant_id\":\"acme\"}' --sql 'SELECT 1'";
          "  haltsql validate policy.yaml";
          "  haltsql test tests/";
        ]
  in
  Cmd.group
    (Cmd.info "haltsql" ~version:Haltsql.version ~doc ~man ~exits)
    [
      verify_cmd;
      explain_cmd;
      validate_cmd;
      convert_cmd;
      schema_cmd;
      test_cmd;
      config_cmd;
      version_cmd;
      lint_cmd;
      Cmd_policy_draft.cmd;
      Cmd_rls.cmd;
      Cmd_bundle.cmd;
    ]

let () =
  let code =
    match Cmd.eval_value main with
    | Ok (`Ok code) -> code
    | Ok (`Help | `Version) -> 0
    | Error (`Parse | `Term) -> 2
    | Error `Exn -> 2
  in
  exit code
