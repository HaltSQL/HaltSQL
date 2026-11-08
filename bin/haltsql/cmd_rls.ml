(** haltsql rls generate | check: database-level defense in depth from a policy. *)

open Cmdliner
open Haltsql
open Common
module Rls_gen = Haltsql_rlsgen.Rls_gen
module Rls_check = Haltsql_rlsgen.Rls_check
module Pg_wire = Haltsql_rlsgen.Pg_wire

let exits =
  [
    Cmd.Exit.info 0 ~doc:"on success ($(b,check): no drift).";
    Cmd.Exit.info 1
      ~doc:"when $(b,check) finds drift between the policy and the database.";
    Cmd.Exit.info 2
      ~doc:
        "on usage errors, when an input file cannot be loaded, or when the database \
         cannot be reached.";
  ]

let man_examples ex =
  `S Manpage.s_examples
  :: List.concat_map (fun e -> [ `Pre (Manpage.escape e); `Noblank ]) ex

(* ---- shared arguments ---- *)

let policy_arg =
  Arg.(
    required
    & opt (some string) None
    & info [ "p"; "policy" ] ~docv:"FILE" ~doc:"Policy file (YAML or JSON).")

let catalog_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "catalog" ] ~docv:"FILE"
        ~doc:
          "Schema snapshot (from $(b,haltsql schema pull)) used for tenant column types. \
           Consulted before the policy's own $(b,catalog:).")

let role_arg =
  Arg.(
    value
    & opt string Rls_gen.default_options.role
    & info [ "role" ] ~docv:"ROLE" ~doc:"Role that runs agent queries.")

let prefix_arg =
  Arg.(
    value
    & opt string Rls_gen.default_options.setting_prefix
    & info [ "setting-prefix" ] ~docv:"PREFIX"
        ~doc:"Namespace of the custom settings: $(docv).<context_field>.")

let set_field_arg =
  Arg.(
    value & opt_all string []
    & info [ "set-field" ] ~docv:"FIELD"
        ~doc:
          "Context field whose value is a set of tenants (e.g. tenant_ids). Its setting \
           holds the values joined with ',' and the predicate uses = ANY(...). \
           Repeatable.")

let force_arg =
  Arg.(
    value & flag
    & info [ "force-rls" ]
        ~doc:"Also FORCE ROW LEVEL SECURITY, so the table owner is subject to RLS too.")

let json_arg = Arg.(value & flag & info [ "json" ] ~doc:"Machine-readable JSON output.")

let load_catalog = function
  | None -> None
  | Some f -> (
      if not (Sys.file_exists f) then usage "catalog file not found: %s" f;
      match Catalog_load.of_file f with
      | Ok c -> Some c
      | Error errs -> usage "cannot load catalog:\n%s" (errors_to_string ~file:f errs))

let make_plan ~policy ~catalog ~role ~prefix ~set_fields ~force ~owner ~drop =
  let p = load_policy policy in
  let opts =
    {
      Rls_gen.role;
      setting_prefix = prefix;
      owner_role = owner;
      drop_existing = drop;
      force_rls = force;
      set_fields;
      catalog = load_catalog catalog;
    }
  in
  match Rls_gen.plan opts p with Ok pl -> pl | Error e -> usage "%s" e

(* ---- generate ---- *)

let generate ~policy ~catalog ~role ~prefix ~set_fields ~force ~owner ~drop ~out ~json =
  run (fun () ->
      let pl = make_plan ~policy ~catalog ~role ~prefix ~set_fields ~force ~owner ~drop in
      let sql = Rls_gen.render pl in
      List.iter (fun w -> prerr_endline ("haltsql: warning: " ^ w)) pl.warnings;
      (match out with
      | Some f -> (
          match write_file f sql with
          | () -> ()
          | exception Sys_error e -> usage "cannot write %s" e)
      | None -> if not json then print_string sql);
      if json then begin
        let extra =
          match out with
          | Some f -> [ ("output", `String f) ]
          | None -> [ ("sql", `String sql) ]
        in
        match Rls_gen.plan_to_json pl with
        | `Assoc kv -> print_json (`Assoc (kv @ extra))
        | j -> print_json j
      end;
      exit_allowed)

let generate_cmd =
  let owner =
    Arg.(
      value
      & opt (some string) None
      & info [ "owner-role" ] ~docv:"ROLE"
          ~doc:
            "Run the table DDL as $(docv) (SET LOCAL ROLE), the role that owns the \
             tables. Only owners may enable RLS and create policies.")
  in
  let drop =
    Arg.(
      value & flag
      & info [ "drop-existing" ]
          ~doc:
            "Drop EVERY existing policy on the managed tables first (not only the \
             haltsql_tenant_* ones). Other permissive policies would widen what the role \
             sees.")
  in
  let out =
    Arg.(
      value
      & opt (some string) None
      & info [ "o"; "output" ] ~docv:"FILE"
          ~doc:"Write the SQL to $(docv) instead of stdout.")
  in
  let doc = "Generate role, grant and row-level-security DDL that mirrors a policy." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Emits idempotent, deterministic PostgreSQL 13-17 DDL: a NOLOGIN NOBYPASSRLS \
         role, REVOKE ALL on the policy's schemas, USAGE on them, column-level SELECT \
         (and INSERT/UPDATE/DELETE matching the policy's writes), and for every \
         tenant-scoped table ENABLE ROW LEVEL SECURITY plus one haltsql_tenant_<command> \
         policy per allowed command, comparing each tenant column with \
         current_setting('<prefix>.<context_field>', true). A missing setting matches no \
         rows.";
      `P
        "The header of the output documents the session preamble: the application sets \
         the settings with set_config(..., true) or SET LOCAL in the same transaction, \
         from the same context values it passed to HaltSQL. See docs/rls-generation.md.";
    ]
    @ man_examples
        [
          "  haltsql rls generate -p policy.yaml -o rls.sql";
          "  haltsql rls generate -p policy.yaml --catalog catalog.json --role agent \\";
          "      --owner-role app_owner --force-rls --drop-existing -o rls.sql";
          "  haltsql rls generate -p hierarchical.yaml --set-field tenant_ids";
          "  psql \"$ADMIN_DSN\" -v ON_ERROR_STOP=1 -f rls.sql";
        ]
  in
  let f policy catalog role prefix set_fields force owner drop out json =
    generate ~policy ~catalog ~role ~prefix ~set_fields ~force ~owner ~drop ~out ~json
  in
  Cmd.v
    (Cmd.info "generate" ~doc ~man ~exits)
    Term.(
      const f $ policy_arg $ catalog_arg $ role_arg $ prefix_arg $ set_field_arg
      $ force_arg $ owner $ drop $ out $ json_arg)

(* ---- check ---- *)

let check ~policy ~catalog ~role ~prefix ~set_fields ~force ~dsn ~json =
  run (fun () ->
      let pl =
        make_plan ~policy ~catalog ~role ~prefix ~set_fields ~force ~owner:None
          ~drop:false
      in
      let dsn =
        match dsn with
        | None -> usage "--dsn (or HALTSQL_DSN) is required"
        | Some s -> (
            match Pg_wire.parse_dsn s with Ok d -> d | Error e -> usage "%s" e)
      in
      let findings =
        try
          Lwt_main.run (Pg_wire.with_connection dsn (fun conn -> Rls_check.check conn pl))
        with
        | Pg_wire.Protocol_error m ->
            usage "cannot check %s: %s" (Pg_wire.dsn_to_string_redacted dsn) m
        | Pg_wire.Pg_error { code; message; _ } ->
            usage "cannot check %s: %s (SQLSTATE %s)"
              (Pg_wire.dsn_to_string_redacted dsn)
              message code
      in
      let drift = findings <> [] in
      if json then
        print_json
          (`Assoc
             [
               ("drift", `Bool drift);
               ("database", `String (Pg_wire.dsn_to_string_redacted dsn));
               ("policy", `String pl.policy_name_meta);
               ("policy_version", `String pl.policy_version);
               ("role", `String role);
               ("findings", `List (List.map Rls_check.finding_to_json findings));
             ])
      else
        begin if not drift then
          Printf.printf "no drift: %s matches policy %s for role %s\n"
            (Pg_wire.dsn_to_string_redacted dsn)
            pl.policy_name_meta role
        else begin
          Printf.printf "drift: %d finding(s) for role %s (policy %s)\n"
            (List.length findings) role pl.policy_name_meta;
          List.iter
            (fun (f : Rls_check.finding) ->
              Printf.printf "  %-8s %-18s %s: %s\n"
                (Rls_check.severity_to_string f.severity)
                f.kind f.obj f.message)
            findings
        end
        end;
      if drift then exit_denied else exit_allowed)

let check_cmd =
  let dsn =
    Arg.(
      value
      & opt (some string) None
      & info [ "dsn" ] ~docv:"URL" ~env:(Cmd.Env.info "HALTSQL_DSN")
          ~doc:
            "postgres://user@host:port/db?sslmode=... Prefer passing the password in \
             PGPASSWORD rather than in the URL.")
  in
  let doc = "Report drift between a policy and the live database (read-only)." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Connects (read-only transaction, catalog queries only) and compares the role's \
         EFFECTIVE privileges and the tables' row-level security with what $(b,rls \
         generate) would create: missing role or BYPASSRLS, schema USAGE/CREATE, table- \
         and column-level grants beyond (or short of) the policy, tables outside the \
         policy the role can touch, RLS disabled, missing or altered haltsql_tenant_* \
         policies, and other permissive policies that widen access. Pass the same \
         --role, --setting-prefix, --set-field and --force-rls used to generate.";
      `P
        "Supports SCRAM-SHA-256 and MD5 password authentication and sslmode \
         disable|prefer|require|verify-full.";
    ]
    @ man_examples
        [
          "  PGPASSWORD=... haltsql rls check -p policy.yaml \\";
          "      --dsn postgres://admin@db.internal:5432/app?sslmode=verify-full";
          "  haltsql rls check -p policy.yaml --dsn \"$DSN\" --role agent --json";
        ]
  in
  let f policy catalog role prefix set_fields force dsn json =
    check ~policy ~catalog ~role ~prefix ~set_fields ~force ~dsn ~json
  in
  Cmd.v
    (Cmd.info "check" ~doc ~man ~exits)
    Term.(
      const f $ policy_arg $ catalog_arg $ role_arg $ prefix_arg $ set_field_arg
      $ force_arg $ dsn $ json_arg)

let cmd : int Cmd.t =
  Cmd.group
    (Cmd.info "rls" ~exits
       ~doc:"Generate and check PostgreSQL row-level security that mirrors a policy.")
    [ generate_cmd; check_cmd ]
