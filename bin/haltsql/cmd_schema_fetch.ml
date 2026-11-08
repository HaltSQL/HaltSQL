(** haltsql schema fetch: PII labels (and, optionally, a non-authoritative structure
    snapshot) from a live data catalog over HTTPS.

    [cmd] belongs in the [schema] group (see main.ml); [cmd_with ~providers] builds it
    over another provider list (tests register fakes this way). *)

open Cmdliner
module Ct = Haltsql_catalog_tools
module Cf = Haltsql_catalog_fetch

let provider_names providers =
  List.map (fun (module P : Cf.Provider.S) -> P.name) providers

let find_provider providers name =
  List.find_opt (fun (module P : Cf.Provider.S) -> String.equal P.name name) providers

let no_provider_msg providers name =
  match provider_names providers with
  | [] ->
      Printf.sprintf
        "unknown provider %S: no live catalog providers are built into this haltsql yet. \
         Export the metadata and use `haltsql schema import --from %s FILE` instead."
        name
        (String.concat "|"
           (List.map Ct.Pii_import.source_to_string Ct.Pii_import.all_sources))
  | names ->
      Printf.sprintf "unknown provider %S (available: %s)" name (String.concat ", " names)

(* The token comes from a file or an environment variable, never from the command line
   (it would end up in shell history and in `ps`). *)
let resolve_auth ~token_env ~token_file ~default_env =
  match (token_file, token_env) with
  | Some _, Some _ -> Common.usage "--token-env and --token-file are mutually exclusive"
  | Some f, None ->
      if not (Sys.file_exists f) then Common.usage "token file not found: %s" f;
      (match Unix.stat f with
      | { Unix.st_perm; _ } when st_perm land 0o077 <> 0 ->
          prerr_endline
            (Printf.sprintf
               "haltsql: warning: token file %s is readable by other users (chmod 600 it)"
               f)
      | _ -> ()
      | exception Unix.Unix_error _ -> ());
      let tok = String.trim (Common.read_file f) in
      if tok = "" then Common.usage "token file %s is empty" f;
      Cf.Fetch_client.Bearer tok
  | None, Some var -> (
      match Sys.getenv_opt var with
      | Some v when String.trim v <> "" -> Cf.Fetch_client.Bearer (String.trim v)
      | _ -> Common.usage "--token-env %s: the environment variable is not set" var)
  | None, None -> (
      match Sys.getenv_opt default_env with
      | Some v when String.trim v <> "" -> Cf.Fetch_client.Bearer (String.trim v)
      | _ ->
          prerr_endline
            (Printf.sprintf
               "haltsql: warning: %s is not set and no --token-file was given; sending \
                unauthenticated requests"
               default_env);
          Cf.Fetch_client.No_auth)

let fetch ~providers ~from ~url ~token_env ~token_file ~ca_file ~service ~database
    ~schemas ~output ~snapshot_out ~tags ~terms ~timeout ~max_pages ~json =
  Common.run (fun () ->
      let (module P : Cf.Provider.S) =
        match find_provider providers from with
        | Some p -> p
        | None -> Common.usage "%s" (no_provider_msg providers from)
      in
      if timeout <= 0. || timeout > 3600. then
        Common.usage "--timeout must be in (0, 3600]";
      if max_pages < 1 || max_pages > 1_000_000 then
        Common.usage "--max-pages must be in [1, 1000000]";
      List.iter
        (fun s -> if s = "" then Common.usage "--schema must not be empty")
        schemas;
      List.iter
        (fun (flag, v) ->
          match v with Some "" -> Common.usage "%s must not be empty" flag | _ -> ())
        [ ("--service", service); ("--database", database) ];
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
      let auth = resolve_auth ~token_env ~token_file ~default_env:P.default_token_env in
      let ctx =
        match ca_file with
        | None -> Haltsql_cloud.Http.default_ctx
        | Some f -> (
            match Lwt_main.run (Haltsql_cloud.Http.ctx_of_ca_file f) with
            | Ok c -> c
            | Error e -> Common.usage "%s" e)
      in
      let client =
        match Cf.Fetch_client.create ~ctx ~timeout ~max_pages ~base_url:url auth with
        | Ok c -> c
        | Error e -> Common.usage "%s" e
      in
      let shown_url = Uri.to_string (Cf.Fetch_client.base_url client) in
      let filter = { Cf.Provider.service; database; schemas } in
      let fetched =
        match Lwt_main.run (Cf.Catalog_fetch.fetch (module P) client filter) with
        | Ok f -> f
        | Error e ->
            Common.usage "schema fetch from %s (%s) failed: %s" shown_url P.name e
      in
      match Cf.Catalog_fetch.import_fetched ~config client fetched with
      | Error e ->
          prerr_endline (Printf.sprintf "haltsql: %s (%s): %s" shown_url P.name e);
          Common.exit_denied
      | Ok r ->
          Cmd_schema.warn_all r.warnings;
          (* The structure: only ever as a non-authoritative snapshot. *)
          let snapshot_written =
            match snapshot_out with
            | None -> None
            | Some path ->
                let snap = Cf.Catalog_fetch.catalog_snapshot ~database r.tables in
                if snap.catalog.tables = [] then begin
                  Cmd_schema.warn_all
                    [
                      Printf.sprintf
                        "%s returned no tables with columns; %s was not written" P.name
                        path;
                    ];
                  None
                end
                else begin
                  let j = Ct.Snapshot.to_json snap in
                  (* Fail closed: the drafter must read it, the policy loader must not. *)
                  (match Ct.Snapshot.of_json ~allow_non_authoritative:true j with
                  | Ok _ -> ()
                  | Error e ->
                      Common.usage "internal error: fetched snapshot does not load: %s" e);
                  (match Haltsql.Catalog_load.of_json j with
                  | Error _ -> ()
                  | Ok _ ->
                      Common.usage
                        "internal error: fetched snapshot is not marked non-authoritative");
                  Cmd_schema.write_atomic path (Yojson.Safe.pretty_to_string j ^ "\n");
                  Some (path, List.length snap.catalog.tables)
                end
          in
          let j =
            Ct.Pii.to_json
              ~metadata:
                [
                  ("source", `String P.name);
                  ("url", `String shown_url);
                  ("generated_by", `String "haltsql schema fetch");
                ]
              r.manifest
          in
          let text = Yojson.Safe.pretty_to_string j ^ "\n" in
          let n = List.length r.manifest in
          (match output with
          | None -> print_string text
          | Some path ->
              Cmd_schema.write_atomic path text;
              if json then
                Common.print_json
                  (`Assoc
                     ([
                        ("output", `String path);
                        ("source", `String P.name);
                        ("url", `String shown_url);
                        ("scanned_columns", `Int r.scanned_columns);
                        ("pii_columns", `Int n);
                        ("tables", `Int (List.length r.tables));
                        ("requests", `Int r.requests);
                      ]
                     @ (match snapshot_written with
                       | Some (p, _) -> [ ("snapshot", `String p) ]
                       | None -> [])
                     @ [ ("warnings", `List (List.map (fun w -> `String w) r.warnings)) ]
                     ))
              else
                Printf.printf
                  "wrote %s: %d PII column(s) out of %d scanned (%s, %d request(s))\n"
                  path n r.scanned_columns P.name r.requests);
          (match (snapshot_written, json && output <> None) with
          | Some (p, nt), false ->
              Printf.eprintf
                "haltsql: wrote %s: non-authoritative snapshot of %d table(s); usable by \
                 `haltsql policy draft --catalog` (SELECT * stays denied), refused as a \
                 policy catalog:\n"
                p nt
          | _ -> ());
          0)

let cmd_with ~providers =
  let names = provider_names providers in
  let from =
    Arg.(
      required
      & opt (some string) None
      & info [ "from" ] ~docv:"PROVIDER"
          ~doc:
            (match names with
            | [] -> "Data catalog provider (none are built in yet)."
            | l ->
                Printf.sprintf "Data catalog provider: %s."
                  (String.concat ", " (List.map (fun n -> Printf.sprintf "$(b,%s)" n) l))))
  in
  let url =
    Arg.(
      required
      & opt (some string) None
      & info [ "url" ] ~docv:"URL"
          ~doc:
            "Base URL of the catalog API, e.g. $(b,https://catalog.example.com/api). \
             https only (http is allowed for loopback hosts); a path prefix is kept; no \
             credentials, query or fragment.")
  in
  let token_env =
    Arg.(
      value
      & opt (some string) None
      & info [ "token-env" ] ~docv:"VAR"
          ~doc:
            "Environment variable holding the API token (default: the provider's, e.g. \
             $(b,OPENMETADATA_TOKEN); when that is unset, requests are unauthenticated). \
             The token is sent only as an Authorization: Bearer header to the --url \
             origin and is never printed. There is deliberately no option taking the \
             token itself.")
  in
  let token_file =
    Arg.(
      value
      & opt (some string) None
      & info [ "token-file" ] ~docv:"FILE"
          ~doc:"Read the API token from FILE (surrounding whitespace is removed).")
  in
  let ca_file =
    Arg.(
      value
      & opt (some string) None
      & info [ "ca-file" ] ~docv:"PEM"
          ~doc:"Trust only the CA certificates in this PEM file (private CA).")
  in
  let service =
    Arg.(
      value
      & opt (some string) None
      & info [ "service" ] ~docv:"NAME"
          ~doc:
            "Provider-specific scope: OpenMetadata database service, DataHub platform \
             instance, Unity Catalog catalog.")
  in
  let database =
    Arg.(
      value
      & opt (some string) None
      & info [ "database" ] ~docv:"NAME" ~doc:"Database name as the catalog records it.")
  in
  let schemas =
    Arg.(
      value & opt_all string []
      & info [ "schema" ] ~docv:"SCHEMA"
          ~doc:"Only this schema (repeatable). Default: all.")
  in
  let snapshot_out =
    Arg.(
      value
      & opt (some string) None
      & info [ "snapshot-out" ] ~docv:"FILE"
          ~doc:
            "Also write the tables and columns the catalog knows as a NON-AUTHORITATIVE \
             snapshot (untyped columns, metadata.authoritative: false). $(b,haltsql \
             policy draft --catalog) accepts it and drafts without catalog:, so SELECT * \
             stays denied; a policy catalog: refuses it. Prefer $(b,haltsql schema pull) \
             for the structure.")
  in
  let tags =
    Arg.(
      value & opt_all string []
      & info [ "pii-tag" ] ~docv:"TERM"
          ~doc:
            (Printf.sprintf
               "A tag/classification term that marks PII (repeatable; replaces the \
                defaults: %s)."
               (String.concat ", " Ct.Pii.Matcher.default_terms)))
  in
  let terms =
    Arg.(
      value & opt_all string []
      & info [ "pii-term" ] ~docv:"TERM"
          ~doc:
            "A business-glossary term that marks PII (repeatable; replaces the defaults).")
  in
  let timeout =
    Arg.(
      value & opt float 30.
      & info [ "timeout" ] ~docv:"SECONDS" ~doc:"Timeout of each HTTP request.")
  in
  let max_pages =
    Arg.(
      value & opt int 1000
      & info [ "max-pages" ] ~docv:"N"
          ~doc:
            "Stop with an error after N pages of one listing (runaway-pagination guard).")
  in
  let doc = "Fetch PII classifications from a live data catalog." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Reads column tags, classifications and glossary terms from a data catalog's API \
         and writes a PII manifest (as $(b,haltsql schema import) does for export \
         files). Labels are trusted; structure is not: a catalog crawler can lag behind \
         the database, so the authoritative table and column lists still come from \
         $(b,haltsql schema pull). $(b,--snapshot-out) writes the catalog's view only as \
         a non-authoritative snapshot. See docs/schema-and-pii.md.";
      `P
        (match names with
        | [] -> "No providers are built into this version."
        | l -> "Providers: " ^ String.concat ", " l ^ ".");
    ]
    @ Cmd_schema.man_examples
        [
          "  export OPENMETADATA_TOKEN=...";
          "  haltsql schema pull --dsn \"$DATABASE_URL\" --schema app -o catalog.json";
          "  haltsql schema fetch --from openmetadata --url https://om.example.com/api \\";
          "      --service prod_pg --database app --schema app -o pii.json";
          "  haltsql policy draft --catalog catalog.json --pii pii.json \\";
          "      --tenant-column tenant_id -o policy.yaml";
        ]
  in
  Cmd.v
    (Cmd.info "fetch" ~doc ~man ~exits:Cmd_schema.exits)
    Term.(
      const
        (fun
          from
          url
          token_env
          token_file
          ca_file
          service
          database
          schemas
          output
          snapshot_out
          tags
          terms
          timeout
          max_pages
          json
        ->
          fetch ~providers ~from ~url ~token_env ~token_file ~ca_file ~service ~database
            ~schemas ~output ~snapshot_out ~tags ~terms ~timeout ~max_pages ~json)
      $ from $ url $ token_env $ token_file $ ca_file $ service $ database $ schemas
      $ Cmd_schema.output_arg ~doc:"Write the PII manifest to FILE (default: stdout)."
      $ snapshot_out $ tags $ terms $ timeout $ max_pages $ Cmd_schema.json_arg)

let cmd = cmd_with ~providers:Cf.Catalog_fetch.providers
