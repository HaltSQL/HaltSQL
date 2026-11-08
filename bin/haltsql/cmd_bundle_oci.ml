(* haltsql bundle push --oci REF | bundle pull --oci REF.

   [cmds] are subcommands of the [bundle] group (register them next to
   Cmd_bundle's). Exit codes: 0 ok, 1 verification or integrity failure,
   2 usage or input error, 3 registry unreachable or refused the request. *)

open Cmdliner
module B = Haltsql_bundle
module S = Haltsql_bundle_source

let exit_registry = 3

let exits =
  [
    Cmd.Exit.info 0 ~doc:"on success.";
    Cmd.Exit.info 1
      ~doc:"when a bundle, signature, manifest or blob fails verification or validation.";
    Cmd.Exit.info 2 ~doc:"on usage errors or when an input file cannot be loaded.";
    Cmd.Exit.info exit_registry
      ~doc:"when the registry cannot be reached or refuses the request.";
  ]

let man_examples ex =
  `S Manpage.s_examples
  :: List.concat_map (fun e -> [ `Pre (Manpage.escape e); `Noblank ]) ex

exception Failed of int * string

let fail code fmt = Printf.ksprintf (fun s -> raise (Failed (code, s))) fmt

(* A verification or registry failure is also reported on stdout with
   [--json] ({"ok":false,"exit":N,"error":...}, the shape of
   [bundle verify --json]), so a script reading the JSON never gets an empty
   document. *)
let run ~json f =
  Common.run (fun () ->
      match f () with
      | code -> code
      | exception Failed (code, msg) ->
          if json then
            Common.print_json
              (`Assoc [ ("ok", `Bool false); ("exit", `Int code); ("error", `String msg) ]);
          prerr_endline ("haltsql: " ^ msg);
          code)

let fetch_fail (e : S.Fetch_error.t) =
  let code =
    match e with S.Fetch_error.Integrity _ -> Common.exit_denied | _ -> exit_registry
  in
  fail code "%s" (S.Fetch_error.to_string e)

(* ------------------------------------------------------------------ args *)

let oci_arg =
  Arg.(
    required
    & opt (some string) None
    & info [ "oci" ] ~docv:"REF"
        ~doc:
          "OCI reference: $(i,registry[:port]/repository:tag), \
           $(i,registry/repository@sha256:DIGEST) or both. The registry host is \
           mandatory.")

let plain_http_arg =
  Arg.(
    value & flag
    & info [ "plain-http" ]
        ~doc:
          "Use plain HTTP. Only allowed for loopback registries (localhost, 127.x, \
           [::1]).")

let username_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "username" ] ~docv:"USER"
        ~doc:"Registry user for basic credentials (with $(b,--password-env)).")

let password_env_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "password-env" ] ~docv:"VAR"
        ~doc:
          "Read the registry password (or access token used as one) from environment \
           variable VAR.")

let token_env_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "token-env" ] ~docv:"VAR"
        ~doc:"Read a pre-issued registry bearer token from environment variable VAR.")

let ca_file_arg =
  Arg.(
    value
    & opt (some file) None
    & info [ "ca-file" ] ~docv:"FILE"
        ~doc:
          "Trust only these PEM CA certificates for the registry (instead of the system \
           store).")

let timeout_arg =
  Arg.(
    value & opt float 60.
    & info [ "timeout" ] ~docv:"SECONDS" ~doc:"Timeout of each HTTP request.")

let json_arg = Arg.(value & flag & info [ "json" ] ~doc:"Machine-readable JSON output.")

let public_keys_arg =
  Arg.(
    value & opt_all string []
    & info [ "public-key"; "k" ] ~docv:"KEY"
        ~doc:
          "Trusted public key: a PEM file, or the base64 of the 32 raw bytes \
           (repeatable).")

type conn = {
  oci : string;
  plain_http : bool;
  username : string option;
  password_env : string option;
  token_env : string option;
  ca_file : string option;
  timeout : float;
}

let conn_term =
  Term.(
    const (fun oci plain_http username password_env token_env ca_file timeout ->
        { oci; plain_http; username; password_env; token_env; ca_file; timeout })
    $ oci_arg $ plain_http_arg $ username_arg $ password_env_arg $ token_env_arg
    $ ca_file_arg $ timeout_arg)

let env_secret var =
  match Sys.getenv_opt var with
  | None | Some "" -> Common.usage "environment variable %s is not set" var
  | Some v ->
      if String.exists (fun c -> c = '\r' || c = '\n') v then
        Common.usage "environment variable %s must not contain line breaks" var;
      v

let credentials c =
  match (c.username, c.password_env, c.token_env) with
  | None, None, None -> S.Registry.Anonymous
  | Some u, Some v, None -> S.Registry.Basic { username = u; password = env_secret v }
  | None, None, Some v -> S.Registry.Bearer (env_secret v)
  | Some _, None, None -> Common.usage "--username needs --password-env"
  | None, Some _, None -> Common.usage "--password-env needs --username"
  | _, _, Some _ ->
      Common.usage "--token-env cannot be combined with --username/--password-env"

let parse_ref s =
  match S.Oci_ref.parse s with Ok r -> r | Error e -> Common.usage "%s" e

let connect c =
  let r = parse_ref c.oci in
  let creds = credentials c in
  if c.timeout <= 0. then Common.usage "--timeout must be positive";
  let ctx =
    match c.ca_file with
    | None -> None
    | Some f -> (
        match Lwt_main.run (Haltsql_cloud.Http.ctx_of_ca_file f) with
        | Ok ctx -> Some ctx
        | Error e -> Common.usage "%s" e)
  in
  match
    S.Registry.create ?ctx ~timeout:c.timeout ~plain_http:c.plain_http ~credentials:creds
      r
  with
  | Ok reg -> (r, reg)
  | Error e -> Common.usage "%s" e

let load_public_key spec =
  let r =
    if Sys.file_exists spec then B.Key.public_of_file spec
    else
      match B.Key.public_of_string spec with
      | Ok k -> Ok k
      | Error _ -> Error (Printf.sprintf "public key file not found: %s" spec)
  in
  match r with Ok k -> k | Error e -> Common.usage "%s" e

let read_or_usage ~max ~what path =
  match B.read_file ~max_bytes:max ~what path with
  | Ok s -> s
  | Error e -> Common.usage "%s" (B.error_to_string e)

(* ------------------------------------------------------------------ push *)

let push ~conn ~bundle ~signature ~public_keys ~json =
  run ~json (fun () ->
      let keys = List.map load_public_key public_keys in
      let bytes = read_or_usage ~max:B.default_max_bytes ~what:"bundle" bundle in
      let sig_path = Option.value signature ~default:(B.signature_path bundle) in
      let sig_text =
        read_or_usage ~max:B.max_signature_bytes ~what:"signature file" sig_path
      in
      let sigs =
        match B.signatures_of_string sig_text with
        | Ok l -> l
        | Error e -> fail Common.exit_denied "%s: %s" sig_path (B.error_to_string e)
      in
      (* Never publish something that does not load or (with keys) verify. *)
      let t =
        match B.parse_unverified bytes with
        | Ok t -> t
        | Error e -> fail Common.exit_denied "refusing to push: %s" (B.error_to_string e)
      in
      let signer =
        match keys with
        | [] -> None
        | _ -> (
            match B.verify_signatures keys bytes sigs with
            | Ok k -> Some (B.Key.keyid k)
            | Error e ->
                fail Common.exit_denied "refusing to push: %s" (B.error_to_string e))
      in
      let r, reg = connect conn in
      let title = Filename.basename bundle in
      match
        Lwt_main.run
          (S.Oci_artifact.push ~title
             ~annotations:(S.Oci_artifact.annotations_of_bundle t)
             reg ~bundle:bytes ~signature:sig_text)
      with
      | Error e -> fetch_fail e
      | Ok digest ->
          let pushed = r.registry ^ "/" ^ r.repository in
          if json then
            Common.print_json
              (`Assoc
                 ([
                    ("ok", `Bool true);
                    ("reference", `String (S.Oci_ref.to_string r));
                    ("digest", `String digest);
                    ("pinned", `String (pushed ^ "@" ^ digest));
                    ("bundle", `String (t.metadata.name ^ "@" ^ t.metadata.version));
                    ("bundle_digest", `String t.digest);
                  ]
                 @
                 match signer with
                 | Some k -> [ ("verified_keyid", `String k) ]
                 | None -> []))
          else
            Printf.printf "pushed %s@%s (%s) to %s\npinned %s@%s\n" t.metadata.name
              t.metadata.version t.digest (S.Oci_ref.to_string r) pushed digest;
          0)

let push_cmd =
  let bundle = Arg.(required & pos 0 (some string) None & info [] ~docv:"BUNDLE") in
  let signature =
    Arg.(
      value
      & opt (some string) None
      & info [ "signature" ] ~docv:"FILE" ~doc:"Signature file (default: BUNDLE.sig).")
  in
  let doc = "Publish a signed bundle to an OCI registry." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Validates the bundle and its signature file (and, with $(b,--public-key), \
         checks the signature), then uploads both as one OCI artifact (artifactType \
         application/vnd.haltsql.bundle.v1) and tags it. The same bundle always produces \
         the same manifest digest. Prints the digest-pinned reference to deploy.";
    ]
    @ man_examples
        [
          "  haltsql bundle push --oci ghcr.io/acme/haltsql-policies:1.4.0 \\";
          "      dist/prod.haltsqlbundle --public-key keys/policy-signing.pub \\";
          "      --username \"$GITHUB_ACTOR\" --password-env GITHUB_TOKEN";
        ]
  in
  Cmd.v
    (Cmd.info "push" ~doc ~man ~exits)
    Term.(
      const (fun conn bundle signature public_keys json ->
          push ~conn ~bundle ~signature ~public_keys ~json)
      $ conn_term $ bundle $ signature $ public_keys_arg $ json_arg)

(* ------------------------------------------------------------------ pull *)

let pull ~conn ~output ~public_keys ~name_prefix ~json =
  run ~json (fun () ->
      if public_keys = [] then Common.usage "pull: at least one --public-key is required";
      let keys = List.map load_public_key public_keys in
      let r, reg = connect conn in
      match Lwt_main.run (S.Oci_artifact.pull reg) with
      | Error e -> fetch_fail e
      | Ok p -> (
          let verified =
            match B.signatures_of_string p.signature with
            | Error e -> Error e
            | Ok sigs -> (
                match B.verify_signatures keys p.bundle sigs with
                | Error e -> Error e
                | Ok key -> (
                    match B.parse_unverified ?name_prefix p.bundle with
                    | Ok t -> Ok (t, key)
                    | Error e -> Error e))
          in
          match verified with
          | Error e ->
              fail Common.exit_denied "%s: %s" (S.Oci_ref.to_string r)
                (B.error_to_string e)
          | Ok (t, key) ->
              let write path contents =
                (try Common.mkdir_p (Filename.dirname path)
                 with Unix.Unix_error (e, _, _) ->
                   Common.usage "cannot create %s: %s" (Filename.dirname path)
                     (Unix.error_message e));
                match S.Cache.write_atomic ~perm:0o644 path contents with
                | Ok () -> ()
                | Error e -> Common.usage "%s" e
              in
              (* signature first, so a reader never sees a new bundle with an old signature *)
              write (B.signature_path output) p.signature;
              write output p.bundle;
              if json then
                Common.print_json
                  (`Assoc
                     [
                       ("ok", `Bool true);
                       ("output", `String output);
                       ("signature", `String (B.signature_path output));
                       ("manifest_digest", `String p.manifest_digest);
                       ("bundle", `String (t.metadata.name ^ "@" ^ t.metadata.version));
                       ("bundle_digest", `String t.digest);
                       ("keyid", `String (B.Key.keyid key));
                       ("policies", `Int (List.length t.policies));
                     ])
              else
                Printf.printf
                  "OK %s@%s from %s@%s: %d policies, signed by %s\nwrote %s and %s\n"
                  t.metadata.name t.metadata.version
                  (r.registry ^ "/" ^ r.repository)
                  p.manifest_digest (List.length t.policies) (B.Key.keyid key) output
                  (B.signature_path output);
              0))

let pull_cmd =
  let output =
    Arg.(
      required
      & opt (some string) None
      & info [ "o"; "output" ] ~docv:"FILE"
          ~doc:"Bundle file to write; the signature goes to FILE.sig.")
  in
  let name_prefix =
    Arg.(
      value
      & opt (some string) None
      & info [ "name-prefix" ] ~docv:"PREFIX"
          ~doc:"Check that the policies load with this prefix, as the server would.")
  in
  let doc = "Download a signed bundle from an OCI registry and verify it." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Resolves the reference, verifies the manifest and both blobs against their \
         digests, then verifies the bundle signature with the trusted keys and loads \
         every policy. Nothing is written unless all checks pass. Artifacts pushed with \
         $(b,oras push --artifact-type application/vnd.haltsql.bundle.v1) are accepted.";
    ]
    @ man_examples
        [
          "  haltsql bundle pull --oci ghcr.io/acme/haltsql-policies@sha256:<digest> \\";
          "      -o /etc/haltsql/bundles/prod.haltsqlbundle --public-key \
           policy-signing.pub";
        ]
  in
  Cmd.v
    (Cmd.info "pull" ~doc ~man ~exits)
    Term.(
      const (fun conn output public_keys name_prefix json ->
          pull ~conn ~output ~public_keys ~name_prefix ~json)
      $ conn_term $ output $ public_keys_arg $ name_prefix $ json_arg)

let cmds = [ push_cmd; pull_cmd ]
