(* haltsql bundle keygen | build | sign | verify | inspect.

   [cmd] is the [bundle] command group (register it in main.ml). Exit codes: 0 ok,
   1 verification or validation failure, 2 usage or load error. *)

open Cmdliner
module B = Haltsql_bundle

let exits =
  [
    Cmd.Exit.info 0 ~doc:"on success.";
    Cmd.Exit.info 1 ~doc:"when a bundle or signature fails verification or validation.";
    Cmd.Exit.info 2 ~doc:"on usage errors or when an input file cannot be loaded.";
  ]

let man_examples ex =
  `S Manpage.s_examples
  :: List.concat_map (fun e -> [ `Pre (Manpage.escape e); `Noblank ]) ex

let json_arg = Arg.(value & flag & info [ "json" ] ~doc:"Machine-readable JSON output.")

exception Failed of string
(** A verification/validation failure: printed to stderr, exit 1. *)

let fail fmt = Printf.ksprintf (fun s -> raise (Failed s)) fmt

let run f =
  Common.run (fun () ->
      match f () with
      | code -> code
      | exception Failed msg ->
          prerr_endline ("haltsql: " ^ msg);
          Common.exit_denied)

let write_atomic ?(perm = 0o644) path contents =
  let dir = Filename.dirname path in
  (try Common.mkdir_p dir
   with Unix.Unix_error (e, _, _) ->
     Common.usage "cannot create %s: %s" dir (Unix.error_message e));
  let tmp =
    Filename.concat dir
      (Printf.sprintf ".%s.tmp%d" (Filename.basename path) (Unix.getpid ()))
  in
  match
    let fd =
      Unix.openfile tmp [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL; Unix.O_CLOEXEC ] perm
    in
    Fun.protect
      ~finally:(fun () -> Unix.close fd)
      (fun () ->
        let b = Bytes.of_string contents in
        let n = Bytes.length b in
        let rec go off = if off < n then go (off + Unix.write fd b off (n - off)) in
        go 0;
        Unix.fchmod fd perm);
    Unix.rename tmp path
  with
  | () -> ()
  | exception Unix.Unix_error (e, _, _) ->
      (try Unix.unlink tmp with Unix.Unix_error _ -> ());
      Common.usage "cannot write %s: %s" path (Unix.error_message e)

let load_public_key spec =
  (* A file path, or inline base64 of the 32 raw bytes / PEM. *)
  let r =
    if Sys.file_exists spec then B.Key.public_of_file spec
    else
      match B.Key.public_of_string spec with
      | Ok k -> Ok k
      | Error _ -> Error (Printf.sprintf "public key file not found: %s" spec)
  in
  match r with Ok k -> k | Error e -> Common.usage "%s" e

let load_secret_key ~key ~key_env =
  match (key, key_env) with
  | Some _, Some _ -> Common.usage "--key and --key-env are mutually exclusive"
  | None, None -> Common.usage "a signing key is required (--key FILE or --key-env VAR)"
  | Some f, None -> (
      match B.Key.secret_of_file f with Ok k -> k | Error e -> Common.usage "%s" e)
  | None, Some var -> (
      match Sys.getenv_opt var with
      | None | Some "" -> Common.usage "environment variable %s is not set" var
      | Some pem -> (
          match B.Key.secret_of_string pem with
          | Ok k -> k
          | Error e -> Common.usage "%s (from $%s)" e var))

let read_bundle_or_fail path =
  match B.read_file ~max_bytes:B.default_max_bytes ~what:"bundle" path with
  | Ok s -> s
  | Error (B.Io _ as e) -> Common.usage "%s" (B.error_to_string e)
  | Error e -> fail "%s" (B.error_to_string e)

let policy_summary (p : Haltsql.Policy.t) : Yojson.Safe.t =
  `Assoc
    [
      ("name", `String p.name);
      ("version", `String p.version);
      ("mode", `String (Common.mode_to_string p.mode));
      ("tables", `Int (List.length p.tables));
    ]

let bundle_json (t : B.t) : Yojson.Safe.t =
  let opt k = function Some v -> [ (k, `String v) ] | None -> [] in
  `Assoc
    [
      ( "metadata",
        `Assoc
          ([ ("name", `String t.metadata.name); ("version", `String t.metadata.version) ]
          @ opt "created_by" t.metadata.created_by
          @ opt "source_url" t.metadata.source.url
          @ opt "source_commit" t.metadata.source.commit) );
      ("digest", `String t.digest);
      ("policies", `List (List.map policy_summary t.policies));
      ( "catalogs",
        `List
          (List.map
             (fun (n, (c : Haltsql.Catalog.t)) ->
               `Assoc [ ("name", `String n); ("tables", `Int (List.length c.tables)) ])
             t.catalogs) );
    ]

(* ---------------------------------------------------------------- keygen *)

let keygen ~output ~force ~json =
  run (fun () ->
      let pub_path = output ^ ".pub" in
      if (not force) && (Sys.file_exists output || Sys.file_exists pub_path) then
        Common.usage "%s or %s already exists (use --force to overwrite)" output pub_path;
      let sk = B.Key.generate () in
      let pk = B.Key.public_of_secret sk in
      write_atomic ~perm:0o600 output (B.Key.secret_to_pem sk);
      write_atomic ~perm:0o644 pub_path (B.Key.public_to_pem pk);
      if json then
        Common.print_json
          (`Assoc
             [
               ("private_key", `String output);
               ("public_key", `String pub_path);
               ("keyid", `String (B.Key.keyid pk));
               ("public_key_base64", `String (B.Key.public_to_base64 pk));
             ])
      else
        Printf.printf "wrote %s (private, mode 0600) and %s\nkeyid %s\n" output pub_path
          (B.Key.keyid pk);
      0)

let keygen_cmd =
  let output =
    Arg.(
      required
      & opt (some string) None
      & info [ "o"; "output" ] ~docv:"FILE"
          ~doc:"Private key file to write (mode 0600); the public key goes to FILE.pub.")
  in
  let force =
    Arg.(value & flag & info [ "force" ] ~doc:"Overwrite existing key files.")
  in
  let doc = "Generate an Ed25519 bundle signing key pair." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Writes a PKCS#8 PEM private key (mode 0600) and its PEM public key. Keys made \
         with $(b,openssl genpkey -algorithm ed25519) are accepted as well. Keep the \
         private key in a secret store; distribute only the .pub file.";
    ]
    @ man_examples [ "  haltsql bundle keygen -o keys/policy-signing.key" ]
  in
  Cmd.v
    (Cmd.info "keygen" ~doc ~man ~exits)
    Term.(
      const (fun output force json -> keygen ~output ~force ~json)
      $ output $ force $ json_arg)

(* ----------------------------------------------------------------- build *)

let catalog_name_of_path path =
  let base = Filename.basename path in
  match Filename.chop_suffix_opt ~suffix:".json" base with
  | Some s -> s
  | None -> Filename.remove_extension base

let load_catalog spec =
  let name, path =
    match String.index_opt spec '=' with
    | Some i when i > 0 ->
        (String.sub spec 0 i, String.sub spec (i + 1) (String.length spec - i - 1))
    | _ -> (catalog_name_of_path spec, spec)
  in
  if not (Sys.file_exists path) then Common.usage "catalog file not found: %s" path;
  match Haltsql.Catalog_load.of_file path with
  | Ok c -> (name, c)
  | Error errs ->
      Common.usage "cannot load catalog:\n%s" (Common.errors_to_string ~file:path errs)

let build ~policies ~catalogs ~name ~version ~created_by ~source_url ~source_commit
    ~output ~json =
  run (fun () ->
      if policies = [] then Common.usage "build: at least one POLICY file is required";
      let ps = List.map Common.load_policy policies in
      let cs =
        List.sort
          (fun (a, _) (b, _) -> String.compare a b)
          (List.map load_catalog catalogs)
      in
      let created_by =
        match created_by with
        | Some "" -> None
        | Some c -> Some c
        | None -> Some ("haltsql/" ^ Haltsql.version)
      in
      let metadata =
        {
          B.name;
          version;
          created_by;
          source = { url = source_url; commit = source_commit };
        }
      in
      match B.build metadata ~policies:ps ~catalogs:cs with
      | Error e -> Common.usage "%s" (B.error_to_string e)
      | Ok bytes -> (
          write_atomic output bytes;
          match B.parse_unverified bytes with
          | Error e -> fail "%s" (B.error_to_string e)
          | Ok t ->
              if json then
                Common.print_json
                  (`Assoc
                     [
                       ("output", `String output);
                       ("bytes", `Int (String.length bytes));
                       ("bundle", bundle_json t);
                     ])
              else
                Printf.printf "wrote %s: %d policies, %d catalogs, %s\n" output
                  (List.length t.policies) (List.length t.catalogs) t.digest;
              0))

let build_cmd =
  let policies = Arg.(value & pos_all string [] & info [] ~docv:"POLICY") in
  let catalogs =
    Arg.(
      value & opt_all string []
      & info [ "catalog" ] ~docv:"[NAME=]FILE"
          ~doc:
            "Also ship this catalog snapshot (repeatable). NAME defaults to the file \
             name without its .json extension.")
  in
  let name_a =
    Arg.(
      required
      & opt (some string) None
      & info [ "name" ] ~docv:"NAME" ~doc:"Bundle name (letters, digits, _ - .).")
  in
  let version_a =
    Arg.(
      required
      & opt (some string) None
      & info [ "bundle-version" ] ~docv:"VERSION"
          ~doc:"Bundle version, e.g. 2026.11.07 or a git tag.")
  in
  let created_by =
    Arg.(
      value
      & opt (some string) None
      & info [ "created-by" ] ~docv:"TEXT"
          ~doc:"Recorded builder (default: haltsql/VERSION; empty to omit).")
  in
  let source_url =
    Arg.(
      value
      & opt (some string) None
      & info [ "source-url" ] ~docv:"URL" ~doc:"Source repository URL to record.")
  in
  let source_commit =
    Arg.(
      value
      & opt (some string) None
      & info [ "source-commit" ] ~docv:"SHA" ~doc:"Source git commit to record (hex).")
  in
  let output =
    Arg.(
      required
      & opt (some string) None
      & info [ "o"; "output" ] ~docv:"FILE" ~doc:"Bundle file to write (.haltsqlbundle).")
  in
  let doc = "Build a policy bundle from policy files." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Loads and validates every policy (and catalog), then writes one canonical JSON \
         document with a SHA-256 digest. The output is deterministic: the same inputs \
         produce byte-identical bundles. Sign it with $(b,haltsql bundle sign).";
    ]
    @ man_examples
        [
          "  haltsql bundle build policies/*.yaml --name prod --bundle-version 1.4.0 \\";
          "      --source-url https://github.com/acme/policies --source-commit \
           $GITHUB_SHA \\";
          "      -o dist/prod.haltsqlbundle";
        ]
  in
  Cmd.v
    (Cmd.info "build" ~doc ~man ~exits)
    Term.(
      const
        (fun
          policies
          catalogs
          name
          version
          created_by
          source_url
          source_commit
          output
          json
        ->
          build ~policies ~catalogs ~name ~version ~created_by ~source_url ~source_commit
            ~output ~json)
      $ policies $ catalogs $ name_a $ version_a $ created_by $ source_url $ source_commit
      $ output $ json_arg)

(* ------------------------------------------------------------------ sign *)

let key_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "key" ] ~docv:"FILE" ~doc:"PEM private key file (must be mode 0600).")

let key_env_arg =
  Arg.(
    value
    & opt (some string) None
    & info [ "key-env" ] ~docv:"VAR"
        ~doc:"Read the PEM private key from environment variable VAR (for CI secrets).")

let signature_arg ~doc =
  Arg.(value & opt (some string) None & info [ "signature" ] ~docv:"FILE" ~doc)

let sign ~bundle ~key ~key_env ~signature ~append ~json =
  run (fun () ->
      let sk = load_secret_key ~key ~key_env in
      let bytes = read_bundle_or_fail bundle in
      (* Never sign something that does not load. *)
      (match B.parse_unverified bytes with
      | Ok _ -> ()
      | Error e -> fail "refusing to sign: %s" (B.error_to_string e));
      let sig_path = Option.value signature ~default:(B.signature_path bundle) in
      let s = B.sign sk bytes in
      let existing =
        if append && Sys.file_exists sig_path then
          match
            B.read_file ~max_bytes:B.max_signature_bytes ~what:"signature file" sig_path
          with
          | Error e -> Common.usage "%s" (B.error_to_string e)
          | Ok text -> (
              match B.signatures_of_string text with
              | Ok l -> List.filter (fun (x : B.signature) -> x.keyid <> s.keyid) l
              | Error e -> fail "%s" (B.error_to_string e))
        else []
      in
      let all = existing @ [ s ] in
      if List.length all > 16 then fail "too many signatures (at most 16)";
      write_atomic sig_path (B.signatures_to_string all);
      if json then
        Common.print_json
          (`Assoc
             [
               ("signature", `String sig_path);
               ("keyid", `String s.keyid);
               ("signatures", `Int (List.length all));
             ])
      else Printf.printf "wrote %s (keyid %s)\n" sig_path s.keyid;
      0)

let sign_cmd =
  let bundle = Arg.(required & pos 0 (some string) None & info [] ~docv:"BUNDLE") in
  let append =
    Arg.(
      value & flag
      & info [ "append" ]
          ~doc:
            "Add this signature to an existing signature file instead of replacing it \
             (useful while rotating keys).")
  in
  let doc = "Sign a policy bundle (detached Ed25519 signature)." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Validates the bundle, then writes BUNDLE.sig (or $(b,--signature)). The \
         signature covers the exact bundle bytes.";
    ]
    @ man_examples
        [
          "  haltsql bundle sign dist/prod.haltsqlbundle --key keys/policy-signing.key";
          "  HALTSQL_SIGNING_KEY=\"$(cat key.pem)\" haltsql bundle sign b.haltsqlbundle \
           --key-env HALTSQL_SIGNING_KEY";
          "  haltsql bundle sign b.haltsqlbundle --key new.key --append";
        ]
  in
  Cmd.v
    (Cmd.info "sign" ~doc ~man ~exits)
    Term.(
      const (fun bundle key key_env signature append json ->
          sign ~bundle ~key ~key_env ~signature ~append ~json)
      $ bundle $ key_arg $ key_env_arg
      $ signature_arg ~doc:"Signature file to write (default: BUNDLE.sig)."
      $ append $ json_arg)

(* ---------------------------------------------------------------- verify *)

let public_keys_arg =
  Arg.(
    value & opt_all string []
    & info [ "public-key"; "k" ] ~docv:"KEY"
        ~doc:
          "Trusted public key: a PEM file, or the base64 of the 32 raw bytes \
           (repeatable; any one may verify, which supports key rotation).")

let verify ~bundle ~public_keys ~signature ~name_prefix ~json =
  run (fun () ->
      if public_keys = [] then
        Common.usage "verify: at least one --public-key is required";
      let keys = List.map load_public_key public_keys in
      match B.load_verified_bundle ?name_prefix ?signature_file:signature bundle keys with
      | Ok (t, key) ->
          if json then
            Common.print_json
              (`Assoc
                 [
                   ("ok", `Bool true);
                   ("keyid", `String (B.Key.keyid key));
                   ("bundle", bundle_json t);
                 ])
          else
            Printf.printf "OK %s %s@%s: %d policies, signed by %s\n" bundle
              t.metadata.name t.metadata.version (List.length t.policies)
              (B.Key.keyid key);
          0
      | Error e ->
          if json then
            Common.print_json
              (`Assoc [ ("ok", `Bool false); ("error", `String (B.error_to_string e)) ]);
          fail "%s: %s" bundle (B.error_to_string e))

let verify_cmd =
  let bundle = Arg.(required & pos 0 (some string) None & info [] ~docv:"BUNDLE") in
  let name_prefix =
    Arg.(
      value
      & opt (some string) None
      & info [ "name-prefix" ] ~docv:"PREFIX"
          ~doc:"Load the policies with this prefix, as the server would.")
  in
  let doc = "Verify a bundle's signature, digest and policies." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Checks, in order: size limits, the signature against the trusted keys, \
         canonical form, the digest, the document structure, and finally that every \
         policy and catalog loads. Exits 1 on any failure.";
    ]
    @ man_examples
        [
          "  haltsql bundle verify prod.haltsqlbundle --public-key \
           keys/policy-signing.key.pub";
          "  haltsql bundle verify prod.haltsqlbundle -k old.pub -k new.pub --json";
        ]
  in
  Cmd.v
    (Cmd.info "verify" ~doc ~man ~exits)
    Term.(
      const (fun bundle public_keys signature name_prefix json ->
          verify ~bundle ~public_keys ~signature ~name_prefix ~json)
      $ bundle $ public_keys_arg
      $ signature_arg ~doc:"Signature file (default: BUNDLE.sig)."
      $ name_prefix $ json_arg)

(* --------------------------------------------------------------- inspect *)

let inspect ~bundle ~public_keys ~signature ~json =
  run (fun () ->
      let keys = List.map load_public_key public_keys in
      let bytes = read_bundle_or_fail bundle in
      let t =
        match B.parse_unverified bytes with
        | Ok t -> t
        | Error e -> fail "%s: %s" bundle (B.error_to_string e)
      in
      let sig_path = Option.value signature ~default:(B.signature_path bundle) in
      let sigs =
        if Sys.file_exists sig_path then
          match
            B.read_file ~max_bytes:B.max_signature_bytes ~what:"signature file" sig_path
          with
          | Ok text -> B.signatures_of_string text
          | Error e -> Error e
        else Ok []
      in
      let keyids =
        match sigs with
        | Ok l -> List.map (fun (s : B.signature) -> s.keyid) l
        | Error _ -> []
      in
      let verified =
        match (keys, sigs) with
        | [], _ -> `Not_checked
        | _, Error e -> `Failed (B.error_to_string e)
        | _, Ok [] -> `Failed "no signature file"
        | _, Ok l -> (
            match B.verify_signatures keys bytes l with
            | Ok k -> `Verified (B.Key.keyid k)
            | Error e -> `Failed (B.error_to_string e))
      in
      let status =
        match verified with
        | `Not_checked -> "UNVERIFIED (no --public-key given)"
        | `Verified k -> "verified (" ^ k ^ ")"
        | `Failed e -> "FAILED: " ^ e
      in
      if json then
        Common.print_json
          (`Assoc
             [
               ("bundle", bundle_json t);
               ("bytes", `Int (String.length bytes));
               ( "signature_file",
                 if Sys.file_exists sig_path then `String sig_path else `Null );
               ("signed_by", `List (List.map (fun k -> `String k) keyids));
               ( "signature_status",
                 `String
                   (match verified with
                   | `Not_checked -> "unverified"
                   | `Verified _ -> "verified"
                   | `Failed _ -> "failed") );
             ])
      else begin
        Printf.printf "bundle   %s@%s\n" t.metadata.name t.metadata.version;
        Printf.printf "digest   %s\n" t.digest;
        Option.iter (Printf.printf "created  %s\n") t.metadata.created_by;
        Option.iter (Printf.printf "source   %s\n") t.metadata.source.url;
        Option.iter (Printf.printf "commit   %s\n") t.metadata.source.commit;
        Printf.printf "policies %d\n" (List.length t.policies);
        List.iter
          (fun (p : Haltsql.Policy.t) ->
            Printf.printf "  %-32s %s  %s  %d tables\n" p.name p.version
              (Common.mode_to_string p.mode)
              (List.length p.tables))
          t.policies;
        if t.catalogs <> [] then begin
          Printf.printf "catalogs %d\n" (List.length t.catalogs);
          List.iter
            (fun (n, (c : Haltsql.Catalog.t)) ->
              Printf.printf "  %-32s %d tables\n" n (List.length c.tables))
            t.catalogs
        end;
        Printf.printf "signed   %s\n"
          (if keyids = [] then "(no signature)" else String.concat ", " keyids);
        Printf.printf "status   %s\n" status
      end;
      match verified with `Failed e -> fail "%s" e | _ -> 0)

let inspect_cmd =
  let bundle = Arg.(required & pos 0 (some string) None & info [] ~docv:"BUNDLE") in
  let doc = "Show a bundle's metadata, policies and signatures." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Checks structure and digest and lists the contents. Without $(b,--public-key) \
         the signature is NOT checked and the output says UNVERIFIED; with keys, exits 1 \
         unless a trusted signature verifies.";
    ]
    @ man_examples
        [
          "  haltsql bundle inspect prod.haltsqlbundle";
          "  haltsql bundle inspect prod.haltsqlbundle -k signing.pub --json";
        ]
  in
  Cmd.v
    (Cmd.info "inspect" ~doc ~man ~exits)
    Term.(
      const (fun bundle public_keys signature json ->
          inspect ~bundle ~public_keys ~signature ~json)
      $ bundle $ public_keys_arg
      $ signature_arg ~doc:"Signature file (default: BUNDLE.sig)."
      $ json_arg)

let cmd =
  let doc = "Build, sign and verify signed policy bundles." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "A bundle packages validated policies (and catalog snapshots) into one \
         canonical, digest-protected file with a detached Ed25519 signature. The server \
         loads bundles listed under $(b,policies) in its config and refuses any bundle \
         whose signature does not verify. See docs/policy-bundles.md.";
    ]
    @ man_examples
        [
          "  haltsql bundle keygen -o signing.key";
          "  haltsql bundle build policies/*.yaml --name prod --bundle-version 1.0.0 -o \
           prod.haltsqlbundle";
          "  haltsql bundle sign prod.haltsqlbundle --key signing.key";
          "  haltsql bundle verify prod.haltsqlbundle --public-key signing.key.pub";
        ]
  in
  Cmd.group
    (Cmd.info "bundle" ~doc ~man ~exits)
    ([ keygen_cmd; build_cmd; sign_cmd; verify_cmd; inspect_cmd ] @ Cmd_bundle_oci.cmds)
