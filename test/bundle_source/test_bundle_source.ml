(* Tests for remote bundle sources (lib/bundle_source) and the
   [haltsql bundle push|pull] CLI. The integration tests run against real
   servers in Docker; see docker_env.ml. *)

open Lwt.Infix
module B = Haltsql_bundle
module S = Haltsql_bundle_source
module Config = Haltsql_load.Config
module D = Docker_env

let examples = "../../examples"
let ok_or_fail what = function Ok x -> x | Error e -> Alcotest.failf "%s: %s" what e

let ok_b what = function
  | Ok x -> x
  | Error e -> Alcotest.failf "%s: %s" what (B.error_to_string e)

let ok_f what = function
  | Ok x -> x
  | Error e -> Alcotest.failf "%s: %s" what (S.Fetch_error.to_string e)

let ok_s what = function
  | Ok x -> x
  | Error e -> Alcotest.failf "%s: %s" what (S.error_to_string e)

(* ------------------------------------------------------------- fixtures *)

let policy =
  lazy
    (match
       Haltsql.Policy_load.of_file (Filename.concat examples "policies/saas.yaml")
     with
    | Ok p -> p
    | Error _ -> Alcotest.fail "cannot load examples/policies/saas.yaml")

let build ?(name = "prod-policies") ?(created_by = "test") version =
  ok_b "build"
    (B.build
       {
         B.name;
         version;
         created_by = Some created_by;
         source = { url = None; commit = None };
       }
       ~policies:[ Lazy.force policy ]
       ~catalogs:[])

let signing_key = lazy (B.Key.generate ())
let untrusted_key = lazy (B.Key.generate ())
let pub k = B.Key.public_of_secret (Lazy.force k)

let sign ?(key = signing_key) bytes =
  B.signatures_to_string [ B.sign (Lazy.force key) bytes ]

let config_key k = Config.Key_base64 (B.Key.public_to_base64 (pub k))

let flip_byte s i =
  let b = Bytes.of_string s in
  Bytes.set b i (Char.chr (Char.code (Bytes.get b i) lxor 1));
  Bytes.to_string b

let tmp_dir name =
  let d =
    Filename.concat (Sys.getcwd ()) (Printf.sprintf "tmp-%s-%d" name (Unix.getpid ()))
  in
  let rm () = ignore (Sys.command (Filename.quote_command "rm" [ "-rf"; d ])) in
  rm ();
  D.mkdir_p d;
  at_exit rm;
  d

let source ?(keys = [ config_key signing_key ]) ?name_prefix ?cache_dir ?auth location =
  {
    Config.location;
    source_public_keys = keys;
    source_name_prefix = name_prefix;
    poll_interval_s = 60;
    cache_dir;
    source_auth = auth;
  }

let oci_location ?(plain_http = true) ref_ =
  let r = ok_or_fail "ref" (S.Oci_ref.parse ref_) in
  Config.Source_oci
    {
      oci_reference = ref_;
      oci_registry = r.registry;
      oci_repository = r.repository;
      oci_tag = r.tag;
      oci_digest = r.digest;
      oci_plain_http = plain_http;
    }

(* Records what on_update received. *)
type recorder = { mutable seen : S.update list; mutable refuse : string option }

let recorder () = { seen = []; refuse = None }

let on_update r (u : S.update) =
  match r.refuse with
  | Some m -> Lwt.return (Error m)
  | None ->
      r.seen <- u :: r.seen;
      Lwt.return (Ok ())

let current_version t =
  match S.current t with Some u -> Some u.bundle.metadata.version | None -> None

let check_current what t v = Alcotest.(check (option string)) what v (current_version t)

let expect_updated what = function
  | Ok (S.Updated u) -> u
  | Ok S.Unchanged -> Alcotest.failf "%s: expected an update, got Unchanged" what
  | Error e -> Alcotest.failf "%s: %s (%s)" what (S.error_to_string e) (S.error_code e)

let expect_unchanged what = function
  | Ok S.Unchanged -> ()
  | Ok (S.Updated u) ->
      Alcotest.failf "%s: unexpected update to %s" what u.bundle.metadata.version
  | Error e -> Alcotest.failf "%s: %s" what (S.error_to_string e)

let expect_error what code = function
  | Error e ->
      Alcotest.(check string)
        (what ^ " (" ^ S.error_to_string e ^ ")")
        code (S.error_code e)
  | Ok S.Unchanged -> Alcotest.failf "%s: expected %s, got Unchanged" what code
  | Ok (S.Updated u) ->
      Alcotest.failf "%s: expected %s, got update %s" what code u.bundle.metadata.version

let create ?allow_downgrade ?ca_file ?poll_interval ?aws_credentials cfg =
  ok_or_fail "create"
    (Lwt_main.run
       (S.create ?allow_downgrade ?ca_file ?poll_interval ?aws_credentials cfg))

let poll t r = Lwt_main.run (S.poll_once t ~on_update:(on_update r) ())

(* =============================================================== unit tests *)

let test_oci_ref () =
  let ok s = ok_or_fail s (S.Oci_ref.parse s) in
  let r = ok "ghcr.io/corp/haltsql-policies:prod" in
  Alcotest.(check string) "registry" "ghcr.io" r.registry;
  Alcotest.(check string) "repo" "corp/haltsql-policies" r.repository;
  Alcotest.(check (option string)) "tag" (Some "prod") r.tag;
  let d = "sha256:" ^ String.make 64 'a' in
  let r = ok ("localhost:5000/p@" ^ d) in
  Alcotest.(check string) "reference is the digest" d (S.Oci_ref.reference r);
  let r = ok ("127.0.0.1:15000/a/b:v1@" ^ d) in
  Alcotest.(check string) "digest wins" d (S.Oci_ref.reference r);
  Alcotest.(check bool) "loopback" true (S.Oci_ref.is_loopback r);
  let r6 = ok "[::1]:5000/p:v1" in
  Alcotest.(check bool) "ipv6 loopback" true (S.Oci_ref.is_loopback r6);
  Alcotest.(check string)
    "round trip"
    ("127.0.0.1:15000/a/b:v1@" ^ d)
    (S.Oci_ref.to_string r);
  List.iter
    (fun s ->
      match S.Oci_ref.parse s with
      | Ok _ -> Alcotest.failf "%S should be rejected" s
      | Error _ -> ())
    [
      "";
      "corp/policies:prod" (* no registry host: no implicit Docker Hub *);
      "policies:prod";
      "ghcr.io/Corp/p:prod";
      "ghcr.io/corp/p";
      "ghcr.io/corp/p@sha256:abc";
      "ghcr.io/corp/p@sha256:" ^ String.make 64 'A';
      "ghcr.io/corp/p:bad tag";
      "ghcr.io:99999/p:v1";
      "ghcr.io/corp/../p:v1";
    ];
  (match S.Oci_ref.base_url ~plain_http:true (ok "ghcr.io/corp/p:v1") with
  | Ok _ -> Alcotest.fail "plain HTTP to a remote registry must be refused"
  | Error _ -> ());
  Alcotest.(check string)
    "https by default" "https://ghcr.io"
    (ok_or_fail "base" (S.Oci_ref.base_url ~plain_http:false (ok "ghcr.io/corp/p:v1")));
  Alcotest.(check string)
    "loopback http" "http://localhost:5000"
    (ok_or_fail "base" (S.Oci_ref.base_url ~plain_http:true (ok "localhost:5000/p:v1")))

let test_www_auth () =
  let cs =
    S.Www_auth.parse
      {|Bearer realm="https://auth.example/token",service="registry.example",scope="repository:corp/p:pull,push"|}
  in
  (match cs with
  | [ c ] ->
      Alcotest.(check string) "scheme" "bearer" c.scheme;
      Alcotest.(check (option string))
        "realm" (Some "https://auth.example/token") (S.Www_auth.param c "realm");
      Alcotest.(check (option string))
        "service" (Some "registry.example")
        (S.Www_auth.param c "Service");
      Alcotest.(check (option string))
        "scope with comma" (Some "repository:corp/p:pull,push")
        (S.Www_auth.param c "scope")
  | _ -> Alcotest.failf "expected one challenge, got %d" (List.length cs));
  (match
     S.Www_auth.parse
       {|Basic realm="r\"q", Bearer realm="https://a/t", error="invalid_token"|}
   with
  | [ b; t ] ->
      Alcotest.(check string) "basic" "basic" b.scheme;
      Alcotest.(check (option string))
        "escaped quote" (Some {|r"q|}) (S.Www_auth.param b "realm");
      Alcotest.(check string) "bearer" "bearer" t.scheme;
      Alcotest.(check (option string))
        "error" (Some "invalid_token") (S.Www_auth.param t "error")
  | l -> Alcotest.failf "expected two challenges, got %d" (List.length l));
  (match S.Www_auth.parse "Negotiate abc==, Basic realm=x" with
  | [ n; b ] ->
      Alcotest.(check string) "token68 scheme" "negotiate" n.scheme;
      Alcotest.(check (option string))
        "token realm" (Some "x") (S.Www_auth.param b "realm")
  | l -> Alcotest.failf "token68: got %d challenges" (List.length l));
  List.iter
    (fun s -> ignore (S.Www_auth.parse s))
    [
      "";
      "\"";
      "Bearer realm=\"unterminated";
      ",,,";
      "=a";
      "Bearer ,=,";
      String.make 1000 '"';
    ]

let test_digest () =
  let d = S.Content_digest.sha256 "hello" in
  Alcotest.(check bool)
    "sha256 matches" true
    (S.Content_digest.matches ~expected:d "hello");
  Alcotest.(check bool)
    "other content" false
    (S.Content_digest.matches ~expected:d "hellO");
  let d5 = S.Content_digest.compute S.Content_digest.Sha512 "hello" in
  Alcotest.(check bool)
    "sha512 matches" true
    (S.Content_digest.matches ~expected:d5 "hello");
  Alcotest.(check bool)
    "upper-case hex refused" false
    (S.Content_digest.matches ~expected:(String.uppercase_ascii d) "hello");
  Alcotest.(check bool)
    "md5 refused" false
    (S.Content_digest.matches ~expected:"md5:5d41402abc4b2a76b9719d911017c592" "hello")

let test_versions () =
  let lt a b =
    Alcotest.(check bool) (a ^ " < " ^ b) true (S.compare_versions a b < 0);
    Alcotest.(check bool) (b ^ " > " ^ a) true (S.compare_versions b a > 0)
  in
  lt "1.9.0" "1.10.0";
  lt "1.4.0" "1.4.1";
  lt "1.4.0-rc.1" "1.4.0";
  lt "1.4.0-rc.1" "1.4.0-rc.2";
  lt "1.4.0" "1.4.0.1";
  lt "2026.11.07" "2026.11.08";
  lt "2026.11.07" "2027.01.01";
  lt "build-99" "build-100";
  lt "1.0.9" "1.0.10";
  lt "v1" "v2";
  Alcotest.(check int) "leading zeros" 0 (S.compare_versions "1.02" "1.2");
  Alcotest.(check int) "equal" 0 (S.compare_versions "1.4.0" "1.4.0");
  let md v : B.metadata =
    { name = "p"; version = v; created_by = None; source = { url = None; commit = None } }
  in
  let rb ?(allow = false) cur v =
    S.check_rollback ~allow_downgrade:allow ~current:cur (md v)
  in
  Alcotest.(check bool) "first bundle" true (Result.is_ok (rb None "0.1"));
  Alcotest.(check bool) "newer" true (Result.is_ok (rb (Some (md "1.0.0")) "1.0.1"));
  Alcotest.(check bool)
    "older refused" true
    (Result.is_error (rb (Some (md "1.0.1")) "1.0.0"));
  Alcotest.(check bool)
    "same version refused" true
    (Result.is_error (rb (Some (md "1.0.1")) "1.0.1"));
  Alcotest.(check bool)
    "allow_downgrade" true
    (Result.is_ok (rb ~allow:true (Some (md "2")) "1"));
  Alcotest.(check bool)
    "renamed refused" true
    (Result.is_error
       (S.check_rollback ~allow_downgrade:false
          ~current:(Some (md "1"))
          { (md "2") with name = "other" }))

let test_manifest () =
  let bundle = build "1.0.0" in
  let signature = sign bundle in
  let m =
    S.Oci_artifact.build_manifest ~title:"prod.haltsqlbundle" ~bundle ~signature ()
  in
  Alcotest.(check string)
    "deterministic" m
    (S.Oci_artifact.build_manifest ~title:"prod.haltsqlbundle" ~bundle ~signature ());
  let l = ok_or_fail "parse" (S.Oci_artifact.parse_manifest ~content_type:None m) in
  Alcotest.(check string)
    "bundle digest"
    (S.Content_digest.sha256 bundle)
    l.bundle_layer.digest;
  Alcotest.(check int) "bundle size" (String.length bundle) l.bundle_layer.size;
  Alcotest.(check (option string))
    "title" (Some "prod.haltsqlbundle") l.bundle_layer.title;
  Alcotest.(check (option string))
    "sig title" (Some "prod.haltsqlbundle.sig") l.signature_layer.title;
  let m_bad_title =
    S.Oci_artifact.build_manifest ~title:"../etc/passwd" ~bundle ~signature ()
  in
  let l2 =
    ok_or_fail "parse" (S.Oci_artifact.parse_manifest ~content_type:None m_bad_title)
  in
  Alcotest.(check (option string))
    "unsafe title replaced" (Some "bundle.haltsqlbundle") l2.bundle_layer.title;
  let j = Yojson.Safe.from_string m in
  let set k v =
    match j with `Assoc kvs -> `Assoc ((k, v) :: List.remove_assoc k kvs) | _ -> j
  in
  let layers =
    match j with
    | `Assoc kvs -> ( match List.assoc "layers" kvs with `List l -> l | _ -> [])
    | _ -> []
  in
  let refused what doc =
    match
      S.Oci_artifact.parse_manifest ~content_type:None (Yojson.Safe.to_string doc)
    with
    | Ok _ -> Alcotest.failf "%s must be refused" what
    | Error _ -> ()
  in
  refused "other artifact type" (set "artifactType" (`String "application/vnd.example"));
  refused "image index"
    (set "mediaType" (`String "application/vnd.oci.image.index.v1+json"));
  refused "schema 1" (set "schemaVersion" (`Int 1));
  refused "extra layer"
    (set "layers"
       (`List
          (layers
          @ [
              `Assoc
                [
                  ("mediaType", `String "application/octet-stream");
                  ("digest", `String (S.Content_digest.sha256 "x"));
                  ("size", `Int 1);
                ];
            ])));
  refused "missing signature layer" (set "layers" (`List [ List.hd layers ]));
  refused "duplicate bundle layer" (set "layers" (`List (List.hd layers :: layers)));
  let big =
    `Assoc
      [
        ("mediaType", `String S.Oci_artifact.bundle_media_type);
        ("digest", `String (S.Content_digest.sha256 "x"));
        ("size", `Int (B.default_max_bytes + 1));
      ]
  in
  refused "oversized bundle layer" (set "layers" (`List (big :: List.tl layers)));
  refused "not JSON" (`String "nope");
  (* oras 1.0 style: no artifactType, the type is the config media type *)
  let old_style =
    match j with
    | `Assoc kvs ->
        `Assoc
          (List.filter_map
             (fun (k, v) ->
               match k with
               | "artifactType" -> None
               | "config" ->
                   Some
                     ( k,
                       `Assoc
                         [
                           ("mediaType", `String S.Oci_artifact.artifact_type);
                           ("digest", `String (S.Content_digest.sha256 "{}"));
                           ("size", `Int 2);
                         ] )
               | _ -> Some (k, v))
             kvs)
    | _ -> j
  in
  ignore
    (ok_or_fail "oras 1.0 layout"
       (S.Oci_artifact.parse_manifest ~content_type:None
          (Yojson.Safe.to_string old_style)));
  (* media type from the Content-Type header when the manifest omits it *)
  let no_mt =
    match j with `Assoc kvs -> `Assoc (List.remove_assoc "mediaType" kvs) | _ -> j
  in
  ignore
    (ok_or_fail "content-type"
       (S.Oci_artifact.parse_manifest
          ~content_type:(Some "application/vnd.oci.image.manifest.v1+json; charset=utf-8")
          (Yojson.Safe.to_string no_mt)));
  refused "no media type at all" no_mt

let test_cache () =
  let dir = tmp_dir "cache" in
  let bundle = build "1.0.0" and signature = sign (build "1.0.0") in
  let src = "https://example.test/b.haltsqlbundle" in
  let d = S.Cache.dir_for ~cache_dir:dir ~source:src in
  Alcotest.(check bool) "empty" true (S.Cache.load ~dir:d ~source:src = Ok None);
  ok_or_fail "store"
    (S.Cache.store ~dir:d
       { source = src; bundle; signature; revision = Some "\"etag-1\"" });
  (match S.Cache.load ~dir:d ~source:src with
  | Ok (Some e) ->
      Alcotest.(check bool) "bundle" true (e.bundle = bundle);
      Alcotest.(check bool) "signature" true (e.signature = signature);
      Alcotest.(check (option string)) "revision" (Some "\"etag-1\"") e.revision
  | _ -> Alcotest.fail "cache entry not found");
  let st = Unix.stat d in
  Alcotest.(check int) "cache dir is private" 0o700 (st.st_perm land 0o777);
  Alcotest.(check bool)
    "other source" true
    (S.Cache.load ~dir:d ~source:"https://other.test/x" = Ok None);
  let bundle2 = build "1.1.0" in
  ok_or_fail "store 2"
    (S.Cache.store ~dir:d { source = src; bundle = bundle2; signature; revision = None });
  let files = Array.to_list (Sys.readdir d) |> List.sort compare in
  Alcotest.(check int) "old bundle removed" 3 (List.length files);
  (* tampering with the cached file is detected (name = content hash) *)
  let f = List.find (fun n -> String.ends_with ~suffix:".haltsqlbundle" n) files in
  D.write ~perm:0o600 (Filename.concat d f) (flip_byte bundle2 10);
  (match S.Cache.load ~dir:d ~source:src with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "tampered cache file must not load");
  D.write ~perm:0o600
    (Filename.concat d "state.json")
    "{\"format\":1,\"source\":\"x\",\"bundle\":\"../../etc/passwd\"}";
  (match S.Cache.load ~dir:d ~source:"x" with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "path traversal in the cache state must be refused");
  D.write ~perm:0o600 (Filename.concat d "state.json") "not json";
  match S.Cache.load ~dir:d ~source:src with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "corrupt state must be an error"

let test_verify () =
  let cfg =
    source ~name_prefix:"prod."
      (Config.Source_https "https://bundles.example/prod.haltsqlbundle")
  in
  let t = create cfg in
  let bundle = build "1.0.0" in
  let u = ok_s "verify" (S.verify t ~bundle ~signature:(sign bundle)) in
  Alcotest.(check (list string))
    "prefixed policy names"
    [ "prod." ^ (Lazy.force policy).name ]
    (List.map fst u.policies);
  Alcotest.(check string) "signer" (B.Key.keyid (pub signing_key)) u.signed_by;
  let fails what ~bundle ~signature code =
    match S.verify t ~bundle ~signature with
    | Ok _ -> Alcotest.failf "%s must fail" what
    | Error e -> Alcotest.(check string) what code (S.error_code e)
  in
  fails "untrusted key" ~bundle
    ~signature:(sign ~key:untrusted_key bundle)
    "bundle_source_signature";
  fails "flipped payload byte" ~bundle:(flip_byte bundle 40) ~signature:(sign bundle)
    "bundle_source_signature";
  fails "truncated"
    ~bundle:(String.sub bundle 0 (String.length bundle / 2))
    ~signature:(sign bundle) "bundle_source_signature";
  fails "garbage signature" ~bundle ~signature:"{}" "bundle_source_signature";
  fails "oversized"
    ~bundle:(String.make (B.default_max_bytes + 1) ' ')
    ~signature:(sign bundle) "bundle_source_invalid";
  (* config errors *)
  (match
     Lwt_main.run (S.create (source ~keys:[] (Config.Source_https "https://b.example/x")))
   with
  | Ok _ -> Alcotest.fail "a source without keys must be refused"
  | Error _ -> ());
  (match
     Lwt_main.run
       (S.create
          (source
             ~keys:[ Config.Key_base64 "bm9wZQ==" ]
             (Config.Source_https "https://b.example/x")))
   with
  | Ok _ -> Alcotest.fail "an invalid key must be refused"
  | Error _ -> ());
  match
    Lwt_main.run (S.create (source (Config.Source_https "http://bundles.example/x")))
  with
  | Ok _ -> Alcotest.fail "http to a non-loopback host must be refused"
  | Error _ -> ()

let test_config_decode () =
  (* The source config as the server decodes it. *)
  let pubfile = Filename.concat (tmp_dir "cfg") "k.pub" in
  D.write pubfile (B.Key.public_to_pem (pub signing_key));
  let doc =
    `Assoc
      [
        ("apiVersion", `String "haltsql.dev/v1");
        ("kind", `String "Config");
        ( "policies",
          `List
            [
              `Assoc
                [
                  ( "bundle_source",
                    `Assoc
                      [
                        ("oci", `String "127.0.0.1:15000/haltsql/policies:prod");
                        ("plain_http", `Bool true);
                      ] );
                  ("public_keys", `List [ `String pubfile ]);
                  ("poll_interval_s", `Int 10);
                ];
            ] );
      ]
  in
  match Config.of_json ~base_dir:(Sys.getcwd ()) doc with
  | Error errs ->
      Alcotest.failf "config: %s"
        (String.concat "; " (List.map Haltsql_core.Load_error.to_string errs))
  | Ok cfg -> (
      match cfg.bundle_sources with
      | [ b ] ->
          let t = create b in
          Alcotest.(check string)
            "source id" "oci:127.0.0.1:15000/haltsql/policies:prod" (S.source_id t)
      | _ -> Alcotest.fail "expected one bundle source")

(* ======================================================== integration tests *)

let docker_ready =
  lazy (match Lazy.force D.available with Ok () -> true | Error _ -> false)

let docker_case name f =
  Alcotest.test_case name `Slow (fun () ->
      match Lazy.force D.available with
      | Error reason ->
          Printf.printf "SKIP %s: %s\n%!" name reason;
          Alcotest.skip ()
      | Ok () -> f ())

let anon = Printf.sprintf "127.0.0.1:%d" D.port_anon
let cli = "./bundle_oci_cli.exe"

let run_cli ?(env = []) args =
  let out = Filename.temp_file "cli" ".out" in
  let envs =
    String.concat " " (List.map (fun (k, v) -> Filename.quote (k ^ "=" ^ v)) env)
  in
  let cmd =
    (if env = [] then "" else "env " ^ envs ^ " ")
    ^ Filename.quote_command cli args ~stdout:out ~stderr:out
  in
  let code = Sys.command cmd in
  let text = D.read_all out in
  Sys.remove out;
  (code, text)

let check_cli what expected (code, out) =
  if code <> expected then
    Alcotest.failf "%s: exit %d (expected %d): %s" what code expected out

(* Writes a bundle and its signature for the CLI. *)
let write_bundle dir name bundle signature =
  let p = Filename.concat dir name in
  D.write p bundle;
  D.write (p ^ ".sig") signature;
  p

let registry ?(plain_http = true) ?(credentials = S.Registry.Anonymous) ref_ =
  let r = ok_or_fail "ref" (S.Oci_ref.parse ref_) in
  ok_or_fail "registry" (S.Registry.create ~plain_http ~credentials r)

let push ?credentials ref_ ~bundle ~signature =
  ok_f ("push " ^ ref_)
    (Lwt_main.run
       (S.Oci_artifact.push ~title:"prod.haltsqlbundle" (registry ?credentials ref_)
          ~bundle ~signature))

let v1 = lazy (build "1.0.0")
let v2 = lazy (build "1.1.0")
let v3 = lazy (build "1.2.0")

let setup_registries =
  lazy
    (D.start_anon_registry ();
     D.start_basic_registry ();
     D.start_token_registry ())

let test_cli_push_pull () =
  Lazy.force setup_registries;
  let dir = tmp_dir "cli" in
  let pubf = Filename.concat dir "k.pub" in
  D.write pubf (B.Key.public_to_pem (pub signing_key));
  let b1 = write_bundle dir "prod.haltsqlbundle" (Lazy.force v1) (sign (Lazy.force v1)) in
  let ref_ = anon ^ "/haltsql/cli:prod" in
  check_cli "push" 0
    (run_cli
       [ "bundle"; "push"; "--oci"; ref_; "--plain-http"; b1; "--public-key"; pubf ]);
  let out = Filename.concat dir "out/pulled.haltsqlbundle" in
  check_cli "pull" 0
    (run_cli
       [
         "bundle";
         "pull";
         "--oci";
         ref_;
         "--plain-http";
         "-o";
         out;
         "--public-key";
         pubf;
         "--json";
       ]);
  Alcotest.(check bool) "pulled bundle bytes" true (D.read_all out = Lazy.force v1);
  Alcotest.(check bool)
    "pulled signature" true
    (D.read_all (out ^ ".sig") = sign (Lazy.force v1));
  (* the same bundle always gives the same manifest digest *)
  let code, o1 =
    run_cli [ "bundle"; "push"; "--oci"; ref_; "--plain-http"; b1; "--json" ]
  in
  check_cli "re-push" 0 (code, o1);
  let digest_of o =
    match Yojson.Safe.from_string o with
    | `Assoc kvs -> (
        match List.assoc_opt "digest" kvs with Some (`String d) -> d | _ -> "")
    | _ -> ""
  in
  let code, o2 =
    run_cli [ "bundle"; "push"; "--oci"; ref_; "--plain-http"; b1; "--json" ]
  in
  check_cli "re-push 2" 0 (code, o2);
  Alcotest.(check string) "deterministic manifest digest" (digest_of o1) (digest_of o2);
  (* pull by digest *)
  check_cli "pull by digest" 0
    (run_cli
       [
         "bundle";
         "pull";
         "--oci";
         anon ^ "/haltsql/cli@" ^ digest_of o1;
         "--plain-http";
         "-o";
         out;
         "-k";
         pubf;
       ]);
  (* refusals *)
  let bu =
    write_bundle dir "untrusted.haltsqlbundle" (Lazy.force v2)
      (sign ~key:untrusted_key (Lazy.force v2))
  in
  check_cli "push refuses a signature that does not verify" 1
    (run_cli
       [ "bundle"; "push"; "--oci"; ref_; "--plain-http"; bu; "--public-key"; pubf ]);
  check_cli "pushed untrusted (no key check)" 0
    (run_cli
       [ "bundle"; "push"; "--oci"; anon ^ "/haltsql/cli:untrusted"; "--plain-http"; bu ]);
  let out2 = Filename.concat dir "out/untrusted.haltsqlbundle" in
  check_cli "pull refuses an untrusted signature" 1
    (run_cli
       [
         "bundle";
         "pull";
         "--oci";
         anon ^ "/haltsql/cli:untrusted";
         "--plain-http";
         "-o";
         out2;
         "-k";
         pubf;
       ]);
  Alcotest.(check bool) "nothing written" false (Sys.file_exists out2);
  check_cli "pull needs keys" 2
    (run_cli [ "bundle"; "pull"; "--oci"; ref_; "--plain-http"; "-o"; out2 ]);
  check_cli "plain http to a remote registry" 2
    (run_cli
       [
         "bundle";
         "pull";
         "--oci";
         "ghcr.io/acme/p:v1";
         "--plain-http";
         "-o";
         out2;
         "-k";
         pubf;
       ]);
  check_cli "no registry host" 2
    (run_cli [ "bundle"; "pull"; "--oci"; "acme/p:v1"; "-o"; out2; "-k"; pubf ]);
  check_cli "unknown tag" 3
    (run_cli
       [
         "bundle";
         "pull";
         "--oci";
         anon ^ "/haltsql/cli:missing";
         "--plain-http";
         "-o";
         out2;
         "-k";
         pubf;
       ]);
  check_cli "registry down" 3
    (run_cli
       [
         "bundle";
         "pull";
         "--oci";
         "127.0.0.1:15009/haltsql/cli:prod";
         "--plain-http";
         "-o";
         out2;
         "-k";
         pubf;
       ])

(* Main flow through the poller: publish, poll, update, untrusted key, rollback. *)
let test_oci_poll_flow () =
  Lazy.force setup_registries;
  let ref_ = anon ^ "/haltsql/policies:prod" in
  let t = create (source ~name_prefix:"prod." (oci_location ref_)) in
  let r = recorder () in
  expect_error "nothing published yet" "bundle_source_not_found" (poll t r);
  ignore (push ref_ ~bundle:(Lazy.force v1) ~signature:(sign (Lazy.force v1)));
  let u = expect_updated "first poll" (poll t r) in
  Alcotest.(check string) "v1" "1.0.0" u.bundle.metadata.version;
  Alcotest.(check bool)
    "revision is the manifest digest" true
    (match u.revision with
    | Some d -> String.starts_with ~prefix:"sha256:" d
    | None -> false);
  Alcotest.(check (list string))
    "prefixed"
    [ "prod." ^ (Lazy.force policy).name ]
    (List.map fst u.policies);
  expect_unchanged "second poll" (poll t r);
  (* new version *)
  ignore (push ref_ ~bundle:(Lazy.force v2) ~signature:(sign (Lazy.force v2)));
  let u2 = expect_updated "v2" (poll t r) in
  Alcotest.(check string) "v2" "1.1.0" u2.bundle.metadata.version;
  (* untrusted key *)
  ignore
    (push ref_ ~bundle:(Lazy.force v3)
       ~signature:(sign ~key:untrusted_key (Lazy.force v3)));
  expect_error "untrusted key" "bundle_source_signature" (poll t r);
  check_current "keeps v2 after untrusted" t (Some "1.1.0");
  (* bad signature (one bit flipped) *)
  let bad_sig =
    B.signatures_to_string
      [
        (let s = B.sign (Lazy.force signing_key) (Lazy.force v3) in
         { s with signature = flip_byte s.signature 5 });
      ]
  in
  ignore (push ref_ ~bundle:(Lazy.force v3) ~signature:bad_sig);
  expect_error "bad signature" "bundle_source_signature" (poll t r);
  check_current "keeps v2 after bad signature" t (Some "1.1.0");
  (* rollback: the old (validly signed) v1 re-tagged *)
  ignore (push ref_ ~bundle:(Lazy.force v1) ~signature:(sign (Lazy.force v1)));
  expect_error "downgrade" "bundle_source_rollback" (poll t r);
  check_current "keeps v2 after downgrade" t (Some "1.1.0");
  (* same version, different content *)
  let v2b = build ~created_by:"someone-else" "1.1.0" in
  ignore (push ref_ ~bundle:v2b ~signature:(sign v2b));
  expect_error "same version, other content" "bundle_source_rollback" (poll t r);
  check_current "keeps v2 after version reuse" t (Some "1.1.0");
  (* on_update refusing keeps the current bundle and is retried *)
  ignore (push ref_ ~bundle:(Lazy.force v3) ~signature:(sign (Lazy.force v3)));
  r.refuse <- Some "policy reference check failed";
  expect_error "rejected by on_update" "bundle_source_rejected" (poll t r);
  check_current "keeps v2 after rejection" t (Some "1.1.0");
  r.refuse <- None;
  let u3 = expect_updated "v3 accepted on retry" (poll t r) in
  Alcotest.(check string) "v3" "1.2.0" u3.bundle.metadata.version;
  Alcotest.(check int) "on_update calls" 3 (List.length r.seen);
  (* allow_downgrade *)
  let t2 = create ~allow_downgrade:true (source (oci_location ref_)) in
  ignore (push ref_ ~bundle:(Lazy.force v3) ~signature:(sign (Lazy.force v3)));
  ignore (expect_updated "t2 v3" (poll t2 r));
  ignore (push ref_ ~bundle:(Lazy.force v1) ~signature:(sign (Lazy.force v1)));
  let u = expect_updated "allowed downgrade" (poll t2 r) in
  Alcotest.(check string) "downgraded" "1.0.0" u.bundle.metadata.version;
  let st = S.status t in
  Alcotest.(check bool) "status counts polls" true (st.checks >= 9)

(* Manipulated manifests and blobs pushed to the real registry. *)
let test_oci_tamper () =
  Lazy.force setup_registries;
  let ref_ = anon ^ "/haltsql/tamper:prod" in
  let reg = registry ref_ in
  let t = create (source (oci_location ref_)) in
  let r = recorder () in
  let bundle = Lazy.force v1 and signature = sign (Lazy.force v1) in
  ignore (push ref_ ~bundle ~signature);
  ignore (expect_updated "baseline" (poll t r));
  let put_manifest m =
    ignore
      (ok_f "put manifest"
         (Lwt_main.run
            (S.Registry.put_manifest reg ~reference:"prod"
               ~media_type:S.Oci_artifact.manifest_media_type m)))
  in
  let manifest_with f =
    let m =
      S.Oci_artifact.build_manifest ~bundle:(Lazy.force v2)
        ~signature:(sign (Lazy.force v2))
        ()
    in
    ignore
      (Lwt_main.run
         (S.Oci_artifact.push reg ~bundle:(Lazy.force v2)
            ~signature:(sign (Lazy.force v2))));
    (* go back to v1 on the tag, then publish the manipulated manifest *)
    match Yojson.Safe.from_string m with
    | `Assoc kvs -> Yojson.Safe.to_string (`Assoc (f kvs))
    | _ -> assert false
  in
  ignore (push ref_ ~bundle ~signature);
  let map_layers f kvs =
    List.map
      (fun (k, v) ->
        match (k, v) with "layers", `List l -> (k, `List (List.mapi f l)) | _ -> (k, v))
      kvs
  in
  let set_field name value = function
    | `Assoc d -> `Assoc ((name, value) :: List.remove_assoc name d)
    | j -> j
  in
  (* 1. the bundle layer claims a wrong size *)
  put_manifest
    (manifest_with
       (map_layers (fun i d ->
            if i = 0 then set_field "size" (`Int (String.length (Lazy.force v2) + 7)) d
            else d)));
  expect_error "wrong layer size" "bundle_source_integrity" (poll t r);
  check_current "keeps v1 (size)" t (Some "1.0.0");
  put_manifest
    (manifest_with
       (map_layers (fun i d ->
            if i = 0 then set_field "size" (`Int (String.length (Lazy.force v2) - 7)) d
            else d)));
  expect_error "short layer size" "bundle_source_integrity" (poll t r);
  (* 2. the bundle layer points at another blob (the signature) *)
  let sig2 = sign (Lazy.force v2) in
  put_manifest
    (manifest_with
       (map_layers (fun i d ->
            if i = 0 then
              d
              |> set_field "digest" (`String (S.Content_digest.sha256 sig2))
              |> set_field "size" (`Int (String.length sig2))
            else d)));
  expect_error "swapped blob" "bundle_source_signature" (poll t r);
  check_current "keeps v1 (swapped)" t (Some "1.0.0");
  (* 3. truncated bundle blob (a valid blob of the truncated bytes) with the real signature *)
  let truncated = String.sub (Lazy.force v2) 0 (String.length (Lazy.force v2) - 20) in
  ignore (ok_f "blob" (Lwt_main.run (S.Registry.push_blob reg truncated)));
  put_manifest
    (manifest_with
       (map_layers (fun i d ->
            if i = 0 then
              d
              |> set_field "digest" (`String (S.Content_digest.sha256 truncated))
              |> set_field "size" (`Int (String.length truncated))
            else d)));
  expect_error "truncated blob" "bundle_source_signature" (poll t r);
  check_current "keeps v1 (truncated)" t (Some "1.0.0");
  (* 4. a foreign artifact type *)
  put_manifest
    (manifest_with (fun kvs ->
         ("artifactType", `String "application/vnd.example+type")
         :: List.remove_assoc "artifactType" kvs));
  expect_error "artifact type" "bundle_source_integrity" (poll t r);
  (* 5. an unknown extra layer *)
  put_manifest
    (manifest_with (fun kvs ->
         List.map
           (fun (k, v) ->
             match (k, v) with
             | "layers", `List l ->
                 ( k,
                   `List
                     (l
                     @ [
                         `Assoc
                           [
                             ("mediaType", `String "application/x-shellscript");
                             ("digest", `String (S.Content_digest.sha256 truncated));
                             ("size", `Int (String.length truncated));
                           ];
                       ]) )
             | _ -> (k, v))
           kvs));
  expect_error "extra layer" "bundle_source_integrity" (poll t r);
  check_current "keeps v1 after every tamper" t (Some "1.0.0");
  (* 6. a pinned digest only ever loads that manifest *)
  let d1 = push ref_ ~bundle ~signature in
  let tp = create (source (oci_location (anon ^ "/haltsql/tamper@" ^ d1))) in
  let u = expect_updated "pinned" (poll tp r) in
  Alcotest.(check (option string)) "pinned revision" (Some d1) u.revision;
  ignore (push ref_ ~bundle:(Lazy.force v2) ~signature:(sign (Lazy.force v2)));
  expect_unchanged "pinned ignores the tag" (poll tp r);
  (* a digest the registry does not have *)
  let tm =
    create (source (oci_location (anon ^ "/haltsql/tamper@sha256:" ^ String.make 64 '0')))
  in
  expect_error "unknown digest" "bundle_source_not_found" (poll tm r)

let test_oci_basic_auth () =
  Lazy.force setup_registries;
  let reg_s = Printf.sprintf "127.0.0.1:%d/haltsql/policies:prod" D.port_basic in
  let creds =
    S.Registry.Basic { username = D.basic_user; password = Lazy.force D.basic_password }
  in
  let dir = tmp_dir "basic" in
  let b1 = write_bundle dir "prod.haltsqlbundle" (Lazy.force v1) (sign (Lazy.force v1)) in
  check_cli "push without credentials" 3
    (run_cli [ "bundle"; "push"; "--oci"; reg_s; "--plain-http"; b1 ]);
  check_cli "push with basic credentials" 0
    (run_cli
       ~env:[ ("TEST_REGISTRY_PASSWORD", Lazy.force D.basic_password) ]
       [
         "bundle";
         "push";
         "--oci";
         reg_s;
         "--plain-http";
         b1;
         "--username";
         D.basic_user;
         "--password-env";
         "TEST_REGISTRY_PASSWORD";
       ]);
  ignore creds;
  let r = recorder () in
  let anon_t = create (source (oci_location reg_s)) in
  expect_error "anonymous pull" "bundle_source_denied" (poll anon_t r);
  let bad =
    create
      (source
         ~auth:(Config.Source_basic { username = D.basic_user; password = "wrong" })
         (oci_location reg_s))
  in
  expect_error "wrong password" "bundle_source_denied" (poll bad r);
  let t =
    create
      (source
         ~auth:
           (Config.Source_basic
              { username = D.basic_user; password = Lazy.force D.basic_password })
         (oci_location reg_s))
  in
  let u = expect_updated "basic pull" (poll t r) in
  Alcotest.(check string) "v1" "1.0.0" u.bundle.metadata.version;
  expect_unchanged "basic HEAD" (poll t r)

let test_oci_token_auth () =
  Lazy.force setup_registries;
  let reg_s = Printf.sprintf "127.0.0.1:%d/haltsql/policies:prod" D.port_token_registry in
  let creds =
    S.Registry.Basic { username = D.token_user; password = Lazy.force D.token_password }
  in
  (match
     Lwt_main.run
       (S.Oci_artifact.push (registry reg_s) ~bundle:(Lazy.force v1)
          ~signature:(sign (Lazy.force v1)))
   with
  | Error (S.Fetch_error.Denied _) -> ()
  | Error e -> Alcotest.failf "anonymous push: unexpected %s" (S.Fetch_error.to_string e)
  | Ok _ -> Alcotest.fail "anonymous push must be denied");
  ignore
    (push ~credentials:creds reg_s ~bundle:(Lazy.force v1)
       ~signature:(sign (Lazy.force v1)));
  let r = recorder () in
  (* anonymous pull through the token flow (docker_auth grants anonymous pull) *)
  let t = create (source (oci_location reg_s)) in
  let u = expect_updated "anonymous token pull" (poll t r) in
  Alcotest.(check string) "v1" "1.0.0" u.bundle.metadata.version;
  expect_unchanged "token HEAD" (poll t r);
  ignore
    (push ~credentials:creds reg_s ~bundle:(Lazy.force v2)
       ~signature:(sign (Lazy.force v2)));
  let tb =
    create
      (source
         ~auth:
           (Config.Source_basic
              { username = D.token_user; password = Lazy.force D.token_password })
         (oci_location reg_s))
  in
  ignore (expect_updated "authenticated token pull" (poll tb r));
  ignore (expect_updated "anonymous sees v2" (poll t r));
  let bad =
    create
      (source
         ~auth:(Config.Source_basic { username = D.token_user; password = "wrong" })
         (oci_location reg_s))
  in
  expect_error "wrong password at the token endpoint" "bundle_source_denied" (poll bad r);
  let static =
    create
      (source ~auth:(Config.Source_token "not-a-registry-token") (oci_location reg_s))
  in
  expect_error "invalid static token" "bundle_source_denied" (poll static r)

let test_oras_compat () =
  Lazy.force setup_registries;
  let dir = tmp_dir "oras" in
  let _ = write_bundle dir "prod.haltsqlbundle" (Lazy.force v2) (sign (Lazy.force v2)) in
  Unix.chmod dir 0o777;
  let host_ref = Printf.sprintf "host.docker.internal:%d/haltsql/oras:v2" D.port_anon in
  (match
     D.oras ~workdir:dir
       [
         "push";
         "--plain-http";
         host_ref;
         "--artifact-type";
         S.Oci_artifact.artifact_type;
         "prod.haltsqlbundle:" ^ S.Oci_artifact.bundle_media_type;
         "prod.haltsqlbundle.sig:" ^ S.Oci_artifact.signature_media_type;
       ]
   with
  | 0, _ -> ()
  | c, out -> Alcotest.failf "oras push failed (%d): %s" c out);
  let r = recorder () in
  let t = create (source (oci_location (anon ^ "/haltsql/oras:v2"))) in
  let u = expect_updated "pull an oras-pushed artifact" (poll t r) in
  Alcotest.(check string) "v2" "1.1.0" u.bundle.metadata.version;
  (* and oras can pull what haltsql pushes *)
  ignore
    (push
       (anon ^ "/haltsql/oras:from-haltsql")
       ~bundle:(Lazy.force v3)
       ~signature:(sign (Lazy.force v3)));
  let out = Filename.concat dir "pulled" in
  D.mkdir_p out;
  Unix.chmod out 0o777;
  (match
     D.oras ~workdir:dir
       [
         "pull";
         "--plain-http";
         Printf.sprintf "host.docker.internal:%d/haltsql/oras:from-haltsql" D.port_anon;
         "-o";
         "pulled";
       ]
   with
  | 0, _ -> ()
  | c, o -> Alcotest.failf "oras pull failed (%d): %s" c o);
  Alcotest.(check bool)
    "oras wrote the bundle under its title" true
    (D.read_all (Filename.concat out "prod.haltsqlbundle") = Lazy.force v3);
  Alcotest.(check bool)
    "and the signature" true
    (D.read_all (Filename.concat out "prod.haltsqlbundle.sig") = sign (Lazy.force v3))

let test_start_loop () =
  Lazy.force setup_registries;
  let ref_ = anon ^ "/haltsql/loop:prod" in
  ignore (push ref_ ~bundle:(Lazy.force v1) ~signature:(sign (Lazy.force v1)));
  let t = create ~poll_interval:0.3 (source (oci_location ref_)) in
  let r = recorder () in
  let errors = ref [] in
  let result =
    Lwt_main.run
      (S.start t ~on_update:(on_update r) ~on_error:(fun e -> errors := e :: !errors))
  in
  ok_s "start" result;
  check_current "started with v1" t (Some "1.0.0");
  ignore
    (push ref_ ~bundle:(Lazy.force v3)
       ~signature:(sign ~key:untrusted_key (Lazy.force v3)));
  let wait what cond =
    Lwt_main.run
      (let deadline = Unix.gettimeofday () +. 20. in
       let rec go () =
         if cond () then Lwt.return_unit
         else if Unix.gettimeofday () > deadline then Lwt.fail_with ("timed out: " ^ what)
         else Lwt_unix.sleep 0.1 >>= go
       in
       go ())
  in
  wait "untrusted bundle reported" (fun () ->
      List.exists (fun e -> S.error_code e = "bundle_source_signature") !errors);
  check_current "still v1" t (Some "1.0.0");
  ignore (push ref_ ~bundle:(Lazy.force v2) ~signature:(sign (Lazy.force v2)));
  wait "background update to v2" (fun () -> current_version t = Some "1.1.0");
  S.stop t;
  let checks = (S.status t).checks in
  Lwt_main.run (Lwt_unix.sleep 1.0);
  Alcotest.(check bool) "no polls after stop" true ((S.status t).checks <= checks + 1)

(* ------------------------------------------------------------------- S3 *)

let bucket = "haltsql-bundles"

let minio_creds () =
  {
    Haltsql_cloud.Sigv4.access_key_id = D.minio_user;
    secret_access_key = Lazy.force D.minio_password;
    session_token = None;
  }

let s3_put ?(creds = minio_creds ()) path body =
  let uri = Uri.of_string (Printf.sprintf "http://127.0.0.1:%d/%s" D.port_minio path) in
  let headers =
    Haltsql_cloud.Sigv4.sign ~s3:true creds ~service:"s3" ~region:"us-east-1"
      ~time:(Unix.gettimeofday ()) ~meth:"PUT" ~uri ~headers:[] ~payload:body
  in
  match Lwt_main.run (Haltsql_cloud.Http.request ~headers ~body `PUT uri) with
  | Ok r when r.status = 200 -> ()
  | Ok r -> Alcotest.failf "S3 PUT %s: HTTP %d" path r.status
  | Error e -> Alcotest.failf "S3 PUT %s: %s" path e

let s3_location
    ?(credentials =
      Config.S3_static
        {
          access_key_id = D.minio_user;
          secret_access_key = Lazy.force D.minio_password;
          session_token = None;
        }) key =
  Config.Source_s3
    {
      src_bucket = bucket;
      src_key = key;
      src_region = "us-east-1";
      src_endpoint = Some (Printf.sprintf "http://127.0.0.1:%d" D.port_minio);
      src_credentials = credentials;
    }

let setup_minio =
  lazy
    (D.start_minio ();
     s3_put bucket "")

let publish_s3 key bundle signature =
  (* signature first, then the bundle *)
  s3_put (bucket ^ "/" ^ key ^ ".sig") signature;
  s3_put (bucket ^ "/" ^ key) bundle

let test_s3 () =
  Lazy.force setup_minio;
  let key = "prod/policies.haltsqlbundle" in
  let t = create (source (s3_location key)) in
  let r = recorder () in
  expect_error "missing object" "bundle_source_not_found" (poll t r);
  publish_s3 key (Lazy.force v1) (sign (Lazy.force v1));
  let u = expect_updated "s3 v1" (poll t r) in
  Alcotest.(check string) "v1" "1.0.0" u.bundle.metadata.version;
  Alcotest.(check bool) "etag revision" true (u.revision <> None);
  expect_unchanged "s3 304" (poll t r);
  publish_s3 key (Lazy.force v2) (sign (Lazy.force v2));
  ignore (expect_updated "s3 v2" (poll t r));
  (* tampered bundle: one byte flipped *)
  publish_s3 key (flip_byte (Lazy.force v3) 50) (sign (Lazy.force v3));
  expect_error "tampered s3 object" "bundle_source_signature" (poll t r);
  publish_s3 key (Lazy.force v3) (sign ~key:untrusted_key (Lazy.force v3));
  expect_error "untrusted s3 bundle" "bundle_source_signature" (poll t r);
  publish_s3 key (Lazy.force v1) (sign (Lazy.force v1));
  expect_error "s3 downgrade" "bundle_source_rollback" (poll t r);
  check_current "s3 keeps v2" t (Some "1.1.0");
  let bad =
    create
      (source
         (s3_location
            ~credentials:
              (Config.S3_static
                 {
                   access_key_id = D.minio_user;
                   secret_access_key = "wrong-secret-key";
                   session_token = None;
                 })
            key))
  in
  expect_error "bad S3 credentials" "bundle_source_denied" (poll bad r)

(* ---------------------------------------------------------------- HTTPS *)

let setup_https = lazy (D.start_https ())

(* Publishes like a web deployment would: a new file renamed into place. *)
let www_write ?mtime name contents =
  let p = Filename.concat (D.www_dir ()) name in
  let tmp = p ^ ".tmp" in
  D.write tmp contents;
  (match mtime with Some m -> Unix.utimes tmp m m | None -> ());
  Unix.rename tmp p

let https_url name = Printf.sprintf "https://localhost:%d/%s" D.port_https name

(* Docker Desktop's file sharing can serve stale metadata for a moment after a
   rename: wait until nginx reports the ETag of the new file ("<mtime>-<size>"
   in hex) so the test does not depend on that delay. *)
let wait_etag name ~mtime ~size =
  let ctx =
    ok_or_fail "ca" (Lwt_main.run (Haltsql_cloud.Http.ctx_of_ca_file (D.ca_file ())))
  in
  let expected = Printf.sprintf "\"%x-%x\"" (int_of_float mtime) size in
  D.wait_until ~timeout:20. ~what:("nginx ETag of " ^ name) (fun () ->
      match
        Lwt_main.run
          (Haltsql_cloud.Http.request ~ctx ~timeout:2.
             ~headers:[ ("authorization", "Bearer " ^ Lazy.force D.https_token) ]
             `HEAD
             (Uri.of_string (https_url name)))
      with
      | Ok r -> Haltsql_cloud.Http.header r "etag" = Some expected
      | Error _ -> false)

let publish_https ?(dir = "") ~mtime name bundle signature =
  www_write ~mtime (dir ^ name ^ ".sig") signature;
  www_write ~mtime (dir ^ name) bundle;
  wait_etag (dir ^ name ^ ".sig") ~mtime ~size:(String.length signature);
  wait_etag (dir ^ name) ~mtime ~size:(String.length bundle)

let wait_https () =
  D.wait_http
    ~ctx:
      (ok_or_fail "ca" (Lwt_main.run (Haltsql_cloud.Http.ctx_of_ca_file (D.ca_file ()))))
    ~what:"nginx https" (https_url "")

let test_https () =
  Lazy.force setup_https;
  wait_https ();
  let ca_file = D.ca_file () in
  let r = recorder () in
  let t =
    create ~ca_file (source (Config.Source_https (https_url "prod.haltsqlbundle")))
  in
  expect_error "missing file" "bundle_source_not_found" (poll t r);
  publish_https ~mtime:1_700_000_000. "prod.haltsqlbundle" (Lazy.force v1)
    (sign (Lazy.force v1));
  let u = expect_updated "https v1" (poll t r) in
  Alcotest.(check bool) "etag" true (u.revision <> None);
  expect_unchanged "https 304" (poll t r);
  publish_https ~mtime:1_700_000_100. "prod.haltsqlbundle" (Lazy.force v2)
    (sign (Lazy.force v2));
  ignore (expect_updated "https v2" (poll t r));
  publish_https ~mtime:1_700_000_200. "prod.haltsqlbundle"
    (flip_byte (Lazy.force v3) 33)
    (sign (Lazy.force v3));
  expect_error "tampered https bundle" "bundle_source_signature" (poll t r);
  check_current "https keeps v2" t (Some "1.1.0");
  (* the server's certificate is not in the system trust store: fail closed *)
  let untrusted =
    create (source (Config.Source_https (https_url "prod.haltsqlbundle")))
  in
  expect_error "unknown CA" "bundle_source_unavailable" (poll untrusted r);
  (* bearer token *)
  publish_https ~dir:"private/" ~mtime:1_700_000_000. "p.haltsqlbundle" (Lazy.force v1)
    (sign (Lazy.force v1));
  let no_token =
    create ~ca_file (source (Config.Source_https (https_url "private/p.haltsqlbundle")))
  in
  expect_error "no token" "bundle_source_denied" (poll no_token r);
  let with_token =
    create ~ca_file
      (source
         ~auth:(Config.Source_token (Lazy.force D.https_token))
         (Config.Source_https (https_url "private/p.haltsqlbundle")))
  in
  ignore (expect_updated "with token" (poll with_token r))

let test_cache_restart () =
  Lazy.force setup_https;
  wait_https ();
  let ca_file = D.ca_file () in
  let cache_dir = tmp_dir "restart-cache" in
  let cfg = source ~cache_dir (Config.Source_https (https_url "cached.haltsqlbundle")) in
  publish_https ~mtime:1_700_001_000. "cached.haltsqlbundle" (Lazy.force v2)
    (sign (Lazy.force v2));
  let r = recorder () in
  let t = create ~ca_file cfg in
  ignore (expect_updated "fills the cache" (poll t r));
  (* the source goes down; a restarted server starts from the cache *)
  D.stop D.https_container;
  let t2 = create ~ca_file cfg in
  let r2 = recorder () in
  let errors = ref [] in
  let res =
    Lwt_main.run
      (S.start t2 ~on_update:(on_update r2) ~on_error:(fun e -> errors := e :: !errors))
  in
  S.stop t2;
  ok_s "start from cache" res;
  (match r2.seen with
  | [ u ] ->
      Alcotest.(check bool) "from cache" true (u.origin = S.From_cache);
      Alcotest.(check string) "cached version" "1.1.0" u.bundle.metadata.version
  | l -> Alcotest.failf "expected one update from the cache, got %d" (List.length l));
  Alcotest.(check bool)
    "source failure reported" true
    (List.exists (fun e -> S.error_code e = "bundle_source_unavailable") !errors);
  (* a stale cached version cannot roll back what the source serves later *)
  D.restart D.https_container;
  wait_https ();
  expect_unchanged "ETag from the cache: not modified" (poll t2 r2);
  publish_https ~mtime:1_700_001_100. "cached.haltsqlbundle" (Lazy.force v1)
    (sign (Lazy.force v1));
  expect_error "downgrade below the cached version" "bundle_source_rollback" (poll t2 r2);
  publish_https ~mtime:1_700_001_200. "cached.haltsqlbundle" (Lazy.force v3)
    (sign (Lazy.force v3));
  ignore (expect_updated "v3 after restart" (poll t2 r2));
  (* without a usable cache and with the source down, start fails closed *)
  D.stop D.https_container;
  let t3 =
    create ~ca_file (source (Config.Source_https (https_url "cached.haltsqlbundle")))
  in
  (match Lwt_main.run (S.start t3 ~on_update:(on_update r2) ~on_error:ignore) with
  | Ok () -> Alcotest.fail "start without cache and source must fail"
  | Error e ->
      Alcotest.(check string) "no bundle" "bundle_source_unavailable" (S.error_code e));
  S.stop t3;
  (* a cache entry that no longer verifies (key removed) is not used *)
  let t4 =
    create ~ca_file
      (source
         ~keys:[ config_key untrusted_key ]
         ~cache_dir
         (Config.Source_https (https_url "cached.haltsqlbundle")))
  in
  (match Lwt_main.run (S.load_cache t4 ~on_update:(on_update r2)) with
  | Error e ->
      Alcotest.(check string)
        "cache refused with other keys" "bundle_source_signature" (S.error_code e)
  | Ok _ -> Alcotest.fail "a cache entry must be re-verified with the current keys");
  D.restart D.https_container;
  wait_https ()

let () =
  ignore docker_ready;
  Alcotest.run "haltsql.bundle_source"
    [
      ( "unit",
        [
          Alcotest.test_case "oci references" `Quick test_oci_ref;
          Alcotest.test_case "WWW-Authenticate" `Quick test_www_auth;
          Alcotest.test_case "content digests" `Quick test_digest;
          Alcotest.test_case "version order and rollback" `Quick test_versions;
          Alcotest.test_case "artifact manifest" `Quick test_manifest;
          Alcotest.test_case "cache" `Quick test_cache;
          Alcotest.test_case "verification" `Quick test_verify;
          Alcotest.test_case "config decode" `Quick test_config_decode;
        ] );
      ( "oci (registry:2)",
        [
          docker_case "cli push and pull" test_cli_push_pull;
          docker_case "poll flow" test_oci_poll_flow;
          docker_case "tampering" test_oci_tamper;
          docker_case "htpasswd basic auth" test_oci_basic_auth;
          docker_case "bearer token auth (docker_auth)" test_oci_token_auth;
          docker_case "oras compatibility" test_oras_compat;
          docker_case "background polling" test_start_loop;
        ] );
      ("s3 (minio)", [ docker_case "poll flow" test_s3 ]);
      ( "https (nginx)",
        [
          docker_case "poll flow" test_https;
          docker_case "cache restart" test_cache_restart;
        ] );
    ]
