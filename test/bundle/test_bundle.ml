(* Tests for signed policy bundles (lib/bundle) and the [haltsql bundle] CLI. *)

open Haltsql
module B = Haltsql_bundle

let examples = "../../examples"

let policy_files =
  [ "saas.yaml"; "writes.yaml"; "shadow.yaml"; "hierarchical.yaml"; "composite.yaml" ]

let ok_or_fail what = function Ok x -> x | Error e -> Alcotest.failf "%s: %s" what e

let ok_b what = function
  | Ok x -> x
  | Error e -> Alcotest.failf "%s: %s" what (B.error_to_string e)

let load_policy f =
  match Policy_load.of_file (Filename.concat examples ("policies/" ^ f)) with
  | Ok p -> p
  | Error _ -> Alcotest.failf "cannot load example policy %s" f

let policies () = List.map load_policy policy_files

let catalog () =
  match Catalog_load.of_file (Filename.concat examples "catalog/saas.snapshot.json") with
  | Ok c -> c
  | Error _ -> Alcotest.fail "cannot load example catalog"

let metadata =
  {
    B.name = "prod-policies";
    version = "1.4.0";
    created_by = Some "test";
    source = { url = Some "https://github.com/acme/policies"; commit = Some "4f0c2a91" };
  }

let build_bytes () =
  ok_b "build"
    (B.build metadata ~policies:(policies ()) ~catalogs:[ ("saas", catalog ()) ])

(* Fixed keys so failures are reproducible. *)
let key_of_seed c =
  match
    B.Key.secret_of_string
      (let raw = String.make 32 c in
       let der =
         "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20" ^ raw
       in
       "-----BEGIN PRIVATE KEY-----\n" ^ B.B64.encode der
       ^ "\n-----END PRIVATE KEY-----\n")
  with
  | Ok k -> k
  | Error e -> Alcotest.failf "key_of_seed: %s" e

let old_key = lazy (key_of_seed 'o')
let new_key = lazy (key_of_seed 'n')
let other_key = lazy (key_of_seed 'x')
let pub k = B.Key.public_of_secret (Lazy.force k)

(* ---------------------------------------------------------------- temp files *)

let tmp_root =
  lazy
    (let d =
       Filename.concat
         (Filename.get_temp_dir_name ())
         (Printf.sprintf "haltsql_bundle_%d" (Unix.getpid ()))
     in
     (try Unix.mkdir d 0o700 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
     at_exit (fun () ->
         ignore (Sys.command (Printf.sprintf "rm -rf %s" (Filename.quote d))));
     d)

let tmp name = Filename.concat (Lazy.force tmp_root) name

let write ?(perm = 0o644) path s =
  Out_channel.with_open_gen [ Open_wronly; Open_creat; Open_trunc; Open_binary ] perm path
    (fun oc -> Out_channel.output_string oc s);
  Unix.chmod path perm

let read path = In_channel.with_open_bin path In_channel.input_all

(* Write a bundle + signature pair and return the bundle path. *)
let write_signed ?(sigs = None) name bytes key =
  let p = tmp name in
  write p bytes;
  let sigs = match sigs with Some s -> s | None -> [ B.sign (Lazy.force key) bytes ] in
  write (B.signature_path p) (B.signatures_to_string sigs);
  p

let expect_error what pred = function
  | Ok _ -> Alcotest.failf "%s: expected an error, got Ok" what
  | Error e ->
      if not (pred e) then
        Alcotest.failf "%s: unexpected error: %s" what (B.error_to_string e)

let is_sig = function B.Signature_invalid _ -> true | _ -> false

let is_malformed sub = function
  | B.Malformed m ->
      let n = String.length sub and len = String.length m in
      let rec go i = i + n <= len && (String.sub m i n = sub || go (i + 1)) in
      go 0
  | _ -> false

(* Re-serialize a modified document canonically, recomputing the digest. *)
let reencode ?(fix_digest = true) (f : Yojson.Safe.t -> Yojson.Safe.t) bytes =
  let j = Yojson.Safe.from_string bytes in
  let j = f j in
  let j =
    if not fix_digest then j
    else
      match j with
      | `Assoc kvs ->
          let payload = `Assoc (List.filter (fun (k, _) -> k <> "digest") kvs) in
          let c = ok_or_fail "canon" (B.Canonical.to_string payload) in
          `Assoc
            (List.filter (fun (k, _) -> k <> "digest") kvs
            @ [
                ( "digest",
                  `String ("sha256:" ^ Digestif.SHA256.(to_hex (digest_string c))) );
              ])
      | j -> j
  in
  ok_or_fail "canon" (B.Canonical.to_string j) ^ "\n"

let map_member k f = function
  | `Assoc kvs ->
      `Assoc (List.map (fun (k', v) -> if k = k' then (k', f v) else (k', v)) kvs)
  | j -> j

let first_policy_doc f =
  map_member "policies" (function
    | `List (p :: rest) -> `List (map_member "document" f p :: rest)
    | j -> j)

(* ------------------------------------------------------------------- tests *)

let test_round_trip () =
  let bytes = build_bytes () in
  let p = write_signed "rt.haltsqlbundle" bytes old_key in
  let t, k = ok_b "load" (B.load_verified_bundle p [ pub old_key ]) in
  Alcotest.(check string) "verifying key" (B.Key.keyid (pub old_key)) (B.Key.keyid k);
  Alcotest.(check string) "name" "prod-policies" t.metadata.name;
  Alcotest.(check string) "version" "1.4.0" t.metadata.version;
  Alcotest.(check (option string)) "commit" (Some "4f0c2a91") t.metadata.source.commit;
  let orig = policies () in
  Alcotest.(check (list string))
    "policy names"
    (List.map (fun (p : Policy.t) -> p.name) orig)
    (List.map (fun (p : Policy.t) -> p.name) t.policies);
  Alcotest.(check (list string))
    "policy versions are preserved"
    (List.map (fun (p : Policy.t) -> p.version) orig)
    (List.map (fun (p : Policy.t) -> p.version) t.policies);
  Alcotest.(check (list string)) "catalogs" [ "saas" ] (List.map fst t.catalogs);
  Alcotest.(check int)
    "catalog tables"
    (List.length (catalog ()).tables)
    (List.length (snd (List.hd t.catalogs)).tables);
  (* the loaded policy behaves like the original *)
  let saas = List.find (fun (p : Policy.t) -> p.name = "saas-analytics") t.policies in
  let ctx = Context.make [ ("tenant_id", One "acme") ] in
  let sql = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10" in
  Alcotest.(check bool) "allowed" true (Haltsql.verify saas ctx sql).allowed;
  Alcotest.(check bool)
    "denied" false (Haltsql.verify saas ctx "SELECT id FROM orders LIMIT 10").allowed;
  let ps = ok_b "load_verified" (B.load_verified p [ pub old_key ]) in
  Alcotest.(check int) "load_verified count" 5 (List.length ps)

(* A policy without tenancy round-trips (Policy_load.to_json writes tenancy.keys: {},
   which the loader rejects; the bundle omits it). *)
let test_untenanted () =
  let p =
    match
      Policy_load.of_string Docload.Yaml
        "apiVersion: haltsql.dev/v1\nkind: Policy\nmetadata: { name: plain }\n\
         search_path: [app]\ntables:\n  app.orders: { columns: [id] }\n"
    with
    | Ok p -> p
    | Error _ -> Alcotest.fail "policy"
  in
  let bytes = ok_b "build" (B.build metadata ~policies:[ p ] ~catalogs:[]) in
  let path = write_signed "plain.haltsqlbundle" bytes old_key in
  let ps = ok_b "load" (B.load_verified path [ pub old_key ]) in
  Alcotest.(check (list string))
    "same version" [ p.version ]
    (List.map (fun (q : Policy.t) -> q.version) ps)

let test_deterministic () =
  let a = build_bytes () and b = build_bytes () in
  Alcotest.(check string) "same bytes" a b;
  (* the same policy written in YAML and JSON gives the same bundle *)
  let one f = ok_b "build" (B.build metadata ~policies:[ load_policy f ] ~catalogs:[]) in
  Alcotest.(check string) "yaml = json" (one "saas.yaml") (one "saas.json");
  Alcotest.(check bool) "trailing newline" true (a.[String.length a - 1] = '\n');
  let s1 = B.sign (Lazy.force old_key) a and s2 = B.sign (Lazy.force old_key) a in
  Alcotest.(check string) "ed25519 signatures are deterministic" s1.signature s2.signature

let test_payload_flip () =
  let bytes = build_bytes () in
  let sigs = Some [ B.sign (Lazy.force old_key) bytes ] in
  (* flip one byte inside a policy (a table name character) *)
  let i = String.length bytes / 2 in
  let flipped = Bytes.of_string bytes in
  Bytes.set flipped i (Char.chr (Char.code bytes.[i] lxor 1));
  let p = write_signed ~sigs "flip.haltsqlbundle" (Bytes.to_string flipped) old_key in
  expect_error "payload flip" is_sig (B.load_verified p [ pub old_key ]);
  (* even a change with a correctly recomputed digest is caught by the signature *)
  let edited =
    reencode
      (map_member "metadata" (map_member "version" (fun _ -> `String "9.9.9")))
      bytes
  in
  let p = write_signed ~sigs "edit.haltsqlbundle" edited old_key in
  expect_error "re-digested edit" is_sig (B.load_verified p [ pub old_key ])

let test_signature_flip () =
  let bytes = build_bytes () in
  let s = B.sign (Lazy.force old_key) bytes in
  let bad = Bytes.of_string s.signature in
  Bytes.set bad 10 (Char.chr (Char.code s.signature.[10] lxor 0x80));
  let p =
    write_signed
      ~sigs:(Some [ { s with signature = Bytes.to_string bad } ])
      "sflip.haltsqlbundle" bytes old_key
  in
  expect_error "signature flip"
    (function
      | B.Signature_invalid m -> m = "the signature does not match the bundle contents"
      | _ -> false)
    (B.load_verified p [ pub old_key ])

let test_wrong_key () =
  let bytes = build_bytes () in
  let p = write_signed "wrong.haltsqlbundle" bytes other_key in
  expect_error "wrong key"
    (function
      | B.Signature_invalid m ->
          m
          = Printf.sprintf "signed by %s, which is not a trusted key"
              (B.Key.keyid (pub other_key))
      | _ -> false)
    (B.load_verified p [ pub old_key ]);
  expect_error "no keys"
    (function
      | B.Signature_invalid "no trusted public keys were given" -> true | _ -> false)
    (B.load_verified p []);
  (* a forged keyid does not help: the attacker's signature labelled with a trusted keyid *)
  let forged =
    { (B.sign (Lazy.force other_key) bytes) with keyid = B.Key.keyid (pub old_key) }
  in
  let p = write_signed ~sigs:(Some [ forged ]) "forged.haltsqlbundle" bytes old_key in
  expect_error "forged keyid" is_sig (B.load_verified p [ pub old_key ])

let test_truncated () =
  let bytes = build_bytes () in
  let sigs = Some [ B.sign (Lazy.force old_key) bytes ] in
  let p =
    write_signed ~sigs "trunc.haltsqlbundle"
      (String.sub bytes 0 (String.length bytes - 40))
      old_key
  in
  expect_error "truncated bundle" is_sig (B.load_verified p [ pub old_key ]);
  let p = write_signed "trsig.haltsqlbundle" bytes old_key in
  let s = read (B.signature_path p) in
  write (B.signature_path p) (String.sub s 0 (String.length s / 2));
  expect_error "truncated signature file" is_sig (B.load_verified p [ pub old_key ]);
  (* missing signature file *)
  let p = tmp "nosig.haltsqlbundle" in
  write p bytes;
  expect_error "missing signature"
    (function B.Io _ -> true | _ -> false)
    (B.load_verified p [ pub old_key ]);
  (* empty bundle, correctly signed: rejected as malformed *)
  let p = write_signed "empty.haltsqlbundle" "" old_key in
  expect_error "empty bundle" (is_malformed "invalid JSON")
    (B.load_verified p [ pub old_key ])

(* Documents signed by the trusted key but structurally invalid are still refused. *)
let test_structure_checks () =
  let bytes = build_bytes () in
  let load name b = B.load_verified (write_signed name b old_key) [ pub old_key ] in
  expect_error "unknown top-level member"
    (is_malformed "bundle: unknown member \"extra\"")
    (load "u1.haltsqlbundle"
       (reencode
          (function `Assoc kvs -> `Assoc (("extra", `Bool true) :: kvs) | j -> j)
          bytes));
  expect_error "unknown metadata member"
    (is_malformed "metadata: unknown member \"owner\"")
    (load "u2.haltsqlbundle"
       (reencode
          (map_member "metadata" (function
            | `Assoc m -> `Assoc (("owner", `String "x") :: m)
            | j -> j))
          bytes));
  expect_error "unknown policy entry member"
    (is_malformed "policies[0]: unknown member \"x\"")
    (load "u3.haltsqlbundle"
       (reencode
          (map_member "policies" (function
            | `List (`Assoc p :: r) -> `List (`Assoc (("x", `Int 1) :: p) :: r)
            | j -> j))
          bytes));
  expect_error "unknown policy document key"
    (function B.Invalid_policy { policy = "saas-analytics"; _ } -> true | _ -> false)
    (load "u4.haltsqlbundle"
       (reencode
          (first_policy_doc (function
            | `Assoc d -> `Assoc (("bogus", `Int 1) :: d)
            | j -> j))
          bytes));
  expect_error "catalog path reference"
    (is_malformed "document.catalog must be an inline snapshot")
    (load "u5.haltsqlbundle"
       (reencode
          (first_policy_doc (function
            | `Assoc d ->
                `Assoc
                  (("catalog", `String "/etc/passwd") :: List.remove_assoc "catalog" d)
            | j -> j))
          bytes));
  expect_error "digest mismatch"
    (function B.Digest_mismatch _ -> true | _ -> false)
    (load "u6.haltsqlbundle"
       (reencode ~fix_digest:false
          (map_member "metadata" (map_member "version" (fun _ -> `String "2.0.0")))
          bytes));
  expect_error "non-canonical"
    (is_malformed "not in canonical form")
    (load "u7.haltsqlbundle"
       (Yojson.Safe.pretty_to_string (Yojson.Safe.from_string bytes)));
  expect_error "wrong kind" (is_malformed "kind must be")
    (load "u8.haltsqlbundle"
       (reencode (map_member "kind" (fun _ -> `String "Policy")) bytes));
  expect_error "name mismatch"
    (is_malformed "metadata.name must equal")
    (load "u9.haltsqlbundle"
       (reencode
          (map_member "policies" (function
            | `List (p :: r) -> `List (map_member "name" (fun _ -> `String "other") p :: r)
            | j -> j))
          bytes));
  expect_error "duplicate keys"
    (is_malformed "duplicate key")
    (load "u10.haltsqlbundle"
       (let b = String.sub bytes 0 (String.length bytes - 2) in
        b ^ ",\"kind\":\"PolicyBundle\"}\n"))

let test_oversized () =
  let bytes = build_bytes () in
  let p = write_signed "big.haltsqlbundle" bytes old_key in
  expect_error "max_bytes"
    (function B.Too_large { what = "bundle"; limit = 1000; _ } -> true | _ -> false)
    (B.load_verified ~max_bytes:1000 p [ pub old_key ]);
  (* oversized signature file *)
  write (B.signature_path p) (String.make (B.max_signature_bytes + 1) ' ');
  expect_error "big signature"
    (function B.Too_large { what = "signature file"; _ } -> true | _ -> false)
    (B.load_verified p [ pub old_key ]);
  expect_error "parse_unverified size"
    (function B.Too_large _ -> true | _ -> false)
    (B.parse_unverified ~max_bytes:10 bytes)

let test_key_rotation () =
  let bytes = build_bytes () in
  (* old bundles keep loading while both keys are trusted *)
  let p = write_signed "rot1.haltsqlbundle" bytes old_key in
  let _, k = ok_b "old key" (B.load_verified_bundle p [ pub new_key; pub old_key ]) in
  Alcotest.(check string) "verified by old" (B.Key.keyid (pub old_key)) (B.Key.keyid k);
  (* new bundles: signed by the new key *)
  let p = write_signed "rot2.haltsqlbundle" bytes new_key in
  let _, k = ok_b "new key" (B.load_verified_bundle p [ pub new_key; pub old_key ]) in
  Alcotest.(check string) "verified by new" (B.Key.keyid (pub new_key)) (B.Key.keyid k);
  expect_error "old key retired" is_sig (B.load_verified p [ pub old_key ]);
  (* dual-signed bundles load under either trust set *)
  let sigs =
    Some [ B.sign (Lazy.force old_key) bytes; B.sign (Lazy.force new_key) bytes ]
  in
  let p = write_signed ~sigs "rot3.haltsqlbundle" bytes old_key in
  ignore (ok_b "dual old" (B.load_verified p [ pub old_key ]));
  ignore (ok_b "dual new" (B.load_verified p [ pub new_key ]));
  expect_error "dual other" is_sig (B.load_verified p [ pub other_key ]);
  let text = read (B.signature_path p) in
  Alcotest.(check bool)
    "multi form" true
    (String.starts_with ~prefix:"{\"signatures\":[" text);
  Alcotest.(check int)
    "parsed" 2
    (List.length (ok_b "sigs" (B.signatures_of_string text)))

let test_name_prefix () =
  let bytes = build_bytes () in
  let p = write_signed "prefix.haltsqlbundle" bytes old_key in
  let ps = ok_b "prefix" (B.load_verified ~name_prefix:"prod." p [ pub old_key ]) in
  Alcotest.(check (list string))
    "prefixed"
    (List.map (fun (p : Policy.t) -> "prod." ^ p.name) (policies ()))
    (List.map (fun (p : Policy.t) -> p.name) ps);
  expect_error "bad prefix"
    (is_malformed "invalid name prefix")
    (B.load_verified ~name_prefix:"-x" p [ pub old_key ]);
  (* via a config entry *)
  let r =
    {
      Config.bundle_path = p;
      public_keys = [ Key_base64 (B.Key.public_to_base64 (pub old_key)) ];
      name_prefix = Some "team-";
    }
  in
  let ps = ok_b "config ref" (B.load_config_ref r) in
  Alcotest.(check string) "first" "team-saas-analytics" (List.hd ps).name;
  let r' = { r with public_keys = [ Key_pem (B.Key.public_to_pem (pub other_key)) ] } in
  expect_error "config wrong key" is_sig (B.load_config_ref r');
  let r'' = { r with public_keys = [ Key_path (tmp "does-not-exist.pub") ] } in
  expect_error "config missing key"
    (function B.Invalid_key _ -> true | _ -> false)
    (B.load_config_ref r'')

let test_keys () =
  let k = pub old_key in
  let via s = ok_or_fail "decode" (B.Key.public_of_string s) in
  Alcotest.(check bool) "pem" true (B.Key.equal k (via (B.Key.public_to_pem k)));
  Alcotest.(check bool) "b64" true (B.Key.equal k (via (B.Key.public_to_base64 k)));
  Alcotest.(check int) "raw" 32 (String.length (B.Key.raw k));
  let sk = Lazy.force old_key in
  let sk' = ok_or_fail "secret pem" (B.Key.secret_of_string (B.Key.secret_to_pem sk)) in
  Alcotest.(check bool)
    "secret round trip" true
    (B.Key.equal k (B.Key.public_of_secret sk'));
  (match B.Key.public_of_string "AAAA" with
  | Ok _ -> Alcotest.fail "short key accepted"
  | Error _ -> ());
  (match B.Key.public_of_string (B.Key.secret_to_pem sk) with
  | Ok _ -> Alcotest.fail "private PEM accepted as public"
  | Error _ -> ());
  (* private key permissions *)
  let f = tmp "perm.key" in
  write ~perm:0o644 f (B.Key.secret_to_pem sk);
  (match B.Key.secret_of_file f with
  | Ok _ -> Alcotest.fail "group-readable key accepted"
  | Error e ->
      Alcotest.(check bool)
        "message" true
        (String.length e > 0 && not (String.exists (fun c -> c = '\n') e)));
  Unix.chmod f 0o600;
  ignore (ok_or_fail "0600 key" (B.Key.secret_of_file f));
  let g = B.Key.generate () and h = B.Key.generate () in
  Alcotest.(check bool)
    "fresh keys differ" false
    (B.Key.equal (B.Key.public_of_secret g) (B.Key.public_of_secret h))

let test_canonical_b64 () =
  let ok s = match B.Canonical.of_string s with Ok _ -> true | Error _ -> false in
  Alcotest.(check bool) "canonical" true (ok "{\"a\":1,\"b\":[true,null,\"x\"]}");
  Alcotest.(check bool) "whitespace" false (ok "{\"a\": 1}");
  Alcotest.(check bool) "unsorted" false (ok "{\"b\":1,\"a\":2}");
  Alcotest.(check bool) "duplicate" false (ok "{\"a\":1,\"a\":1}");
  Alcotest.(check bool) "float" false (ok "{\"a\":1.5}");
  Alcotest.(check bool) "escape" false (ok "{\"a\":\"\\u0041\"}");
  Alcotest.(check bool) "big int" false (ok "{\"a\":123456789012345678901234567890}");
  Alcotest.(check (option string)) "b64" (Some "hi!") (B.B64.decode "aGkh");
  Alcotest.(check (option string)) "b64 pad" (Some "h") (B.B64.decode "aA==");
  Alcotest.(check (option string)) "b64 non-zero bits" None (B.B64.decode "aB==");
  Alcotest.(check (option string)) "b64 no pad" None (B.B64.decode "aA");
  Alcotest.(check (option string)) "b64 newline" None (B.B64.decode "aGkh\n");
  Alcotest.(check string) "b64 enc" "aGVsbG8=" (B.B64.encode "hello")

let test_build_errors () =
  let p = load_policy "saas.yaml" in
  expect_error "no policies"
    (is_malformed "at least one policy")
    (B.build metadata ~policies:[] ~catalogs:[]);
  expect_error "duplicate"
    (is_malformed "duplicate policy name")
    (B.build metadata ~policies:[ p; p ] ~catalogs:[]);
  expect_error "bad name"
    (is_malformed "metadata.name")
    (B.build { metadata with name = "../x" } ~policies:[ p ] ~catalogs:[]);
  expect_error "bad version"
    (is_malformed "metadata.version")
    (B.build { metadata with version = "1 0" } ~policies:[ p ] ~catalogs:[]);
  expect_error "bad commit"
    (is_malformed "metadata.source.commit")
    (B.build
       { metadata with source = { url = None; commit = Some "XYZ" } }
       ~policies:[ p ] ~catalogs:[]);
  expect_error "bad catalog name"
    (is_malformed "invalid catalog name")
    (B.build metadata ~policies:[ p ] ~catalogs:[ ("a b", catalog ()) ])

(* ------------------------------------------------------------------- CLI *)

let cli = "./bundle_cli.exe"

let run_cli ?(env = "") args =
  let out = tmp "cli.out" and err = tmp "cli.err" in
  let cmd =
    Printf.sprintf "%s %s bundle %s >%s 2>%s" env cli
      (String.concat " " (List.map Filename.quote args))
      (Filename.quote out) (Filename.quote err)
  in
  let code = Sys.command cmd in
  (code, read out, read err)

let check_code what expected (code, out, err) =
  if code <> expected then
    Alcotest.failf "%s: exit %d (expected %d)\nstdout: %s\nstderr: %s" what code expected
      out err

let test_cli () =
  let key = tmp "cli.key" in
  let pubf = key ^ ".pub" in
  check_code "keygen" 0 (run_cli [ "keygen"; "-o"; key ]);
  Alcotest.(check int) "private key mode" 0o600 ((Unix.stat key).st_perm land 0o777);
  check_code "keygen exists" 2 (run_cli [ "keygen"; "-o"; key ]);
  check_code "keygen --force" 0 (run_cli [ "keygen"; "-o"; key; "--force" ]);
  let pol f = Filename.concat examples ("policies/" ^ f) in
  let out = tmp "cli.haltsqlbundle" in
  let build_args o =
    [
      "build";
      pol "saas.yaml";
      pol "writes.yaml";
      "--catalog";
      Filename.concat examples "catalog/saas.snapshot.json";
      "--name";
      "cli";
      "--bundle-version";
      "1.0.0";
      "--created-by";
      "ci";
      "-o";
      o;
    ]
  in
  check_code "build" 0 (run_cli (build_args out));
  let out2 = tmp "cli2.haltsqlbundle" in
  check_code "build again" 0 (run_cli (build_args out2));
  Alcotest.(check string) "deterministic CLI build" (read out) (read out2);
  check_code "build missing policy" 2
    (run_cli
       [ "build"; pol "nope.yaml"; "--name"; "x"; "--bundle-version"; "1"; "-o"; tmp "x" ]);
  check_code "build missing --name" 2
    (run_cli [ "build"; pol "saas.yaml"; "-o"; tmp "x" ]);
  check_code "sign" 0 (run_cli [ "sign"; out; "--key"; key ]);
  Alcotest.(check bool) "sig written" true (Sys.file_exists (out ^ ".sig"));
  let code, stdout, _ = run_cli [ "verify"; out; "--public-key"; pubf; "--json" ] in
  check_code "verify" 0 (code, stdout, "");
  (match Yojson.Safe.from_string stdout with
  | `Assoc kvs -> Alcotest.(check bool) "json ok" true (List.assoc "ok" kvs = `Bool true)
  | _ -> Alcotest.fail "verify --json");
  (* inline base64 key *)
  let b64 = B.Key.public_to_base64 (ok_or_fail "pub" (B.Key.public_of_file pubf)) in
  check_code "verify inline key" 0 (run_cli [ "verify"; out; "-k"; b64 ]);
  check_code "verify no key" 2 (run_cli [ "verify"; out ]);
  let other = tmp "cli-other.key" in
  check_code "keygen other" 0 (run_cli [ "keygen"; "-o"; other ]);
  check_code "verify wrong key" 1 (run_cli [ "verify"; out; "-k"; other ^ ".pub" ]);
  check_code "verify rotation set" 0
    (run_cli [ "verify"; out; "-k"; other ^ ".pub"; "-k"; pubf ]);
  check_code "inspect" 0 (run_cli [ "inspect"; out ]);
  check_code "inspect verified" 0 (run_cli [ "inspect"; out; "-k"; pubf ]);
  check_code "inspect wrong key" 1 (run_cli [ "inspect"; out; "-k"; other ^ ".pub" ]);
  (* append a second signature, then verify with only the other key *)
  check_code "sign --append" 0 (run_cli [ "sign"; out; "--key"; other; "--append" ]);
  check_code "verify appended" 0 (run_cli [ "verify"; out; "-k"; other ^ ".pub" ]);
  check_code "verify original" 0 (run_cli [ "verify"; out; "-k"; pubf ]);
  (* tamper *)
  let b = read out in
  write out (String.map (fun c -> if c = 'X' then 'Y' else c) b ^ " ");
  check_code "verify tampered" 1 (run_cli [ "verify"; out; "-k"; pubf ]);
  check_code "inspect tampered" 1 (run_cli [ "inspect"; out ]);
  check_code "sign tampered" 1
    (run_cli [ "sign"; out; "--key"; key; "--signature"; tmp "s2.sig" ]);
  Alcotest.(check bool) "no signature written" false (Sys.file_exists (tmp "s2.sig"));
  check_code "verify missing bundle" 1
    (run_cli [ "verify"; tmp "none.haltsqlbundle"; "-k"; pubf ]);
  (* signing key permissions and key from env *)
  Unix.chmod key 0o644;
  check_code "sign group-readable key" 2 (run_cli [ "sign"; out2; "--key"; key ]);
  Unix.chmod key 0o600;
  check_code "sign key-env" 0
    (run_cli
       ~env:(Printf.sprintf "HALTSQL_TEST_KEY=%s" (Filename.quote (read key)))
       [ "sign"; out2; "--key-env"; "HALTSQL_TEST_KEY" ]);
  check_code "verify env-signed" 0 (run_cli [ "verify"; out2; "-k"; pubf ]);
  check_code "sign key-env unset" 2
    (run_cli [ "sign"; out2; "--key-env"; "HALTSQL_TEST_KEY_UNSET" ]);
  check_code "help" 0 (run_cli [ "verify"; "--help=plain" ])

let () =
  Alcotest.run "bundle"
    [
      ( "bundle",
        [
          Alcotest.test_case "round trip" `Quick test_round_trip;
          Alcotest.test_case "policy without tenancy" `Quick test_untenanted;
          Alcotest.test_case "deterministic build" `Quick test_deterministic;
          Alcotest.test_case "payload byte flip" `Quick test_payload_flip;
          Alcotest.test_case "signature flip" `Quick test_signature_flip;
          Alcotest.test_case "wrong key" `Quick test_wrong_key;
          Alcotest.test_case "truncated" `Quick test_truncated;
          Alcotest.test_case "structure checks after signature" `Quick
            test_structure_checks;
          Alcotest.test_case "oversized" `Quick test_oversized;
          Alcotest.test_case "key rotation" `Quick test_key_rotation;
          Alcotest.test_case "name prefix and config refs" `Quick test_name_prefix;
          Alcotest.test_case "build errors" `Quick test_build_errors;
        ] );
      ( "encoding",
        [
          Alcotest.test_case "keys" `Quick test_keys;
          Alcotest.test_case "canonical json and base64" `Quick test_canonical_b64;
        ] );
      ("cli", [ Alcotest.test_case "exit codes" `Quick test_cli ]);
    ]
