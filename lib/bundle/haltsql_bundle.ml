(* Signed policy bundles. See haltsql_bundle.mli and docs/policy-bundles.md. *)

open Haltsql_core
module Canonical = Canonical
module Key = Key
module B64 = B64
module Policy_load = Haltsql_load.Policy_load
module Catalog_load = Haltsql_load.Catalog_load
module Config = Haltsql_load.Config

type error =
  | Io of string
  | Too_large of { what : string; size : int; limit : int }
  | Signature_invalid of string
  | Malformed of string
  | Digest_mismatch of { expected : string; actual : string }
  | Invalid_policy of { policy : string; errors : Load_error.t list }
  | Invalid_catalog of { catalog : string; errors : Load_error.t list }
  | Invalid_key of string

let errors_lines errs =
  String.concat "" (List.map (fun e -> "\n  " ^ Load_error.to_string e) errs)

let error_to_string = function
  | Io m -> m
  | Too_large { what; size; limit } ->
      Printf.sprintf "%s is too large (%d bytes; the limit is %d)" what size limit
  | Signature_invalid m -> "signature verification failed: " ^ m
  | Malformed m -> "malformed bundle: " ^ m
  | Digest_mismatch { expected; actual } ->
      Printf.sprintf "bundle digest mismatch: recorded %s, computed %s" expected actual
  | Invalid_policy { policy; errors } ->
      Printf.sprintf "policy %S in the bundle does not load:%s" policy
        (errors_lines errors)
  | Invalid_catalog { catalog; errors } ->
      Printf.sprintf "catalog %S in the bundle does not load:%s" catalog
        (errors_lines errors)
  | Invalid_key m -> "invalid key: " ^ m

type source = { url : string option; commit : string option }

type metadata = {
  name : string;
  version : string;
  created_by : string option;
  source : source;
}

type t = {
  metadata : metadata;
  policies : Policy.t list;
  catalogs : (string * Catalog.t) list;
  digest : string;
}

let api_version = "haltsql.dev/v1"
let kind = "PolicyBundle"
let default_max_bytes = 16 * 1024 * 1024
let max_signature_bytes = 64 * 1024
let max_signatures = 16
let max_policies = 1000
let ( let* ) = Result.bind

(* ------------------------------------------------------------ validation *)

let is_alnum = function 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' -> true | _ -> false

let valid_name s =
  let n = String.length s in
  n >= 1 && n <= 128
  && is_alnum s.[0]
  && String.for_all (fun c -> is_alnum c || c = '_' || c = '-' || c = '.') s

let printable_no_space s = String.for_all (fun c -> c > ' ' && c < '\127') s

let valid_version s =
  let n = String.length s in
  n >= 1 && n <= 64 && printable_no_space s

(* Free text: no control characters, bounded. *)
let valid_text ~max s =
  let n = String.length s in
  n >= 1 && n <= max && String.for_all (fun c -> c >= ' ' && c <> '\127') s

let valid_url s =
  valid_text ~max:2048 s && printable_no_space s
  && (String.starts_with ~prefix:"https://" s || String.starts_with ~prefix:"http://" s)

let valid_commit s =
  let n = String.length s in
  n >= 7 && n <= 64
  && String.for_all (function '0' .. '9' | 'a' .. 'f' -> true | _ -> false) s

let check_metadata (m : metadata) =
  let bad fmt = Printf.ksprintf (fun s -> Error (Malformed s)) fmt in
  if not (valid_name m.name) then
    bad
      "metadata.name %S is invalid (1-128 characters: letters, digits, '_', '-', '.'; \
       starting with a letter or digit)"
      m.name
  else if not (valid_version m.version) then
    bad "metadata.version %S is invalid (1-64 printable characters, no spaces)" m.version
  else if match m.created_by with Some c -> not (valid_text ~max:256 c) | None -> false
  then bad "metadata.created_by must be 1-256 characters without control characters"
  else if match m.source.url with Some u -> not (valid_url u) | None -> false then
    bad "metadata.source.url must be an http(s) URL without spaces"
  else if match m.source.commit with Some c -> not (valid_commit c) | None -> false then
    bad "metadata.source.commit must be 7-64 lower-case hex characters"
  else Ok ()

(* -------------------------------------------------------------- encoding *)

let digest_of_canonical s = "sha256:" ^ Digestif.SHA256.(to_hex (digest_string s))
let str s = `String s
let opt k f = function Some v -> [ (k, f v) ] | None -> []

let metadata_to_json (m : metadata) : Yojson.Safe.t =
  let source = opt "url" str m.source.url @ opt "commit" str m.source.commit in
  `Assoc
    ([ ("name", str m.name); ("version", str m.version) ]
    @ opt "created_by" str m.created_by
    @ if source = [] then [] else [ ("source", `Assoc source) ])

(* The document without its digest, i.e. the payload the digest covers. *)
let payload_json ~metadata ~policies ~catalogs : Yojson.Safe.t =
  `Assoc
    [
      ("apiVersion", str api_version);
      ("kind", str kind);
      ("metadata", metadata_to_json metadata);
      ("policies", `List policies);
      ("catalogs", `Assoc catalogs);
    ]

let with_digest payload digest =
  match payload with
  | `Assoc kvs -> `Assoc (kvs @ [ ("digest", `String digest) ])
  | j -> j

(* ---------------------------------------------------------------- decoding *)

let malformed fmt = Printf.ksprintf (fun s -> Error (Malformed s)) fmt

let obj ~path ~keys ~required (j : Yojson.Safe.t) =
  match j with
  | `Assoc kvs -> (
      match List.find_opt (fun (k, _) -> not (List.mem k keys)) kvs with
      | Some (k, _) -> malformed "%s: unknown member %S" path k
      | None -> (
          match List.find_opt (fun k -> not (List.mem_assoc k kvs)) required with
          | Some k -> malformed "%s: missing member %S" path k
          | None -> Ok kvs))
  | _ -> malformed "%s: expected an object" path

let get_string ~path kvs k =
  match List.assoc_opt k kvs with
  | Some (`String s) -> Ok s
  | Some _ -> malformed "%s.%s: expected a string" path k
  | None -> malformed "%s: missing member %S" path k

let get_string_opt ~path kvs k =
  match List.assoc_opt k kvs with
  | None -> Ok None
  | Some (`String s) -> Ok (Some s)
  | Some _ -> malformed "%s.%s: expected a string" path k

let decode_metadata j =
  let path = "metadata" in
  let* kvs =
    obj ~path
      ~keys:[ "name"; "version"; "created_by"; "source" ]
      ~required:[ "name"; "version" ] j
  in
  let* name = get_string ~path kvs "name" in
  let* version = get_string ~path kvs "version" in
  let* created_by = get_string_opt ~path kvs "created_by" in
  let* source =
    match List.assoc_opt "source" kvs with
    | None -> Ok { url = None; commit = None }
    | Some s ->
        let path = "metadata.source" in
        let* skv = obj ~path ~keys:[ "url"; "commit" ] ~required:[] s in
        let* url = get_string_opt ~path skv "url" in
        let* commit = get_string_opt ~path skv "commit" in
        Ok { url; commit }
  in
  let m = { name; version; created_by; source } in
  let* () = check_metadata m in
  Ok m

let rec map_result f = function
  | [] -> Ok []
  | x :: xs ->
      let* y = f x in
      let* ys = map_result f xs in
      Ok (y :: ys)

let set_policy_name name (doc : Yojson.Safe.t) : Yojson.Safe.t =
  match doc with
  | `Assoc kvs ->
      `Assoc
        (List.map
           (fun (k, v) ->
             match (k, v) with
             | "metadata", `Assoc m ->
                 ( k,
                   `Assoc
                     (List.map
                        (fun (mk, mv) ->
                          if mk = "name" then (mk, `String name) else (mk, mv))
                        m) )
             | _ -> (k, v))
           kvs)
  | j -> j

(* Structural checks on one policy entry, then compile it. *)
let decode_policy ~name_prefix i (j : Yojson.Safe.t) =
  let path = Printf.sprintf "policies[%d]" i in
  let* kvs = obj ~path ~keys:[ "name"; "document" ] ~required:[ "name"; "document" ] j in
  let* name = get_string ~path kvs "name" in
  if not (valid_name name) then malformed "%s.name: invalid policy name %S" path name
  else
    let doc = List.assoc "document" kvs in
    let* dkv =
      match doc with
      | `Assoc d -> Ok d
      | _ -> malformed "%s.document: expected an object" path
    in
    let* () =
      match List.assoc_opt "kind" dkv with
      | Some (`String "Policy") -> Ok ()
      | _ -> malformed "%s.document: kind must be \"Policy\"" path
    in
    let* () =
      match List.assoc_opt "metadata" dkv with
      | Some (`Assoc m) when List.assoc_opt "name" m = Some (`String name) -> Ok ()
      | _ -> malformed "%s.document.metadata.name must equal %S" path name
    in
    (* A bundle is self-contained: a catalog given as a path would be resolved against
       the server's working directory. *)
    let* () =
      match List.assoc_opt "catalog" dkv with
      | None | Some (`Assoc _) -> Ok ()
      | Some _ -> malformed "%s.document.catalog must be an inline snapshot" path
    in
    let final_name = match name_prefix with Some p -> p ^ name | None -> name in
    let doc = if final_name = name then doc else set_policy_name final_name doc in
    match Policy_load.of_json doc with
    | Ok p -> Ok (name, p)
    | Error errors -> Error (Invalid_policy { policy = final_name; errors })

let decode_catalog (name, j) =
  if not (valid_name name) then malformed "catalogs: invalid catalog name %S" name
  else
    match j with
    | `Assoc _ -> (
        match Catalog_load.of_json j with
        | Ok c -> Ok (name, c)
        | Error errors -> Error (Invalid_catalog { catalog = name; errors }))
    | _ -> malformed "catalogs.%s: expected an object" name

let is_digest s =
  String.length s = 71
  && String.starts_with ~prefix:"sha256:" s
  && String.for_all
       (function '0' .. '9' | 'a' .. 'f' -> true | _ -> false)
       (String.sub s 7 64)

let parse_unverified ?(max_bytes = default_max_bytes) ?name_prefix bytes =
  let size = String.length bytes in
  if size > max_bytes then Error (Too_large { what = "bundle"; size; limit = max_bytes })
  else
    let* () =
      match name_prefix with
      | Some p when p = "" || String.length p > 64 || not (valid_name (p ^ "x")) ->
          malformed "invalid name prefix %S" p
      | _ -> Ok ()
    in
    let* j = Result.map_error (fun m -> Malformed m) (Canonical.of_string bytes) in
    let* kvs =
      obj ~path:"bundle"
        ~keys:[ "apiVersion"; "kind"; "metadata"; "policies"; "catalogs"; "digest" ]
        ~required:[ "apiVersion"; "kind"; "metadata"; "policies"; "catalogs"; "digest" ]
        j
    in
    let* av = get_string ~path:"bundle" kvs "apiVersion" in
    let* () =
      if av = api_version then Ok ()
      else malformed "unsupported apiVersion %S (expected %S)" av api_version
    in
    let* k = get_string ~path:"bundle" kvs "kind" in
    let* () = if k = kind then Ok () else malformed "kind must be %S, not %S" kind k in
    let* recorded = get_string ~path:"bundle" kvs "digest" in
    let* () =
      if is_digest recorded then Ok ()
      else malformed "digest must be \"sha256:\" followed by 64 lower-case hex digits"
    in
    let payload = `Assoc (List.filter (fun (k, _) -> k <> "digest") kvs) in
    let* canon = Result.map_error (fun m -> Malformed m) (Canonical.to_string payload) in
    let actual = digest_of_canonical canon in
    let* () =
      if Eqaf.equal actual recorded then Ok ()
      else Error (Digest_mismatch { expected = recorded; actual })
    in
    let* metadata = decode_metadata (List.assoc "metadata" kvs) in
    let* entries =
      match List.assoc "policies" kvs with
      | `List [] -> malformed "policies: a bundle needs at least one policy"
      | `List l when List.length l > max_policies ->
          malformed "policies: at most %d policies per bundle" max_policies
      | `List l -> Ok l
      | _ -> malformed "policies: expected an array"
    in
    let* compiled = map_result Fun.id (List.mapi (decode_policy ~name_prefix) entries) in
    let names = List.map fst compiled in
    let* () =
      match
        List.find_opt
          (fun n -> List.length (List.filter (String.equal n) names) > 1)
          names
      with
      | Some n -> malformed "policies: duplicate policy name %S" n
      | None -> Ok ()
    in
    let* catalogs =
      match List.assoc "catalogs" kvs with
      | `Assoc cs -> map_result decode_catalog cs
      | _ -> malformed "catalogs: expected an object"
    in
    Ok { metadata; policies = List.map snd compiled; catalogs; digest = recorded }

let build (metadata : metadata) ~(policies : Policy.t list) ~catalogs =
  let* () = check_metadata metadata in
  let* () =
    if policies = [] then malformed "a bundle needs at least one policy"
    else if List.length policies > max_policies then
      malformed "at most %d policies per bundle" max_policies
    else Ok ()
  in
  let names = List.map (fun (p : Policy.t) -> p.name) policies in
  let* () =
    match
      List.find_opt (fun n -> List.length (List.filter (String.equal n) names) > 1) names
    with
    | Some n -> malformed "duplicate policy name %S" n
    | None -> Ok ()
  in
  let cnames = List.map fst catalogs in
  let* () =
    match List.find_opt (fun n -> not (valid_name n)) cnames with
    | Some n -> malformed "invalid catalog name %S" n
    | None -> (
        match
          List.find_opt
            (fun n -> List.length (List.filter (String.equal n) cnames) > 1)
            cnames
        with
        | Some n -> malformed "duplicate catalog name %S" n
        | None -> Ok ())
  in
  let policies_json =
    List.map
      (fun (p : Policy.t) ->
        `Assoc [ ("name", `String p.name); ("document", Policy_load.to_json p) ])
      policies
  in
  let catalogs_json =
    List.map (fun (n, c) -> (n, Haltsql_load.Catalog_impl.to_json c)) catalogs
  in
  let payload = payload_json ~metadata ~policies:policies_json ~catalogs:catalogs_json in
  let* canon = Result.map_error (fun m -> Malformed m) (Canonical.to_string payload) in
  let doc = with_digest payload (digest_of_canonical canon) in
  let* bytes = Result.map_error (fun m -> Malformed m) (Canonical.to_string doc) in
  let bytes = bytes ^ "\n" in
  let* _ = parse_unverified bytes in
  Ok bytes

(* -------------------------------------------------------------- signatures *)

type signature = { keyid : string; signature : string }

let domain = "haltsql.dev/v1 PolicyBundle signature\n"
let signing_input bytes = domain ^ bytes

let sign secret bytes =
  let pub = Key.public_of_secret secret in
  { keyid = Key.keyid pub; signature = Key.sign secret (signing_input bytes) }

let signature_to_json s : Yojson.Safe.t =
  `Assoc
    [
      ("algorithm", `String "ed25519");
      ("keyid", `String s.keyid);
      ("signature", `String (B64.encode s.signature));
    ]

let signatures_to_string sigs =
  let j =
    match sigs with
    | [ s ] -> signature_to_json s
    | l -> `Assoc [ ("signatures", `List (List.map signature_to_json l)) ]
  in
  match Canonical.to_string j with Ok s -> s ^ "\n" | Error e -> invalid_arg e

let decode_signature path j =
  let* kvs =
    obj ~path
      ~keys:[ "algorithm"; "keyid"; "signature" ]
      ~required:[ "algorithm"; "keyid"; "signature" ]
      j
  in
  let* alg = get_string ~path kvs "algorithm" in
  let* keyid = get_string ~path kvs "keyid" in
  let* sigb64 = get_string ~path kvs "signature" in
  if alg <> "ed25519" then malformed "%s: unsupported algorithm %S" path alg
  else if not (is_digest keyid) then malformed "%s: invalid keyid" path
  else
    match B64.decode sigb64 with
    | Some s when String.length s = 64 -> Ok { keyid; signature = s }
    | _ -> malformed "%s: signature must be the base64 of 64 bytes" path

let signatures_of_string s =
  let size = String.length s in
  if size > max_signature_bytes then
    Error (Too_large { what = "signature file"; size; limit = max_signature_bytes })
  else
    let to_sig = function
      | Malformed m -> Signature_invalid ("invalid signature file: " ^ m)
      | e -> e
    in
    Result.map_error to_sig
      (let* j = Result.map_error (fun m -> Malformed m) (Canonical.of_string s) in
       match j with
       | `Assoc [ ("signatures", `List l) ] ->
           if l = [] || List.length l > max_signatures then
             malformed "1-%d signatures are allowed" max_signatures
           else
             map_result Fun.id
               (List.mapi
                  (fun i x -> decode_signature (Printf.sprintf "signatures[%d]" i) x)
                  l)
       | j ->
           let* s = decode_signature "signature" j in
           Ok [ s ])

let verify_signatures keys bytes sigs =
  if keys = [] then Error (Signature_invalid "no trusted public keys were given")
  else
    let msg = signing_input bytes in
    let verified =
      List.find_map
        (fun s ->
          List.find_opt
            (fun k ->
              String.equal (Key.keyid k) s.keyid
              && Key.verify k ~signature:s.signature msg)
            keys)
        sigs
    in
    match verified with
    | Some k -> Ok k
    | None ->
        let known =
          List.exists
            (fun s -> List.exists (fun k -> String.equal (Key.keyid k) s.keyid) keys)
            sigs
        in
        Error
          (Signature_invalid
             (if known then "the signature does not match the bundle contents"
              else
                Printf.sprintf "signed by %s, which is not a trusted key"
                  (String.concat ", " (List.map (fun s -> s.keyid) sigs))))

(* --------------------------------------------------------------- loading *)

let read_file ~max_bytes ~what path =
  match Unix.openfile path [ Unix.O_RDONLY; Unix.O_CLOEXEC ] 0 with
  | exception Unix.Unix_error (e, _, _) ->
      Error (Io (Printf.sprintf "cannot read %s %s: %s" what path (Unix.error_message e)))
  | fd ->
      Fun.protect
        ~finally:(fun () -> try Unix.close fd with Unix.Unix_error _ -> ())
        (fun () ->
          match Unix.fstat fd with
          | exception Unix.Unix_error (e, _, _) ->
              Error
                (Io
                   (Printf.sprintf "cannot read %s %s: %s" what path
                      (Unix.error_message e)))
          | st when st.st_kind <> Unix.S_REG ->
              Error (Io (Printf.sprintf "%s %s is not a regular file" what path))
          | st when st.st_size > max_bytes ->
              Error (Too_large { what; size = st.st_size; limit = max_bytes })
          | _ -> (
              (* Read at most max_bytes + 1 so a file that grows is still caught. *)
              let buf = Buffer.create 65536 in
              let chunk = Bytes.create 65536 in
              let rec loop () =
                if Buffer.length buf > max_bytes then ()
                else
                  match Unix.read fd chunk 0 (Bytes.length chunk) with
                  | 0 -> ()
                  | n ->
                      Buffer.add_subbytes buf chunk 0 n;
                      loop ()
              in
              match loop () with
              | exception Unix.Unix_error (e, _, _) ->
                  Error
                    (Io
                       (Printf.sprintf "cannot read %s %s: %s" what path
                          (Unix.error_message e)))
              | () ->
                  let size = Buffer.length buf in
                  if size > max_bytes then
                    Error (Too_large { what; size; limit = max_bytes })
                  else Ok (Buffer.contents buf)))

let signature_path bundle = bundle ^ ".sig"

let load_verified_bundle ?(max_bytes = default_max_bytes) ?name_prefix ?signature_file
    path keys =
  let sig_path = Option.value signature_file ~default:(signature_path path) in
  if keys = [] then Error (Signature_invalid "no trusted public keys were given")
  else
    let* bytes = read_file ~max_bytes ~what:"bundle" path in
    let* sig_text =
      read_file ~max_bytes:max_signature_bytes ~what:"signature file" sig_path
    in
    let* sigs = signatures_of_string sig_text in
    let* key = verify_signatures keys bytes sigs in
    let* t = parse_unverified ~max_bytes ?name_prefix bytes in
    Ok (t, key)

let load_verified ?max_bytes ?name_prefix ?signature_file path keys =
  let* t, _ = load_verified_bundle ?max_bytes ?name_prefix ?signature_file path keys in
  Ok t.policies

let load_config_ref ?max_bytes (r : Config.bundle_ref) =
  let* keys =
    map_result
      (fun k -> Result.map_error (fun m -> Invalid_key m) (Key.of_config k))
      r.public_keys
  in
  load_verified ?max_bytes ?name_prefix:r.name_prefix r.bundle_path keys
