(** Ed25519 bundle-signing keys: PEM/base64 codecs and safe file loading; see key.mli. *)

module Ed = Mirage_crypto_ec.Ed25519

type public = { pub : Ed.pub; raw_pub : string }
type secret = Ed.priv

let mk_public pub = { pub; raw_pub = Ed.pub_to_octets pub }
let raw p = p.raw_pub
let keyid p = "sha256:" ^ Digestif.SHA256.(to_hex (digest_string p.raw_pub))
let equal a b = Eqaf.equal a.raw_pub b.raw_pub
let rng_ready = lazy (Mirage_crypto_rng_unix.use_default ())

let generate () =
  Lazy.force rng_ready;
  fst (Ed.generate ())

let public_of_secret s = mk_public (Ed.pub_of_priv s)
let sign s msg = Ed.sign ~key:s msg

let verify p ~signature msg =
  String.length signature = 64 && Ed.verify ~key:p.pub signature ~msg

(* DER prefixes of the only encodings we produce and accept (RFC 8410). *)
let spki_prefix = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"
let pkcs8_prefix = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"

let wrap_pem label der =
  let b64 = B64.encode der in
  let b = Buffer.create 128 in
  Buffer.add_string b (Printf.sprintf "-----BEGIN %s-----\n" label);
  let n = String.length b64 in
  let rec go i =
    if i < n then begin
      Buffer.add_string b (String.sub b64 i (min 64 (n - i)));
      Buffer.add_char b '\n';
      go (i + 64)
    end
  in
  go 0;
  Buffer.add_string b (Printf.sprintf "-----END %s-----\n" label);
  Buffer.contents b

(* Exactly one PEM block with [label]; nothing but whitespace around it. *)
let unwrap_pem label s =
  let lines =
    String.split_on_char '\n' s |> List.map String.trim |> List.filter (fun l -> l <> "")
  in
  let begin_l = Printf.sprintf "-----BEGIN %s-----" label
  and end_l = Printf.sprintf "-----END %s-----" label in
  match lines with
  | first :: rest when first = begin_l -> (
      match List.rev rest with
      | last :: body_rev when last = end_l -> (
          let body = String.concat "" (List.rev body_rev) in
          match B64.decode body with
          | Some der -> Ok der
          | None -> Error "invalid base64 in PEM body")
      | _ -> Error (Printf.sprintf "missing %S line" end_l))
  | _ -> Error (Printf.sprintf "expected a %S block" begin_l)

let strip_prefix ~prefix der =
  let pl = String.length prefix in
  if String.length der = pl + 32 && String.sub der 0 pl = prefix then
    Some (String.sub der pl 32)
  else None

let public_to_pem p = wrap_pem "PUBLIC KEY" (spki_prefix ^ p.raw_pub)
let public_to_base64 p = B64.encode p.raw_pub
let secret_to_pem s = wrap_pem "PRIVATE KEY" (pkcs8_prefix ^ Ed.priv_to_octets s)

let public_of_raw raw =
  match Ed.pub_of_octets raw with
  | Ok pub -> Ok (mk_public pub)
  | Error _ -> Error "not a valid ed25519 public key"

let public_of_string s =
  let t = String.trim s in
  if String.starts_with ~prefix:"-----BEGIN" t then
    match unwrap_pem "PUBLIC KEY" t with
    | Error e -> Error ("invalid PEM public key: " ^ e)
    | Ok der -> (
        match strip_prefix ~prefix:spki_prefix der with
        | Some raw -> public_of_raw raw
        | None -> Error "PEM public key is not an ed25519 key")
  else
    match B64.decode t with
    | Some raw when String.length raw = 32 -> public_of_raw raw
    | _ ->
        Error
          "expected a PEM public key (-----BEGIN PUBLIC KEY-----) or the base64 of 32 \
           raw bytes"

let secret_of_string s =
  match unwrap_pem "PRIVATE KEY" (String.trim s) with
  | Error e -> Error ("invalid PEM private key: " ^ e)
  | Ok der -> (
      match strip_prefix ~prefix:pkcs8_prefix der with
      | None -> Error "PEM private key is not an unencrypted PKCS#8 ed25519 key"
      | Some raw -> (
          match Ed.priv_of_octets raw with
          | Ok k -> Ok k
          | Error _ -> Error "not a valid ed25519 private key"))

let max_key_file = 16 * 1024

let read_small path =
  match Unix.stat path with
  | exception Unix.Unix_error (e, _, _) ->
      Error (Printf.sprintf "%s: %s" path (Unix.error_message e))
  | st when st.st_kind <> Unix.S_REG -> Error (path ^ ": not a regular file")
  | st when st.st_size > max_key_file -> Error (path ^ ": too large for a key file")
  | st -> (
      match In_channel.with_open_bin path In_channel.input_all with
      | s -> Ok (s, st)
      | exception Sys_error e -> Error e)

let public_of_file path =
  match read_small path with
  | Error _ as e -> e
  | Ok (s, _) -> (
      match public_of_string s with
      | Ok k -> Ok k
      | Error e -> Error (Printf.sprintf "%s: %s" path e))

let secret_of_file path =
  match read_small path with
  | Error _ as e -> e
  | Ok (_, st) when st.st_perm land 0o077 <> 0 ->
      Error
        (Printf.sprintf
           "%s: private key is accessible by group or others (mode %o); run chmod 600 %s"
           path st.st_perm path)
  | Ok (s, _) -> (
      match secret_of_string s with
      | Ok k -> Ok k
      | Error e -> Error (Printf.sprintf "%s: %s" path e))

let of_config : Haltsql_load.Config.public_key -> (public, string) result = function
  | Key_path p -> public_of_file p
  | Key_pem s | Key_base64 s -> public_of_string s
