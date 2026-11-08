(** Client-certificate identity extraction and mapping. *)

module Config = Haltsql.Config

type peer = {
  spiffe_id : string option;
  uri_sans : string list;
  subject_cn : string option;
  fingerprint : string;
}

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

(* X.509 >= 1.2 returns a CN as typed content octets in their declared ASN.1 string
   encoding, not as UTF-8. Identities are configured as UTF-8 text, so decode the
   encodings that map unambiguously to Unicode and reject anything else (fail closed:
   a CN that cannot be decoded is treated as absent, so it never matches a
   [subject_cn] identity). *)
let no_controls s = String.for_all (fun c -> Char.code c >= 0x20 && Char.code c <> 0x7f) s

let decode_wide ~width ~get s =
  let len = String.length s in
  if len mod width <> 0 then None
  else
    let b = Buffer.create len in
    let rec go i =
      if i >= len then Some (Buffer.contents b)
      else
        match get s i with
        | Some (u, n) ->
            Buffer.add_utf_8_uchar b u;
            go (i + n)
        | None -> None
    in
    go 0

let utf16be s i =
  let d = String.get_utf_16be_uchar s i in
  if Uchar.utf_decode_is_valid d then
    Some (Uchar.utf_decode_uchar d, Uchar.utf_decode_length d)
  else None

let ucs4be s i =
  let cp = Int32.to_int (String.get_int32_be s i) land 0xFFFF_FFFF in
  if Uchar.is_valid cp then Some (Uchar.of_int cp, 4) else None

let cn_text (cn : X509.Distinguished_name.Common_name.t) =
  let module E = X509.Distinguished_name.Encoded_string in
  let enc = X509.Distinguished_name.Common_name.encoded cn in
  let raw = E.to_string enc in
  let text =
    match E.encoding enc with
    | `UTF8 -> if String.is_valid_utf_8 raw then Some raw else None
    | `Printable ->
        (* PrintableString is a subset of ASCII; accept printable ASCII (some CAs put
           '_' or '*' in it), which is byte-identical in UTF-8. *)
        if String.for_all (fun c -> Char.code c < 0x80) raw then Some raw else None
    | `BMP -> decode_wide ~width:2 ~get:utf16be raw
    | `Universal -> decode_wide ~width:4 ~get:ucs4be raw
    | `Teletex ->
        (* T.61 has no unambiguous mapping to Unicode. *)
        None
  in
  match text with Some t when t <> "" && no_controls t -> Some t | _ -> None

let peer_of_certificate cert =
  let uri_sans =
    match X509.Extension.(find Subject_alt_name (X509.Certificate.extensions cert)) with
    | Some (_critical, names) -> (
        match X509.General_name.find X509.General_name.URI names with
        | Some l -> l
        | None -> [])
    | None -> []
  in
  let spiffe_id =
    match uri_sans with
    | [ u ] when starts_with ~prefix:"spiffe://" u -> Some u
    | _ -> None
  in
  let subject_cn =
    Option.bind
      (X509.Distinguished_name.common_name (X509.Certificate.subject cert))
      cn_text
  in
  let fingerprint =
    let raw = X509.Certificate.fingerprint `SHA256 cert in
    String.concat ""
      (List.init (String.length raw) (fun i -> Printf.sprintf "%02x" (Char.code raw.[i])))
  in
  { spiffe_id; uri_sans; subject_cn; fingerprint }

let subject p =
  match (p.spiffe_id, p.subject_cn) with
  | Some s, _ -> s
  | None, Some cn -> cn
  | None, None -> "sha256:" ^ p.fingerprint

let find_identity (ids : Config.mtls_identity list) p =
  List.find_opt
    (fun (i : Config.mtls_identity) ->
      match i.mtls_match with
      | Config.Spiffe_id s -> p.spiffe_id = Some s
      | Config.Subject_cn cn -> p.subject_cn = Some cn)
    ids
