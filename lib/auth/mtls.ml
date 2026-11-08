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
    Option.map X509.Distinguished_name.Common_name.to_string
      (X509.Distinguished_name.common_name (X509.Certificate.subject cert))
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
