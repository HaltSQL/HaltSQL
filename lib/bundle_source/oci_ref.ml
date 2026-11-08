type t = {
  registry : string;
  host : string;
  repository : string;
  tag : string option;
  digest : string option;
}

let is_digit c = c >= '0' && c <= '9'
let is_alnum c = is_digit c || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
let is_lower_hex c = is_digit c || (c >= 'a' && c <= 'f')
let has_ws_or_ctl s = String.exists (fun c -> c <= ' ' || c = '\127') s

let contains_sub s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let valid_digest d =
  let hex_of n prefix =
    String.starts_with ~prefix d
    && String.length d = String.length prefix + n
    && String.for_all is_lower_hex
         (String.sub d (String.length prefix) (String.length d - String.length prefix))
  in
  hex_of 64 "sha256:" || hex_of 128 "sha512:"

let valid_repo_component c =
  c <> ""
  && String.for_all
       (fun ch ->
         (ch >= 'a' && ch <= 'z') || is_digit ch || ch = '.' || ch = '_' || ch = '-')
       c
  && is_alnum c.[0]
  && is_alnum c.[String.length c - 1]
  && not (contains_sub c "..")

let valid_tag t =
  let n = String.length t in
  n >= 1 && n <= 128
  && (is_alnum t.[0] || t.[0] = '_')
  && String.for_all (fun c -> is_alnum c || c = '_' || c = '.' || c = '-') t

let valid_port p =
  p <> ""
  && String.length p <= 5
  && String.for_all is_digit p
  &&
  let n = int_of_string p in
  n >= 1 && n <= 65535

(* host[:port] with a DNS name, IPv4 address or [IPv6]; returns the lower-cased
   host. *)
let registry_host r =
  if r = "" then None
  else if r.[0] = '[' then
    match String.index_opt r ']' with
    | None -> None
    | Some i ->
        let h = String.sub r 1 (i - 1) in
        let rest = String.sub r (i + 1) (String.length r - i - 1) in
        let port_ok =
          rest = ""
          || (rest.[0] = ':' && valid_port (String.sub rest 1 (String.length rest - 1)))
        in
        if
          port_ok && h <> ""
          && String.for_all
               (fun c ->
                 is_digit c || is_lower_hex (Char.lowercase_ascii c) || c = ':' || c = '.')
               h
        then Some (String.lowercase_ascii h)
        else None
  else
    let h, port_ok =
      match String.index_opt r ':' with
      | None -> (r, true)
      | Some i ->
          (String.sub r 0 i, valid_port (String.sub r (i + 1) (String.length r - i - 1)))
    in
    if
      port_ok && h <> ""
      && String.for_all (fun c -> is_alnum c || c = '.' || c = '-') h
      && is_alnum h.[0]
    then Some (String.lowercase_ascii h)
    else None

let parse s =
  let err m = Error (Printf.sprintf "invalid OCI reference %S: %s" s m) in
  if s = "" || has_ws_or_ctl s then err "must not be empty or contain whitespace"
  else if String.length s > 1024 then err "too long"
  else
    let name, digest =
      match String.index_opt s '@' with
      | None -> (s, None)
      | Some i -> (String.sub s 0 i, Some (String.sub s (i + 1) (String.length s - i - 1)))
    in
    match String.index_opt name '/' with
    | None ->
        err "expected registry/repository:tag or registry/repository@sha256:<digest>"
    | Some i -> (
        let registry = String.sub name 0 i in
        let rest = String.sub name (i + 1) (String.length name - i - 1) in
        let last_slash =
          match String.rindex_opt rest '/' with Some j -> j | None -> -1
        in
        let repository, tag =
          match String.rindex_opt rest ':' with
          | Some j when j > last_slash ->
              ( String.sub rest 0 j,
                Some (String.sub rest (j + 1) (String.length rest - j - 1)) )
          | _ -> (rest, None)
        in
        match registry_host registry with
        | None -> err (Printf.sprintf "invalid registry %S" registry)
        | Some host
          when not
                 (String.contains registry '.' || String.contains registry ':'
                || host = "localhost") ->
            err
              (Printf.sprintf
                 "%S is not a registry host: the reference must start with one (e.g. \
                  ghcr.io/corp/policies:prod or localhost:5000/policies:prod)"
                 registry)
        | Some host ->
            if
              repository = ""
              || String.length repository > 255
              || not
                   (List.for_all valid_repo_component
                      (String.split_on_char '/' repository))
            then
              err
                (Printf.sprintf
                   "invalid repository %S (lower-case path components of letters, \
                    digits, '.', '_', '-')"
                   repository)
            else if match tag with Some t -> not (valid_tag t) | None -> false then
              err "invalid tag (1-128 characters: letters, digits, '_', '.', '-')"
            else if match digest with Some d -> not (valid_digest d) | None -> false
            then
              err
                "the digest must be sha256:<64 lower-case hex> or sha512:<128 lower-case \
                 hex>"
            else if tag = None && digest = None then
              err "needs a :tag or an @sha256:<digest>"
            else Ok { registry; host; repository; tag; digest })

let of_config (o : Haltsql_load.Config.oci_source) =
  match parse o.oci_reference with
  | Error e -> Error e
  | Ok r ->
      if
        r.registry = o.oci_registry
        && r.repository = o.oci_repository
        && r.tag = o.oci_tag && r.digest = o.oci_digest
      then Ok r
      else
        Error
          (Printf.sprintf "OCI reference %S does not match its decoded fields"
             o.oci_reference)

let to_string r =
  r.registry ^ "/" ^ r.repository
  ^ (match r.tag with Some t -> ":" ^ t | None -> "")
  ^ match r.digest with Some d -> "@" ^ d | None -> ""

let reference r =
  match (r.digest, r.tag) with
  | Some d, _ -> d
  | None, Some t -> t
  | None, None -> invalid_arg "Oci_ref.reference: no tag or digest"

let is_loopback r =
  r.host = "localhost" || r.host = "::1"
  || (String.length r.host > 4 && String.sub r.host 0 4 = "127.")

let base_url ~plain_http r =
  if plain_http then
    if is_loopback r then Ok ("http://" ^ r.registry)
    else
      Error
        (Printf.sprintf
           "plain HTTP is only allowed for loopback registries (localhost, 127.x, \
            [::1]), not %s"
           r.registry)
  else Ok ("https://" ^ r.registry)
