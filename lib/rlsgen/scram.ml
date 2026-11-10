(** SCRAM-SHA-256 client. See scram.mli. *)

type state = {
  client_first_bare : string;
  nonce : string;
  auth_message : string;  (** set by [client_final] *)
  salted_password : string;
}

let hmac ~key msg = Digestif.SHA256.(to_raw_string (hmac_string ~key msg))
let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))

let xor a b =
  String.init (String.length a) (fun i -> Char.chr (Char.code a.[i] lxor Char.code b.[i]))

let constant_time_equal a b =
  let la = String.length a and lb = String.length b in
  let acc = ref (la lxor lb) in
  for i = 0 to max la lb - 1 do
    let ca = if i < la then Char.code a.[i] else 0 in
    let cb = if i < lb then Char.code b.[i] else 0 in
    acc := !acc lor (ca lxor cb)
  done;
  !acc = 0

let pbkdf2_sha256 ~password ~salt ~iterations =
  Pbkdf.pbkdf2 ~prf:`SHA256 ~password ~salt ~count:(max 1 iterations) ~dk_len:32l

(* RFC 5802 saslname: ',' -> =2C, '=' -> =3D *)
let saslname s =
  let b = Buffer.create (String.length s) in
  String.iter
    (function
      | ',' -> Buffer.add_string b "=2C"
      | '=' -> Buffer.add_string b "=3D"
      | c -> Buffer.add_char b c)
    s;
  Buffer.contents b

let client_first ~user ~nonce =
  let bare = "n=" ^ saslname user ^ ",r=" ^ nonce in
  ( { client_first_bare = bare; nonce; auth_message = ""; salted_password = "" },
    "n,," ^ bare )

let parse_attrs s =
  List.filter_map
    (fun part ->
      if String.length part >= 2 && part.[1] = '=' then
        Some (part.[0], String.sub part 2 (String.length part - 2))
      else None)
    (String.split_on_char ',' s)

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

let client_final st ~password ~server_first =
  let attrs = parse_attrs server_first in
  match
    (List.assoc_opt 'r' attrs, List.assoc_opt 's' attrs, List.assoc_opt 'i' attrs)
  with
  | Some r, Some s, Some i -> (
      if List.mem_assoc 'm' attrs then Error "SCRAM: unsupported mandatory extension"
      else if
        (not (starts_with ~prefix:st.nonce r))
        || String.length r <= String.length st.nonce
      then Error "SCRAM: server nonce does not extend the client nonce"
      else
        match (B64.decode s, int_of_string_opt i) with
        | None, _ -> Error "SCRAM: invalid salt"
        | _, None -> Error "SCRAM: invalid iteration count"
        | Some _, Some n when n < 1 || n > 10_000_000 ->
            Error "SCRAM: iteration count out of range"
        | Some salt, Some iterations ->
            let salted = pbkdf2_sha256 ~password ~salt ~iterations in
            let client_key = hmac ~key:salted "Client Key" in
            let stored_key = sha256 client_key in
            let without_proof = "c=biws,r=" ^ r in
            let auth = st.client_first_bare ^ "," ^ server_first ^ "," ^ without_proof in
            let signature = hmac ~key:stored_key auth in
            let proof = xor client_key signature in
            Ok
              ( { st with auth_message = auth; salted_password = salted },
                without_proof ^ ",p=" ^ B64.encode proof ))
  | _ -> Error "SCRAM: malformed server-first-message"

let verify_server_final st msg =
  if st.auth_message = "" then Error "SCRAM: exchange incomplete"
  else
    let attrs = parse_attrs msg in
    match (List.assoc_opt 'e' attrs, List.assoc_opt 'v' attrs) with
    | Some e, _ -> Error ("SCRAM: server error: " ^ e)
    | None, Some v -> (
        match B64.decode v with
        | None -> Error "SCRAM: malformed server signature"
        | Some sig_ ->
            let server_key = hmac ~key:st.salted_password "Server Key" in
            let expected = hmac ~key:server_key st.auth_message in
            if constant_time_equal sig_ expected then Ok ()
            else
              Error
                "SCRAM: server signature mismatch (server did not prove it knows the \
                 password)")
    | None, None -> Error "SCRAM: malformed server-final-message"
