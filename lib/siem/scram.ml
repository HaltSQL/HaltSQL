type hash = Sha256 | Sha512
type client_first = { nonce : string; bare : string; message : string }

let hmac h ~key msg =
  match h with
  | Sha256 -> Digestif.SHA256.(to_raw_string (hmac_string ~key msg))
  | Sha512 -> Digestif.SHA512.(to_raw_string (hmac_string ~key msg))

let digest h s =
  match h with
  | Sha256 -> Digestif.SHA256.(to_raw_string (digest_string s))
  | Sha512 -> Digestif.SHA512.(to_raw_string (digest_string s))

let xor a b =
  String.init (String.length a) (fun i -> Char.chr (Char.code a.[i] lxor Char.code b.[i]))

let hi h ~password ~salt ~iterations =
  let u1 = hmac h ~key:password (salt ^ "\000\000\000\001") in
  let len = String.length u1 in
  let acc = Bytes.of_string u1 in
  let prev = ref u1 in
  for _ = 2 to iterations do
    let u = hmac h ~key:password !prev in
    for j = 0 to len - 1 do
      Bytes.unsafe_set acc j
        (Char.chr
           (Char.code (Bytes.unsafe_get acc j) lxor Char.code (String.unsafe_get u j)))
    done;
    prev := u
  done;
  Bytes.unsafe_to_string acc

let escape_user u =
  let b = Buffer.create (String.length u) in
  String.iter
    (function
      | '=' -> Buffer.add_string b "=3D"
      | ',' -> Buffer.add_string b "=2C"
      | c -> Buffer.add_char b c)
    u;
  Buffer.contents b

let rng_ready =
  lazy
    (try ignore (Mirage_crypto_rng.generate 1)
     with Mirage_crypto_rng.Unseeded_generator -> Mirage_crypto_rng_unix.use_default ())

let client_first ?nonce ~username () =
  let nonce =
    match nonce with
    | Some n -> n
    | None ->
        Lazy.force rng_ready;
        Base64.encode_string (Mirage_crypto_rng.generate 24)
  in
  let bare = Printf.sprintf "n=%s,r=%s" (escape_user username) nonce in
  { nonce; bare; message = "n,," ^ bare }

let attrs s =
  List.filter_map
    (fun a ->
      if String.length a >= 2 && a.[1] = '=' then
        Some (a.[0], String.sub a 2 (String.length a - 2))
      else None)
    (String.split_on_char ',' s)

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

let client_final h ~password cf ~server_first =
  let a = attrs server_first in
  if List.mem_assoc 'm' a then Error "SCRAM: server requires an unsupported extension"
  else
    match (List.assoc_opt 'r' a, List.assoc_opt 's' a, List.assoc_opt 'i' a) with
    | Some r, Some s, Some i -> (
        if not (starts_with ~prefix:cf.nonce r && String.length r > String.length cf.nonce)
        then Error "SCRAM: server nonce does not extend the client nonce"
        else
          match (Base64.decode s, int_of_string_opt i) with
          | Error _, _ -> Error "SCRAM: invalid salt"
          | _, None -> Error "SCRAM: invalid iteration count"
          | Ok _, Some n when n < 4096 || n > 600_000 ->
              Error (Printf.sprintf "SCRAM: iteration count %d outside 4096..600000" n)
          | Ok salt, Some iterations ->
              let salted = hi h ~password ~salt ~iterations in
              let client_key = hmac h ~key:salted "Client Key" in
              let stored_key = digest h client_key in
              let without_proof = "c=biws,r=" ^ r in
              let auth_message = cf.bare ^ "," ^ server_first ^ "," ^ without_proof in
              let client_sig = hmac h ~key:stored_key auth_message in
              let proof = xor client_key client_sig in
              let server_key = hmac h ~key:salted "Server Key" in
              let server_sig = hmac h ~key:server_key auth_message in
              Ok
                ( without_proof ^ ",p=" ^ Base64.encode_string proof,
                  Base64.encode_string server_sig ))
    | _ -> Error "SCRAM: malformed server-first message"

let verify_server_final ~expected msg =
  match attrs msg with
  | ('v', v) :: _ ->
      if Eqaf.equal v expected then Ok ()
      else
        Error "SCRAM: server signature mismatch (the broker did not prove the password)"
  | ('e', e) :: _ ->
      let e = String.map (fun c -> if c < ' ' || c > '~' then '?' else c) e in
      Error ("SCRAM: server error: " ^ e)
  | _ -> Error "SCRAM: malformed server-final message"
